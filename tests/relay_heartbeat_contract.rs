//! Relay-side host liveness: the relay Pings each registered bridge and retires one
//! that stops answering, while idle bridges that answer (including legacy bridges
//! that never Ping the relay themselves) stay registered.

use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use futures_util::{SinkExt, StreamExt};
use orca_relay::{
    adapter::{run_bridge, BridgeConfig},
    app, RelayConfig,
};
use tokio::{
    net::TcpListener,
    sync::mpsc,
    task::JoinHandle,
    time::{timeout, Instant},
};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{
        client::IntoClientRequest, http::header::AUTHORIZATION, Error as WsError, Message,
    },
    MaybeTlsStream, WebSocketStream,
};

const TOKEN: &str = "relay-heartbeat-test-token";
// Mirrors the relay: 5s Ping interval, 15s Pong deadline, checked on a 5s tick.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(15);
const EVICTION_DEADLINE: Duration =
    Duration::from_secs(HEARTBEAT_TIMEOUT.as_secs() + HEARTBEAT_INTERVAL.as_secs() + 3);
type Ws = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

struct Relay {
    addr: SocketAddr,
    task: JoinHandle<()>,
}

impl Relay {
    async fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, app(RelayConfig::new("test", TOKEN)))
                .await
                .unwrap();
        });
        Self { addr, task }
    }

    fn url(&self) -> String {
        format!("ws://{}/ws", self.addr)
    }

    async fn try_connect(&self, role: &str, server: &str, client: &str) -> Result<Ws, WsError> {
        let mut request = format!(
            "ws://{}/ws?role={role}&serverId={server}&clientId={client}&v=1",
            self.addr
        )
        .into_client_request()
        .unwrap();
        request
            .headers_mut()
            .insert(AUTHORIZATION, format!("Bearer {TOKEN}").parse().unwrap());
        connect_async(request).await.map(|(socket, _)| socket)
    }

    async fn connect(&self, role: &str, server: &str, client: &str) -> Ws {
        self.try_connect(role, server, client).await.unwrap()
    }

    async fn assert_unavailable(&self, server: &str, client: &str) {
        match self.try_connect("client", server, client).await {
            Err(WsError::Http(response)) => assert_eq!(response.status(), 503),
            Err(other) => panic!("expected HTTP 503 for an absent host, got {other:?}"),
            Ok(_) => panic!("relay still admits clients for an evicted host"),
        }
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn frame(client: &str, connection: &str, payload: &[u8]) -> Message {
    let header = format!(
        r#"{{"clientId":"{client}","connectionId":"{connection}","direction":"client_to_server","opcode":"binary"}}"#
    );
    let mut bytes = (header.len() as u32).to_be_bytes().to_vec();
    bytes.extend_from_slice(header.as_bytes());
    bytes.extend_from_slice(payload);
    Message::Binary(bytes)
}

/// Resolves to the close code/reason the relay sent, or `None` if the socket just ended.
async fn closed(socket: &mut Ws, within: Duration) -> Option<(u16, String)> {
    timeout(within, async {
        while let Some(message) = socket.next().await {
            match message {
                Ok(Message::Close(Some(close))) => {
                    return Some((u16::from(close.code), close.reason.into_owned()))
                }
                Ok(Message::Close(None)) | Err(_) => return None,
                Ok(_) => {}
            }
        }
        None
    })
    .await
    .expect("expected the relay to close the socket in time")
}

#[tokio::test]
async fn silent_registered_host_is_evicted_and_its_clients_close() {
    let relay = Relay::spawn().await;
    // Never polled: no auto-Pong is ever written, like a wedged or sleeping bridge.
    let mut silent = relay.connect("server", "silent", "").await;
    let registered = Instant::now();
    let mut client = relay.connect("client", "silent", "phone").await;
    client.send(frame("phone", "c1", b"open")).await.unwrap();

    let (code, reason) = closed(&mut client, EVICTION_DEADLINE)
        .await
        .expect("evicted host's client must get a close frame");
    let evicted = registered.elapsed();
    assert_eq!(code, 1013, "clients must be told to retry later");
    assert_eq!(reason, "server unavailable");
    assert!(
        evicted >= HEARTBEAT_TIMEOUT - Duration::from_millis(500),
        "one missed Pong must be tolerated; evicted after {evicted:?}"
    );

    relay.assert_unavailable("silent", "late-phone").await;

    // The relay drops the wedged host socket. Its close reason is not asserted: once this
    // peer resumes reading, tungstenite's auto-Pong to the queued Pings hits a broken pipe
    // before the Close frame can be read.
    let _ = closed(&mut silent, Duration::from_secs(5)).await;
}

#[tokio::test]
async fn idle_hosts_that_answer_pings_stay_registered() {
    let relay = Relay::spawn().await;

    // Legacy bridge shape: never Pings the relay, only reads (tungstenite auto-answers Pings).
    let mut legacy = relay.connect("server", "legacy", "").await;
    let (frames_tx, mut frames_rx) = mpsc::unbounded_channel();
    let pings = Arc::new(AtomicUsize::new(0));
    let seen = pings.clone();
    let legacy_task = tokio::spawn(async move {
        while let Some(Ok(message)) = legacy.next().await {
            match message {
                Message::Ping(_) => {
                    seen.fetch_add(1, Ordering::Relaxed);
                }
                Message::Binary(bytes) => {
                    let _ = frames_tx.send(bytes);
                }
                Message::Close(close) => panic!("idle legacy host was closed: {close:?}"),
                _ => {}
            }
        }
    });

    // Current bridge, idle with no clients and no runtime traffic.
    let mut bridge = run_bridge(BridgeConfig {
        relay_url: relay.url(),
        local_runtime_url: "ws://127.0.0.1:9/ws".to_owned(),
        server_id: "current".to_owned(),
        relay_token: TOKEN.to_owned(),
    })
    .await
    .unwrap();

    // Observe past the worst-case eviction point for a non-answering host.
    tokio::time::sleep(EVICTION_DEADLINE).await;
    assert!(!legacy_task.is_finished(), "legacy host socket was dropped");
    let answered = pings.load(Ordering::Relaxed);
    assert!(
        answered >= 3,
        "relay must actively Ping idle hosts; legacy host saw {answered} Ping(s)"
    );
    assert!(
        timeout(Duration::from_millis(10), bridge.wait())
            .await
            .is_err(),
        "current bridge stopped while idle"
    );

    let mut phone = relay.connect("client", "legacy", "phone").await;
    phone
        .send(frame("phone", "c1", b"still here"))
        .await
        .unwrap();
    let routed = timeout(Duration::from_secs(3), frames_rx.recv())
        .await
        .expect("legacy host must still receive client frames")
        .unwrap();
    assert!(routed.ends_with(b"still here"));
    relay.connect("client", "current", "phone").await;
    legacy_task.abort();
}
