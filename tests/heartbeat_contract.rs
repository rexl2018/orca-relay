//! Bridge relay-heartbeat contract against a hand-rolled loopback WebSocket peer.
//!
//! The fake relay completes the upgrade itself and parses raw client frames so it
//! can observe the bridge's heartbeat Pings without any library auto-answering them.

use std::time::Duration;

use orca_relay::adapter::{run_bridge, BridgeConfig, BridgeHandle};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    task::JoinHandle,
    time::{timeout_at, Instant},
};
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;

const TOKEN: &str = "heartbeat-test-token";
const SERVER_ID: &str = "heartbeat";
const HEARTBEAT_PAYLOAD: &[u8] = b"orca-relay";
// Mirrors the bridge: 5s Ping interval, 15s Pong deadline, 1s first retry delay.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(15);
const FIRST_RETRY_DELAY: Duration = Duration::from_secs(1);
// Detection lands on an interval tick, so allow one extra interval plus loopback slack.
const RECONNECT_DEADLINE: Duration = Duration::from_secs(
    HEARTBEAT_TIMEOUT.as_secs() + HEARTBEAT_INTERVAL.as_secs() + FIRST_RETRY_DELAY.as_secs() + 3,
);

#[derive(Clone, Copy)]
enum Peer {
    /// Upgrade, then read frames but never answer a Ping.
    Silent,
    /// Upgrade, then answer every Ping with a matching Pong.
    Responsive,
}

#[derive(Debug)]
enum Event {
    Accepted(usize),
    Ping(usize, Vec<u8>),
    Gone(usize),
}

struct FakeRelay {
    url: String,
    events: mpsc::UnboundedReceiver<Event>,
    task: JoinHandle<()>,
}

impl FakeRelay {
    async fn spawn(peers: Vec<Peer>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}/ws", listener.local_addr().unwrap());
        let (tx, events) = mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            let scripted = peers.len();
            for (index, peer) in peers.into_iter().enumerate() {
                let (stream, _) = listener.accept().await.unwrap();
                let tx = tx.clone();
                connections.spawn(serve(index, peer, stream, tx));
            }
            // Any connection beyond the script is reported and then refused.
            if let Ok((stream, _)) = listener.accept().await {
                let _ = tx.send(Event::Accepted(scripted));
                drop(stream);
            }
            while connections.join_next().await.is_some() {}
        });
        Self { url, events, task }
    }

    async fn bridge(&self) -> BridgeHandle {
        run_bridge(BridgeConfig {
            relay_url: self.url.clone(),
            local_runtime_url: "ws://127.0.0.1:1".into(),
            server_id: SERVER_ID.into(),
            relay_token: TOKEN.into(),
        })
        .await
        .expect("bridge should complete the relay upgrade")
    }

    async fn next(&mut self, within: Duration) -> Option<Event> {
        self.next_before(Instant::now() + within).await
    }

    async fn next_before(&mut self, deadline: Instant) -> Option<Event> {
        timeout_at(deadline, self.events.recv())
            .await
            .ok()
            .flatten()
    }
}

impl Drop for FakeRelay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve(index: usize, peer: Peer, mut stream: TcpStream, tx: mpsc::UnboundedSender<Event>) {
    let key = read_upgrade_request(&mut stream).await;
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
        derive_accept_key(key.as_bytes())
    );
    stream.write_all(response.as_bytes()).await.unwrap();
    let _ = tx.send(Event::Accepted(index));
    while let Some((opcode, payload)) = read_client_frame(&mut stream).await {
        match opcode {
            0x9 => {
                if let Peer::Responsive = peer {
                    let mut pong = vec![0x8a, payload.len() as u8];
                    pong.extend_from_slice(&payload);
                    if stream.write_all(&pong).await.is_err() {
                        break;
                    }
                }
                let _ = tx.send(Event::Ping(index, payload));
            }
            0x8 => break,
            _ => {}
        }
    }
    let _ = tx.send(Event::Gone(index));
}

async fn read_upgrade_request(stream: &mut TcpStream) -> String {
    let mut request = Vec::new();
    let mut byte = [0u8; 1];
    while !request.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).await.unwrap();
        request.push(byte[0]);
    }
    let request = String::from_utf8(request).unwrap();
    let request_line = request.lines().next().unwrap();
    assert!(
        request_line.starts_with("GET /ws?"),
        "unexpected upgrade target"
    );
    assert!(request_line.contains("role=server"));
    assert!(request_line.contains(&format!("serverId={SERVER_ID}")));
    let header = |name: &str| {
        request.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name)
                .then(|| value.trim().to_owned())
        })
    };
    assert_eq!(
        header("authorization").as_deref(),
        Some(format!("Bearer {TOKEN}").as_str()),
        "bridge must authenticate every relay attempt"
    );
    header("sec-websocket-key").expect("upgrade must carry a key")
}

/// Reads one masked client frame; `None` once the bridge has dropped the socket.
async fn read_client_frame(stream: &mut TcpStream) -> Option<(u8, Vec<u8>)> {
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await.ok()?;
    assert_eq!(head[1] & 0x80, 0x80, "client frames must be masked");
    let len = match head[1] & 0x7f {
        126 => stream.read_u16().await.ok()? as usize,
        127 => stream.read_u64().await.ok()? as usize,
        len => len as usize,
    };
    let mut mask = [0u8; 4];
    stream.read_exact(&mut mask).await.ok()?;
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await.ok()?;
    for (i, byte) in payload.iter_mut().enumerate() {
        *byte ^= mask[i % 4];
    }
    Some((head[0] & 0x0f, payload))
}

#[tokio::test]
async fn bridge_abandons_relay_that_ignores_heartbeat_and_reconnects_within_deadline() {
    let mut relay = FakeRelay::spawn(vec![Peer::Silent, Peer::Responsive]).await;
    let _bridge = relay.bridge().await;
    assert!(matches!(
        relay.next(Duration::from_secs(1)).await,
        Some(Event::Accepted(0))
    ));
    let upgraded = Instant::now();
    let deadline = upgraded + RECONNECT_DEADLINE;

    let mut ignored_pings = 0;
    loop {
        match relay.next_before(deadline).await {
            Some(Event::Ping(0, payload)) => {
                assert_eq!(payload, HEARTBEAT_PAYLOAD);
                ignored_pings += 1;
            }
            Some(Event::Gone(0)) => break,
            other => panic!("silent relay socket was not abandoned: {other:?}"),
        }
    }
    let abandoned = upgraded.elapsed();
    assert!(
        ignored_pings >= 2,
        "one lost Pong must be tolerated; abandoned after {ignored_pings} Ping(s) at {abandoned:?}"
    );
    assert!(abandoned >= HEARTBEAT_TIMEOUT - Duration::from_millis(100));

    match relay.next_before(deadline).await {
        Some(Event::Accepted(1)) => {}
        other => {
            panic!("no fresh relay socket within {RECONNECT_DEADLINE:?} of the upgrade: {other:?}")
        }
    }

    // The replacement socket is actively heartbeated, not just opened.
    match relay
        .next(HEARTBEAT_INTERVAL + Duration::from_secs(2))
        .await
    {
        Some(Event::Ping(1, payload)) => assert_eq!(payload, HEARTBEAT_PAYLOAD),
        other => panic!("fresh relay socket is not heartbeated: {other:?}"),
    }
}

#[tokio::test]
async fn bridge_keeps_idle_relay_that_answers_heartbeat() {
    let mut relay = FakeRelay::spawn(vec![Peer::Responsive]).await;
    let _bridge = relay.bridge().await;
    assert!(matches!(
        relay.next(Duration::from_secs(1)).await,
        Some(Event::Accepted(0))
    ));
    // Observe past the worst-case abandonment point (timeout + one tick + retry).
    let observe_until = Instant::now() + HEARTBEAT_TIMEOUT + HEARTBEAT_INTERVAL + FIRST_RETRY_DELAY;
    let mut answered_pings = 0;
    loop {
        match relay.next_before(observe_until).await {
            Some(Event::Ping(0, payload)) => {
                assert_eq!(payload, HEARTBEAT_PAYLOAD);
                answered_pings += 1;
            }
            None => break,
            other => panic!("responsive idle relay was disturbed: {other:?}"),
        }
    }
    assert!(
        answered_pings >= 4,
        "heartbeat must keep running on an idle socket; saw {answered_pings} Ping(s)"
    );
}
