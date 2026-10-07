use std::{net::SocketAddr, time::Duration};

use futures_util::{SinkExt, StreamExt};
use orca_relay::{
    adapter::{
        decode_adapter_frame, encode_adapter_frame, run_bridge, run_proxy, AdapterDirection,
        AdapterFrame, AdapterFrameHeader, AdapterOpcode, BridgeConfig, ProxyConfig,
    },
    app, RelayConfig,
};
use tokio::{net::TcpListener, sync::mpsc, task::JoinHandle, time::timeout};
use tokio_tungstenite::{
    accept_async, connect_async,
    tungstenite::{client::IntoClientRequest, http::header::AUTHORIZATION, Message},
    MaybeTlsStream, WebSocketStream,
};

const TOKEN: &str = "recovery-test-token";
type Ws = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

struct Relay {
    addr: SocketAddr,
    task: JoinHandle<()>,
}

impl Relay {
    async fn spawn(addr: &str) -> Self {
        let listener = TcpListener::bind(addr).await.unwrap();
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

    async fn connect(&self, role: &str, client: &str) -> Ws {
        let mut request = format!(
            "{}?role={role}&serverId=recovery&clientId={client}&v=1",
            self.url()
        )
        .into_client_request()
        .unwrap();
        request
            .headers_mut()
            .insert(AUTHORIZATION, format!("Bearer {TOKEN}").parse().unwrap());
        connect_async(request).await.unwrap().0
    }

    fn bridge_config(&self, runtime: &str) -> BridgeConfig {
        BridgeConfig {
            relay_url: self.url(),
            local_runtime_url: runtime.to_owned(),
            server_id: "recovery".to_owned(),
            relay_token: TOKEN.to_owned(),
        }
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct Runtime {
    url: String,
    closed: mpsc::Receiver<()>,
    task: JoinHandle<()>,
}

impl Runtime {
    async fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let (closed_tx, closed) = mpsc::channel(8);
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let closed_tx = closed_tx.clone();
                connections.spawn(async move {
                    let mut socket = accept_async(stream).await.unwrap();
                    while let Some(Ok(message)) = socket.next().await {
                        match message {
                            Message::Text(_) | Message::Binary(_) => {
                                if socket.send(message).await.is_err() {
                                    break;
                                }
                            }
                            Message::Close(_) => break,
                            _ => {}
                        }
                    }
                    let _ = closed_tx.send(()).await;
                });
            }
        });
        Self { url, closed, task }
    }

    async fn assert_closed(&mut self) {
        timeout(Duration::from_secs(3), self.closed.recv())
            .await
            .expect("orphaned runtime socket must be retired")
            .unwrap();
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn frame(client: &str, connection: &str, payload: &str) -> Message {
    Message::Binary(
        encode_adapter_frame(&AdapterFrame {
            header: AdapterFrameHeader {
                client_id: client.to_owned(),
                connection_id: connection.to_owned(),
                direction: AdapterDirection::ClientToServer,
                opcode: AdapterOpcode::Text,
                close_code: None,
                close_reason: None,
            },
            payload: payload.as_bytes().to_vec(),
        })
        .unwrap(),
    )
}

async fn next(socket: &mut Ws) -> Message {
    timeout(Duration::from_secs(3), async {
        loop {
            let message = socket.next().await.unwrap().unwrap();
            if !matches!(message, Message::Ping(_) | Message::Pong(_)) {
                return message;
            }
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn root_proxy_and_abrupt_phone_disconnect_retire_runtime() {
    let relay = Relay::spawn("127.0.0.1:0").await;
    let mut runtime = Runtime::spawn().await;
    let _bridge = run_bridge(relay.bridge_config(&runtime.url)).await.unwrap();
    let proxy = run_proxy(ProxyConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        relay_url: relay.url(),
        server_id: "recovery".to_owned(),
        relay_token: TOKEN.to_owned(),
        client_id: "phone".to_owned(),
    })
    .await
    .unwrap();
    let mut phone = connect_async(format!("ws://{}/", proxy.local_addr()))
        .await
        .unwrap()
        .0;
    phone.send(Message::Text("hello".into())).await.unwrap();
    assert_eq!(next(&mut phone).await, Message::Text("hello".into()));
    drop(phone);
    runtime.assert_closed().await;
}

#[tokio::test]
async fn dropping_bridge_retires_runtime_and_disconnects_clients() {
    let relay = Relay::spawn("127.0.0.1:0").await;
    let mut runtime = Runtime::spawn().await;
    let bridge = run_bridge(relay.bridge_config(&runtime.url)).await.unwrap();
    let mut client = relay.connect("client", "a").await;
    client.send(frame("a", "one", "hello")).await.unwrap();
    assert!(matches!(next(&mut client).await, Message::Binary(_)));
    drop(bridge);
    runtime.assert_closed().await;
    assert!(matches!(next(&mut client).await, Message::Close(_)));
}

#[tokio::test]
async fn replacement_server_disconnects_old_clients_and_stops_old_bridge() {
    let relay = Relay::spawn("127.0.0.1:0").await;
    let runtime = Runtime::spawn().await;
    let mut bridge = run_bridge(relay.bridge_config(&runtime.url)).await.unwrap();
    let mut client = relay.connect("client", "a").await;
    let mut replacement = relay.connect("server", "").await;
    assert!(matches!(next(&mut client).await, Message::Close(_)));
    timeout(Duration::from_secs(3), bridge.wait())
        .await
        .expect("retired bridge must not fight its replacement")
        .unwrap();
    let mut new_client = relay.connect("client", "a").await;
    new_client.send(frame("a", "one", "new")).await.unwrap();
    assert!(matches!(next(&mut replacement).await, Message::Binary(_)));
}

#[tokio::test]
async fn frame_cannot_spoof_another_clients_routing_id() {
    let relay = Relay::spawn("127.0.0.1:0").await;
    let mut server = relay.connect("server", "").await;
    let mut attacker = relay.connect("client", "a").await;
    let mut victim = relay.connect("client", "b").await;
    attacker
        .send(frame("b", "collision", "spoof"))
        .await
        .unwrap();
    victim.send(frame("b", "valid", "safe")).await.unwrap();
    let Message::Binary(bytes) = next(&mut server).await else {
        panic!("expected legitimate adapter frame")
    };
    assert_eq!(decode_adapter_frame(&bytes).unwrap().payload, b"safe");
}

#[tokio::test]
async fn equal_connection_ids_from_different_clients_stay_isolated() {
    let relay = Relay::spawn("127.0.0.1:0").await;
    let runtime = Runtime::spawn().await;
    let _bridge = run_bridge(relay.bridge_config(&runtime.url)).await.unwrap();
    let mut a = relay.connect("client", "a").await;
    let mut b = relay.connect("client", "b").await;
    for (socket, client, payload) in [(&mut a, "a", "first"), (&mut b, "b", "second")] {
        socket.send(frame(client, "same", payload)).await.unwrap();
        let Message::Binary(bytes) = next(socket).await else {
            panic!("expected isolated runtime reply")
        };
        let reply = decode_adapter_frame(&bytes).unwrap();
        assert_eq!(reply.header.client_id, client);
        assert_eq!(reply.payload, payload.as_bytes());
    }
}

#[tokio::test]
async fn invalid_text_payload_closes_only_its_connection() {
    let relay = Relay::spawn("127.0.0.1:0").await;
    let runtime = Runtime::spawn().await;
    let _bridge = run_bridge(relay.bridge_config(&runtime.url)).await.unwrap();
    let mut bad = relay.connect("client", "bad").await;
    let mut good = relay.connect("client", "good").await;
    let Message::Binary(bytes) = frame("bad", "one", "placeholder") else {
        unreachable!()
    };
    let mut invalid = decode_adapter_frame(&bytes).unwrap();
    invalid.payload = vec![0xff];
    bad.send(Message::Binary(encode_adapter_frame(&invalid).unwrap()))
        .await
        .unwrap();
    let Message::Binary(bytes) = next(&mut bad).await else {
        panic!("expected connection-local adapter close")
    };
    assert_eq!(
        decode_adapter_frame(&bytes).unwrap().header.close_code,
        Some(1007)
    );
    good.send(frame("good", "two", "unaffected")).await.unwrap();
    let Message::Binary(bytes) = next(&mut good).await else {
        panic!("other client must remain connected")
    };
    assert_eq!(decode_adapter_frame(&bytes).unwrap().payload, b"unaffected");
}

#[tokio::test]
async fn stalled_runtime_handshake_does_not_block_other_connections() {
    let relay = Relay::spawn("127.0.0.1:0").await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let runtime_url = format!("ws://{}", listener.local_addr().unwrap());
    let (accepted_tx, mut accepted_rx) = mpsc::channel(1);
    let task = tokio::spawn(async move {
        // Hold one TCP socket without completing its WebSocket upgrade.
        let (_stalled, _) = listener.accept().await.unwrap();
        accepted_tx.send(()).await.unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = accept_async(stream).await.unwrap();
        while let Some(Ok(message)) = socket.next().await {
            if let Message::Text(_) = message {
                socket.send(message).await.unwrap();
                break;
            }
        }
    });
    let _bridge = run_bridge(relay.bridge_config(&runtime_url)).await.unwrap();
    let mut stalled = relay.connect("client", "stalled").await;
    stalled.send(frame("stalled", "one", "wait")).await.unwrap();
    timeout(Duration::from_secs(1), accepted_rx.recv())
        .await
        .unwrap()
        .unwrap();
    let mut good = relay.connect("client", "good").await;
    good.send(frame("good", "two", "responsive")).await.unwrap();
    let Message::Binary(bytes) = timeout(Duration::from_secs(1), next(&mut good))
        .await
        .expect("a second handshake must not wait for the stalled first handshake")
    else {
        panic!("expected unaffected response")
    };
    assert_eq!(decode_adapter_frame(&bytes).unwrap().payload, b"responsive");
    task.abort();
}

#[tokio::test]
async fn runtime_replies_precede_its_original_terminal_close() {
    let relay = Relay::spawn("127.0.0.1:0").await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let runtime_url = format!("ws://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = accept_async(stream).await.unwrap();
        socket.next().await.unwrap().unwrap();
        socket
            .send(Message::Text("last reply".into()))
            .await
            .unwrap();
        socket
            .close(Some(tokio_tungstenite::tungstenite::protocol::CloseFrame {
                code: tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Normal,
                reason: "finished".into(),
            }))
            .await
            .unwrap();
    });
    let _bridge = run_bridge(relay.bridge_config(&runtime_url)).await.unwrap();
    let mut client = relay.connect("client", "a").await;
    client.send(frame("a", "one", "hello")).await.unwrap();
    let Message::Binary(bytes) = next(&mut client).await else {
        panic!("missing last reply")
    };
    assert_eq!(decode_adapter_frame(&bytes).unwrap().payload, b"last reply");
    let Message::Binary(bytes) = next(&mut client).await else {
        panic!("missing original close")
    };
    let close = decode_adapter_frame(&bytes).unwrap();
    assert_eq!(close.header.close_code, Some(1000));
    assert_eq!(close.header.close_reason.as_deref(), Some("finished"));
    // Past the next heartbeat sweep, no second/synthetic terminal frame may appear.
    assert!(timeout(Duration::from_secs(6), client.next())
        .await
        .is_err());
    task.await.unwrap();
}

#[tokio::test]
async fn bridge_reconnects_after_relay_socket_loss() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (accepted_tx, mut accepted_rx) = mpsc::channel(2);
    let task = tokio::spawn(async move {
        for attempt in 0..2 {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = accept_async(stream).await.unwrap();
            accepted_tx.send(()).await.unwrap();
            if attempt == 0 {
                socket.close(None).await.unwrap();
            } else {
                while let Some(Ok(message)) = socket.next().await {
                    if let Message::Ping(payload) = message {
                        socket.send(Message::Pong(payload)).await.unwrap();
                    }
                }
            }
        }
    });
    let bridge = run_bridge(BridgeConfig {
        relay_url: format!("ws://{addr}/ws"),
        local_runtime_url: "ws://127.0.0.1:1".into(),
        server_id: "recovery".into(),
        relay_token: TOKEN.into(),
    })
    .await
    .unwrap();
    for _ in 0..2 {
        timeout(Duration::from_secs(4), accepted_rx.recv())
            .await
            .expect("bridge should establish a fresh relay socket")
            .unwrap();
    }
    drop(bridge);
    task.abort();
}
