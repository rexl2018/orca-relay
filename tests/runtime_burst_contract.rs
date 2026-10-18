use std::{future::pending, time::Duration};

use futures_util::{SinkExt, StreamExt};
use orca_relay::adapter::{
    decode_adapter_frame, encode_adapter_frame, run_bridge, AdapterDirection, AdapterFrame,
    AdapterFrameHeader, AdapterOpcode, BridgeConfig, BridgeHandle,
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time::timeout,
};
use tokio_tungstenite::{accept_async, tungstenite::Message, WebSocketStream};

type RelaySocket = WebSocketStream<TcpStream>;
const WAIT: Duration = Duration::from_secs(3);

async fn bridge(runtime_url: String) -> (RelaySocket, BridgeHandle) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let config = BridgeConfig {
        relay_url: format!("ws://{}/ws", listener.local_addr().unwrap()),
        local_runtime_url: runtime_url,
        server_id: "runtime-burst".into(),
        relay_token: "runtime-burst-test-token".into(),
    };
    let connecting = tokio::spawn(run_bridge(config));
    let (stream, _) = listener.accept().await.unwrap();
    let socket = accept_async(stream).await.unwrap();
    (socket, connecting.await.unwrap().unwrap())
}

fn data(client: &str, payload: Vec<u8>) -> Message {
    Message::Binary(
        encode_adapter_frame(&AdapterFrame {
            header: AdapterFrameHeader {
                client_id: client.into(),
                connection_id: "connection".into(),
                direction: AdapterDirection::ClientToServer,
                opcode: AdapterOpcode::Binary,
                close_code: None,
                close_reason: None,
            },
            payload,
        })
        .unwrap(),
    )
}

async fn next(socket: &mut RelaySocket) -> Message {
    timeout(WAIT, socket.next())
        .await
        .expect("bridge must remain responsive")
        .expect("bridge relay socket must remain open")
        .unwrap()
}

async fn next_adapter(socket: &mut RelaySocket) -> AdapterFrame {
    loop {
        match next(socket).await {
            Message::Binary(bytes) => return decode_adapter_frame(&bytes).unwrap(),
            Message::Ping(payload) => socket.send(Message::Pong(payload)).await.unwrap(),
            message => panic!("expected adapter frame, got {message:?}"),
        }
    }
}

// The Pong is an ingress barrier: all preceding frames were handled while the
// runtime handshake was still held. No adapter reply or close is expected yet.
async fn ingress_barrier(socket: &mut RelaySocket) {
    socket
        .send(Message::Ping(b"ingress-barrier".to_vec()))
        .await
        .unwrap();
    loop {
        match next(socket).await {
            Message::Pong(payload) if payload == b"ingress-barrier" => return,
            Message::Ping(payload) => socket.send(Message::Pong(payload)).await.unwrap(),
            Message::Binary(bytes) => {
                let frame = decode_adapter_frame(&bytes).unwrap();
                panic!(
                    "runtime ingress closed before the burst limit: code={:?}, reason={:?}",
                    frame.header.close_code, frame.header.close_reason
                );
            }
            message => panic!("expected barrier Pong, got {message:?}"),
        }
    }
}

#[tokio::test]
async fn pending_runtime_handshake_preserves_a_64_frame_burst_in_order() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let runtime_url = format!("ws://{}", listener.local_addr().unwrap());
    let (release_tx, release_rx) = oneshot::channel();
    let runtime = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        release_rx.await.unwrap();
        let mut socket = accept_async(stream).await.unwrap();
        for seq in 0..64u32 {
            let message = timeout(WAIT, socket.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(message, Message::Binary(seq.to_be_bytes().to_vec()));
            socket.send(message).await.unwrap();
        }
    });
    let (mut relay, _bridge) = bridge(runtime_url).await;
    for seq in 0..64u32 {
        relay
            .feed(data("burst", seq.to_be_bytes().to_vec()))
            .await
            .unwrap();
    }
    relay.flush().await.unwrap();
    ingress_barrier(&mut relay).await;
    release_tx.send(()).unwrap();
    for seq in 0..64u32 {
        let frame = next_adapter(&mut relay).await;
        assert_eq!(frame.header.opcode, AdapterOpcode::Binary);
        assert_eq!(frame.header.client_id, "burst");
        assert_eq!(frame.payload, seq.to_be_bytes());
    }
    runtime.await.unwrap();
}

struct Runtime {
    url: String,
    accepted: mpsc::Receiver<()>,
    task: JoinHandle<()>,
}

impl Runtime {
    async fn stalled_then_echoing() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let (accepted_tx, accepted) = mpsc::channel(1);
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            let (stalled, _) = listener.accept().await.unwrap();
            accepted_tx.send(()).await.unwrap();
            connections.spawn(async move {
                let _stalled = stalled;
                pending::<()>().await;
            });
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                connections.spawn(async move {
                    let mut socket = accept_async(stream).await.unwrap();
                    while let Some(Ok(message)) = socket.next().await {
                        if matches!(message, Message::Binary(_) | Message::Text(_))
                            && socket.send(message).await.is_err()
                        {
                            break;
                        }
                    }
                });
            }
        });
        Self {
            url,
            accepted,
            task,
        }
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn assert_overflow_is_isolated(relay: &mut RelaySocket) {
    let close = next_adapter(relay).await;
    assert_eq!(close.header.client_id, "slow");
    assert_eq!(close.header.opcode, AdapterOpcode::Close);
    assert_eq!(close.header.close_code, Some(1013));
    assert_eq!(
        close.header.close_reason.as_deref(),
        Some("runtime queue unavailable")
    );

    relay
        .send(data("healthy", b"unaffected".to_vec()))
        .await
        .unwrap();
    let reply = next_adapter(relay).await;
    assert_eq!(reply.header.client_id, "healthy");
    assert_eq!(reply.payload, b"unaffected");
    ingress_barrier(relay).await;
}

#[tokio::test]
async fn runtime_message_limit_closes_only_the_overflowing_connection_and_keeps_heartbeat() {
    let mut runtime = Runtime::stalled_then_echoing().await;
    let (mut relay, _bridge) = bridge(runtime.url.clone()).await;
    relay.send(data("slow", vec![0])).await.unwrap();
    timeout(WAIT, runtime.accepted.recv())
        .await
        .unwrap()
        .unwrap();
    for _ in 1..256 {
        relay.feed(data("slow", vec![0])).await.unwrap();
    }
    relay.flush().await.unwrap();
    ingress_barrier(&mut relay).await;
    relay.send(data("slow", vec![0])).await.unwrap();
    assert_overflow_is_isolated(&mut relay).await;

    let ping = timeout(Duration::from_secs(7), relay.next())
        .await
        .expect("overflow must not block scheduled bridge heartbeat")
        .unwrap()
        .unwrap();
    assert_eq!(ping, Message::Ping(b"orca-relay".to_vec()));
    relay
        .send(Message::Pong(b"orca-relay".to_vec()))
        .await
        .unwrap();
}

#[tokio::test]
async fn runtime_byte_limit_closes_only_the_overflowing_connection() {
    let mut runtime = Runtime::stalled_then_echoing().await;
    let (mut relay, _bridge) = bridge(runtime.url.clone()).await;
    relay.send(data("slow", vec![0])).await.unwrap();
    timeout(WAIT, runtime.accepted.recv())
        .await
        .unwrap()
        .unwrap();
    // Each adapter frame is below the existing 16 MiB message limit. Four
    // payloads fit in 64 MiB, but the next 8 KiB must exceed the byte budget
    // well before the independent 256-message limit.
    for _ in 0..4 {
        relay
            .send(data("slow", vec![0; 16 * 1024 * 1024 - 1024]))
            .await
            .unwrap();
    }
    ingress_barrier(&mut relay).await;
    relay.send(data("slow", vec![0; 8 * 1024])).await.unwrap();
    assert_overflow_is_isolated(&mut relay).await;
}
