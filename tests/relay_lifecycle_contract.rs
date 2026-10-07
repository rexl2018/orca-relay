use std::{net::SocketAddr, time::Duration};

use futures_util::{SinkExt, StreamExt};
use orca_relay::{
    adapter::{AdapterDirection, AdapterOpcode},
    app, RelayConfig,
};
use serde_json::{json, Value};
use tokio::{net::TcpListener, task::JoinHandle, time::timeout};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{client::IntoClientRequest, http::header::AUTHORIZATION, Message},
    MaybeTlsStream, WebSocketStream,
};

const TOKEN: &str = "lifecycle-test-token";
const LIFECYCLE_REASON: &str = "relay client disconnected";
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

    async fn connect(&self, role: &str, client: &str) -> Ws {
        let mut request = format!(
            "ws://{}/ws?role={role}&serverId=lifecycle&clientId={client}&v=1",
            self.addr
        )
        .into_client_request()
        .unwrap();
        request
            .headers_mut()
            .insert(AUTHORIZATION, format!("Bearer {TOKEN}").parse().unwrap());
        connect_async(request).await.unwrap().0
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn encode(header: Value, payload: &[u8]) -> Message {
    let header = serde_json::to_vec(&header).unwrap();
    let mut frame = (header.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(&header);
    frame.extend_from_slice(payload);
    Message::Binary(frame)
}

fn data(client: &str, connection: &str, direction: &str, payload: &[u8]) -> Message {
    encode(
        json!({"clientId": client, "connectionId": connection, "direction": direction, "opcode": "binary"}),
        payload,
    )
}

fn decode(message: Message) -> (Value, Vec<u8>) {
    let Message::Binary(frame) = message else {
        panic!("expected binary adapter frame, got {message:?}")
    };
    let header_len = u32::from_be_bytes(frame[0..4].try_into().unwrap()) as usize;
    (
        serde_json::from_slice(&frame[4..4 + header_len]).unwrap(),
        frame[4 + header_len..].to_vec(),
    )
}

async fn next(socket: &mut Ws, wait: Duration) -> Message {
    timeout(wait, async {
        loop {
            let message = socket.next().await.unwrap().unwrap();
            if !matches!(message, Message::Ping(_) | Message::Pong(_)) {
                return message;
            }
        }
    })
    .await
    .expect("expected a relay message in time")
}

fn assert_lifecycle_close(header: &Value, payload: &[u8], client: &str, connection: &str) {
    assert_eq!(header["clientId"], client);
    assert_eq!(header["connectionId"], connection);
    assert_eq!(
        header["direction"],
        serde_json::to_value(AdapterDirection::ClientToServer).unwrap()
    );
    assert_eq!(
        header["opcode"],
        serde_json::to_value(AdapterOpcode::Close).unwrap()
    );
    assert_eq!(header["closeCode"], 1001);
    assert_eq!(header["closeReason"], LIFECYCLE_REASON);
    assert_eq!(&payload[..2], &1001u16.to_be_bytes());
    assert_eq!(&payload[2..], LIFECYCLE_REASON.as_bytes());
}

async fn close_reason(socket: &mut Ws, wait: Duration) -> String {
    timeout(wait, async {
        loop {
            match socket.next().await {
                Some(Ok(Message::Close(Some(close)))) => return close.reason.into_owned(),
                Some(Ok(Message::Close(None))) | None | Some(Err(_)) => return String::new(),
                Some(Ok(_)) => {}
            }
        }
    })
    .await
    .expect("expected the relay to close the socket")
}

#[tokio::test]
async fn slow_client_is_retired_without_stalling_host_or_dropping_mid_stream() {
    let relay = Relay::spawn().await;
    let mut server = relay.connect("server", "").await;
    let mut slow = relay.connect("client", "slow").await;
    let mut fast = relay.connect("client", "fast").await;
    slow.send(data("slow", "s1", "client_to_server", b"open"))
        .await
        .unwrap();
    assert_eq!(
        decode(next(&mut server, Duration::from_secs(3)).await).1,
        b"open"
    );

    const FRAMES: u64 = 64;
    let chunk = vec![0xA5u8; 1024 * 1024];
    for seq in 0..FRAMES {
        let mut payload = seq.to_be_bytes().to_vec();
        payload.extend_from_slice(&chunk);
        server
            .send(data("slow", "s1", "server_to_client", &payload))
            .await
            .unwrap();
    }
    server
        .send(data("fast", "f1", "server_to_client", b"unblocked"))
        .await
        .unwrap();
    let (_, payload) = decode(next(&mut fast, Duration::from_secs(3)).await);
    assert_eq!(
        payload, b"unblocked",
        "a slow client must not stall the host"
    );

    let (header, payload) = decode(next(&mut server, Duration::from_secs(15)).await);
    assert_lifecycle_close(&header, &payload, "slow", "s1");

    let mut delivered = 0u64;
    let drained = timeout(Duration::from_secs(15), async {
        while let Some(Ok(message)) = slow.next().await {
            match message {
                Message::Binary(_) => {
                    let (_, payload) = decode(message);
                    let seq = u64::from_be_bytes(payload[..8].try_into().unwrap());
                    assert_eq!(seq, delivered, "retired client must not see a gap");
                    delivered += 1;
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
    })
    .await;
    assert!(drained.is_ok(), "retired client socket must terminate");
    assert!(delivered < FRAMES, "overflowing client must be retired");
}

#[tokio::test]
async fn client_disconnect_closes_only_known_open_adapter_connections() {
    let relay = Relay::spawn().await;
    let mut server = relay.connect("server", "").await;
    let mut legacy = relay.connect("client", "legacy").await;
    legacy
        .send(encode(json!({"clientId": "legacy"}), b"\x00opaque\xff"))
        .await
        .unwrap();
    let (header, payload) = decode(next(&mut server, Duration::from_secs(3)).await);
    assert_eq!(header, json!({"clientId": "legacy"}));
    assert_eq!(payload, b"\x00opaque\xff");
    drop(legacy);

    let mut client = relay.connect("client", "a").await;
    client
        .send(data("a", "c1", "client_to_server", b"one"))
        .await
        .unwrap();
    client
        .send(data("a", "c2", "client_to_server", b"two"))
        .await
        .unwrap();
    client
        .send(encode(
            json!({"clientId": "a", "connectionId": "c2", "direction": "client_to_server", "opcode": "close", "closeCode": 1000, "closeReason": "done"}),
            b"\x03\xe8done",
        ))
        .await
        .unwrap();
    for expected in [&b"one"[..], b"two", b"\x03\xe8done"] {
        let (header, payload) = decode(next(&mut server, Duration::from_secs(3)).await);
        assert_eq!(header["clientId"], "a");
        assert_eq!(payload, expected);
    }
    drop(client);

    let (header, payload) = decode(next(&mut server, Duration::from_secs(3)).await);
    assert_lifecycle_close(&header, &payload, "a", "c1");
    assert!(
        timeout(Duration::from_millis(300), server.next())
            .await
            .is_err(),
        "legacy frames and already-closed connections get no lifecycle close"
    );
}

#[tokio::test]
async fn replacement_closes_predecessor_connections_before_successor_frames() {
    let relay = Relay::spawn().await;
    let mut server = relay.connect("server", "").await;
    let mut old = relay.connect("client", "a").await;
    old.send(data("a", "same", "client_to_server", b"old"))
        .await
        .unwrap();
    assert_eq!(
        decode(next(&mut server, Duration::from_secs(3)).await).1,
        b"old"
    );

    let mut new = relay.connect("client", "a").await;
    new.send(data("a", "same", "client_to_server", b"new"))
        .await
        .unwrap();
    let (header, payload) = decode(next(&mut server, Duration::from_secs(3)).await);
    assert_lifecycle_close(&header, &payload, "a", "same");
    assert_eq!(
        decode(next(&mut server, Duration::from_secs(3)).await).1,
        b"new"
    );
    assert_eq!(
        close_reason(&mut old, Duration::from_secs(3)).await,
        "client replaced"
    );
}

#[tokio::test]
async fn server_replacement_closes_sockets_even_with_full_queues() {
    let relay = Relay::spawn().await;
    let mut old_server = relay.connect("server", "").await;
    let client = relay.connect("client", "c").await;
    let (mut client_tx, mut client_rx) = client.split();
    let flood = tokio::spawn(async move {
        let chunk = vec![0x5Au8; 256 * 1024];
        for _ in 0..64 {
            let send = client_tx.send(data("c", "x", "client_to_server", &chunk));
            if !matches!(timeout(Duration::from_secs(1), send).await, Ok(Ok(()))) {
                break;
            }
        }
    });
    tokio::time::sleep(Duration::from_millis(500)).await;

    let mut new_server = relay.connect("server", "").await;
    let reason = timeout(Duration::from_secs(5), async {
        loop {
            match client_rx.next().await {
                Some(Ok(Message::Close(Some(close)))) => return close.reason.into_owned(),
                Some(Ok(_)) => {}
                _ => return String::new(),
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(reason, "server replaced");
    assert_eq!(
        close_reason(&mut old_server, Duration::from_secs(15)).await,
        "server replaced",
        "a full host queue must not swallow the replacement close"
    );
    flood.abort();

    let mut client = relay.connect("client", "c").await;
    client
        .send(data("c", "y", "client_to_server", b"fresh"))
        .await
        .unwrap();
    let (header, payload) = decode(next(&mut new_server, Duration::from_secs(3)).await);
    assert_eq!(header["connectionId"], "y");
    assert_eq!(payload, b"fresh");
}
