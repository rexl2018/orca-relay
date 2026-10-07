use std::{
    fmt::Write as _,
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use futures_util::{SinkExt, StreamExt};
use orca_relay::{
    adapter::{
        run_bridge, run_proxy, run_proxy_with_server_ids, BridgeConfig, BridgeHandle, ProxyConfig,
        ProxyHandle,
    },
    app, RelayConfig,
};
use tokio::{net::TcpListener, sync::mpsc, task::JoinHandle, time::timeout};
use tokio_tungstenite::{
    accept_async, connect_async,
    tungstenite::{
        client::IntoClientRequest,
        http::{header::AUTHORIZATION, StatusCode},
        protocol::frame::coding::CloseCode,
        Error as WsError, Message,
    },
    MaybeTlsStream, WebSocketStream,
};

const TOKEN: &str = "multiplex-test-token";
const SERVER_A: &str = "server-a";
const SERVER_B: &str = "server-b";
const SERVER_C: &str = "server-c";
const STEP: Duration = Duration::from_secs(3);
type Ws = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

static NEXT_PROBE: AtomicUsize = AtomicUsize::new(0);

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

    async fn bridge(&self, server_id: &str, runtime: &TaggedRuntime) -> BridgeHandle {
        let bridge = run_bridge(BridgeConfig {
            relay_url: self.url(),
            local_runtime_url: runtime.url.clone(),
            server_id: server_id.to_owned(),
            relay_token: TOKEN.to_owned(),
        })
        .await
        .expect("bridge should connect to the test relay");
        self.wait_registered(server_id).await;
        bridge
    }

    /// The relay registers a host after the upgrade completes; probe until clients are accepted.
    async fn wait_registered(&self, server_id: &str) {
        let probe = format!("probe-{}", NEXT_PROBE.fetch_add(1, Ordering::Relaxed));
        let url = format!(
            "{}?role=client&serverId={}&clientId={probe}&v=1",
            self.url(),
            percent_encode(server_id)
        );
        timeout(STEP, async {
            loop {
                let mut request = url.as_str().into_client_request().unwrap();
                request
                    .headers_mut()
                    .insert(AUTHORIZATION, format!("Bearer {TOKEN}").parse().unwrap());
                match connect_async(request).await {
                    Ok((mut socket, _)) => {
                        let _ = socket.close(None).await;
                        return;
                    }
                    Err(WsError::Http(response))
                        if response.status() == StatusCode::SERVICE_UNAVAILABLE =>
                    {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    Err(error) => panic!("unexpected relay probe failure: {error}"),
                }
            }
        })
        .await
        .expect("bridge never registered with the relay");
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Echo runtime that tags every reply so a misrouted connection cannot pass as a correct one.
struct TaggedRuntime {
    tag: &'static str,
    url: String,
    observed: mpsc::UnboundedReceiver<Message>,
    connections: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl TaggedRuntime {
    async fn spawn(tag: &'static str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let (observed_tx, observed) = mpsc::unbounded_channel();
        let connections = Arc::new(AtomicUsize::new(0));
        let accepted = Arc::clone(&connections);
        let task = tokio::spawn(async move {
            let mut sockets = tokio::task::JoinSet::new();
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                accepted.fetch_add(1, Ordering::SeqCst);
                let observed_tx = observed_tx.clone();
                sockets.spawn(async move {
                    let Ok(mut socket) = accept_async(stream).await else {
                        return;
                    };
                    while let Some(Ok(message)) = socket.next().await {
                        let reply = match &message {
                            Message::Text(text) => Message::Text(format!("{tag}|{text}")),
                            Message::Binary(bytes) => Message::Binary(tagged_bytes(tag, bytes)),
                            Message::Close(_) => break,
                            _ => continue,
                        };
                        let _ = observed_tx.send(message);
                        if socket.send(reply).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        Self {
            tag,
            url,
            observed,
            connections,
            task,
        }
    }

    async fn next_observed(&mut self) -> Message {
        timeout(STEP, self.observed.recv())
            .await
            .unwrap_or_else(|_| panic!("runtime {} observed nothing", self.tag))
            .expect("runtime observation channel closed")
    }

    fn assert_quiet(&mut self) {
        assert!(
            self.observed.try_recv().is_err(),
            "runtime {} received a message that was routed elsewhere",
            self.tag
        );
    }

    fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }
}

impl Drop for TaggedRuntime {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn tagged_bytes(tag: &str, payload: &[u8]) -> Vec<u8> {
    let mut bytes = format!("{tag}|").into_bytes();
    bytes.extend_from_slice(payload);
    bytes
}

fn percent_encode(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            encoded.push(byte as char);
        } else {
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}

fn proxy_config(relay: &Relay, default_server_id: &str) -> ProxyConfig {
    ProxyConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        relay_url: relay.url(),
        server_id: default_server_id.to_owned(),
        relay_token: TOKEN.to_owned(),
        client_id: "multiplex-cli".to_owned(),
    }
}

async fn multiplex_proxy(relay: &Relay, default_server_id: &str, extra: &[&str]) -> ProxyHandle {
    run_proxy_with_server_ids(
        proxy_config(relay, default_server_id),
        extra.iter().map(|id| id.to_string()).collect(),
    )
    .await
    .expect("multiplex proxy should bind")
}

async fn connect(proxy: &ProxyHandle, path: &str) -> Ws {
    timeout(
        STEP,
        connect_async(format!("ws://{}{path}", proxy.local_addr())),
    )
    .await
    .expect("proxy upgrade timed out")
    .unwrap_or_else(|error| panic!("proxy should upgrade {path}: {error}"))
    .0
}

async fn assert_rejected_before_upgrade(proxy: &ProxyHandle, path: &str) {
    let result = timeout(
        STEP,
        connect_async(format!("ws://{}{path}", proxy.local_addr())),
    )
    .await
    .expect("proxy rejection timed out");
    match result {
        Err(WsError::Http(response)) => assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "{path} must be rejected with 404"
        ),
        Ok(_) => panic!("{path} must not upgrade"),
        Err(error) => panic!("{path} must fail with an HTTP 404, got {error}"),
    }
}

async fn next(socket: &mut Ws) -> Option<Message> {
    timeout(STEP, async {
        loop {
            match socket.next().await {
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
                Some(Ok(message)) => return Some(message),
                Some(Err(_)) | None => return None,
            }
        }
    })
    .await
    .expect("timed out waiting for a proxy websocket message")
}

async fn assert_closed(socket: &mut Ws) {
    match next(socket).await {
        Some(Message::Close(_)) | None => {}
        Some(other) => panic!("expected the routed connection to close, got {other:?}"),
    }
}

/// Sends one opaque text and one opaque binary payload and checks both directions byte-for-byte.
async fn round_trip(socket: &mut Ws, runtime: &mut TaggedRuntime, label: &str) {
    let text = format!("opaque text ✓ {label} \u{0}\t{{\"k\":[1,2]}}");
    socket.send(Message::Text(text.clone())).await.unwrap();
    assert_eq!(runtime.next_observed().await, Message::Text(text.clone()));
    assert_eq!(
        next(socket).await,
        Some(Message::Text(format!("{}|{text}", runtime.tag)))
    );

    let mut binary = vec![0x00, 0xff, 0x80, 0x7f, b'|', 0x00];
    binary.extend_from_slice(label.as_bytes());
    binary.extend((0..=255u8).cycle().take(32 * 1024));
    socket.send(Message::Binary(binary.clone())).await.unwrap();
    assert_eq!(
        runtime.next_observed().await,
        Message::Binary(binary.clone())
    );
    assert_eq!(
        next(socket).await,
        Some(Message::Binary(tagged_bytes(runtime.tag, &binary)))
    );
}

#[tokio::test]
async fn one_listener_forwards_three_targets_concurrently_without_cross_talk() {
    let relay = Relay::spawn().await;
    let mut runtime_a = TaggedRuntime::spawn("runtime-a").await;
    let mut runtime_b = TaggedRuntime::spawn("runtime-b").await;
    let mut runtime_c = TaggedRuntime::spawn("runtime-c").await;
    let _bridge_a = relay.bridge(SERVER_A, &runtime_a).await;
    let _bridge_b = relay.bridge(SERVER_B, &runtime_b).await;
    let _bridge_c = relay.bridge(SERVER_C, &runtime_c).await;
    let proxy = multiplex_proxy(&relay, SERVER_A, &[SERVER_B, SERVER_C]).await;

    let mut cli_a = connect(&proxy, "/ws").await;
    let mut cli_b = connect(&proxy, "/r/server-b").await;
    let mut cli_c = connect(&proxy, "/r/server-c/ws").await;

    tokio::join!(
        async {
            for round in 0..5 {
                round_trip(&mut cli_a, &mut runtime_a, &format!("a-{round}")).await;
            }
        },
        async {
            for round in 0..5 {
                round_trip(&mut cli_b, &mut runtime_b, &format!("b-{round}")).await;
            }
        },
        async {
            for round in 0..5 {
                round_trip(&mut cli_c, &mut runtime_c, &format!("c-{round}")).await;
            }
        },
    );

    for runtime in [&mut runtime_a, &mut runtime_b, &mut runtime_c] {
        runtime.assert_quiet();
        assert_eq!(
            runtime.connections(),
            1,
            "one runtime socket per routed client"
        );
    }
}

#[tokio::test]
async fn root_and_ws_stay_on_default_and_query_cannot_switch_targets() {
    let relay = Relay::spawn().await;
    let mut runtime_a = TaggedRuntime::spawn("runtime-a").await;
    let mut runtime_b = TaggedRuntime::spawn("runtime-b").await;
    let mut runtime_c = TaggedRuntime::spawn("runtime-c").await;
    let _bridge_a = relay.bridge(SERVER_A, &runtime_a).await;
    let _bridge_b = relay.bridge(SERVER_B, &runtime_b).await;
    let _bridge_c = relay.bridge(SERVER_C, &runtime_c).await;
    // Padded entries are trimmed and a repeated default ID is harmless.
    let proxy = multiplex_proxy(&relay, SERVER_A, &[" server-b\t", SERVER_A, SERVER_B]).await;

    for path in [
        "/",
        "/ws",
        "/?serverId=server-b",
        "/ws?serverId=server-b&role=server&v=1",
        "/ws?server_id=server-c&server-id=server-b",
        "/r/server-a",
        "/r/server-a/ws?serverId=server-b",
    ] {
        let mut cli = connect(&proxy, path).await;
        round_trip(&mut cli, &mut runtime_a, path).await;
        let _ = cli.close(None).await;
    }
    let mut cli = connect(&proxy, "/r/server-b?serverId=server-a").await;
    round_trip(&mut cli, &mut runtime_b, "query on routed path").await;
    assert_rejected_before_upgrade(&proxy, "/r/server-c?serverId=server-a").await;

    runtime_b.assert_quiet();
    runtime_c.assert_quiet();
    assert_eq!(runtime_c.connections(), 0);
}

#[tokio::test]
async fn existing_but_not_allowed_bridge_and_unknown_ids_are_rejected_before_upgrade() {
    let relay = Relay::spawn().await;
    let mut runtime_a = TaggedRuntime::spawn("runtime-a").await;
    let mut runtime_b = TaggedRuntime::spawn("runtime-b").await;
    let runtime_c = TaggedRuntime::spawn("runtime-c").await;
    let _bridge_a = relay.bridge(SERVER_A, &runtime_a).await;
    let _bridge_b = relay.bridge(SERVER_B, &runtime_b).await;
    let _bridge_c = relay.bridge(SERVER_C, &runtime_c).await;
    let proxy = multiplex_proxy(&relay, SERVER_A, &[SERVER_B]).await;

    for path in [
        "/r/server-c",
        "/r/server-c/ws",
        "/r/server%2Dc",
        "/r/unknown",
        "/r/server-b/extra",
        "/r/server-b/ws/extra",
        "/r/",
        "/r",
    ] {
        assert_rejected_before_upgrade(&proxy, path).await;
    }
    assert_eq!(runtime_c.connections(), 0);

    // Rejections leave the listener and the allowed targets usable.
    let mut cli_a = connect(&proxy, "/ws").await;
    let mut cli_b = connect(&proxy, "/r/server-b/ws").await;
    round_trip(&mut cli_a, &mut runtime_a, "after rejection a").await;
    round_trip(&mut cli_b, &mut runtime_b, "after rejection b").await;
}

#[tokio::test]
async fn fixed_run_proxy_only_selects_its_configured_server_id() {
    let relay = Relay::spawn().await;
    let mut runtime_a = TaggedRuntime::spawn("runtime-a").await;
    let runtime_b = TaggedRuntime::spawn("runtime-b").await;
    let _bridge_a = relay.bridge(SERVER_A, &runtime_a).await;
    let _bridge_b = relay.bridge(SERVER_B, &runtime_b).await;
    let proxy = run_proxy(proxy_config(&relay, SERVER_A))
        .await
        .expect("legacy proxy should bind");

    for path in ["/", "/ws", "/ws?serverId=server-b", "/r/server-a/ws"] {
        let mut cli = connect(&proxy, path).await;
        round_trip(&mut cli, &mut runtime_a, path).await;
        let _ = cli.close(None).await;
    }
    for path in ["/r/server-b", "/r/server-b/ws"] {
        assert_rejected_before_upgrade(&proxy, path).await;
    }
    assert_eq!(runtime_b.connections(), 0);
}

#[tokio::test]
async fn invalid_additional_server_ids_fail_startup_without_reflecting_them() {
    const MARKER: &str = "marker-q7z";
    let relay = Relay::spawn().await;
    let mut invalid: Vec<String> = ["", " ", ".", "..", " .. ", "/", "\\"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    for suffix in ["/b", "\\b", "\u{7}", "\tid", "\nid", "\u{0}", "\u{7f}"] {
        invalid.push(format!("{MARKER}{suffix}"));
    }
    for id in invalid {
        let Err(error) = run_proxy_with_server_ids(
            proxy_config(&relay, SERVER_A),
            vec![SERVER_B.to_owned(), id.clone()],
        )
        .await
        else {
            panic!("additional server ID {id:?} must fail proxy startup");
        };
        let rendered = format!("{error:#} {error:?}");
        assert!(
            !rendered.contains(MARKER),
            "startup error must not reflect the rejected ID {id:?}"
        );
    }
    for valid in [
        "ws",
        "r",
        "team runtime",
        "ünïcode rüntime",
        "a.b",
        "a?b",
        "a#b",
        "a%41",
    ] {
        run_proxy_with_server_ids(proxy_config(&relay, SERVER_A), vec![valid.to_owned()])
            .await
            .unwrap_or_else(|_| panic!("additional server ID {valid:?} should be accepted"));
    }
}

#[tokio::test]
async fn unsafe_legacy_default_serves_root_but_is_not_a_named_route() {
    const LEGACY: &str = "legacy/unsafe";
    let relay = Relay::spawn().await;
    let mut runtime_legacy = TaggedRuntime::spawn("runtime-legacy").await;
    let mut runtime_b = TaggedRuntime::spawn("runtime-b").await;
    let _bridge_legacy = relay.bridge(LEGACY, &runtime_legacy).await;
    let _bridge_b = relay.bridge(SERVER_B, &runtime_b).await;

    let legacy = run_proxy(proxy_config(&relay, LEGACY))
        .await
        .expect("legacy proxy must keep accepting its existing default ID");
    let multiplex = multiplex_proxy(&relay, LEGACY, &[SERVER_B]).await;
    for proxy in [&legacy, &multiplex] {
        for path in ["/", "/ws", "/ws?serverId=server-b"] {
            let mut cli = connect(proxy, path).await;
            round_trip(&mut cli, &mut runtime_legacy, path).await;
            let _ = cli.close(None).await;
        }
        for path in [
            "/r/legacy%2Funsafe",
            "/r/legacy%2Funsafe/ws",
            "/r/legacy%2funsafe",
        ] {
            assert_rejected_before_upgrade(proxy, path).await;
        }
    }
    let mut cli = connect(&multiplex, "/r/server-b").await;
    round_trip(&mut cli, &mut runtime_b, "named beside unsafe default").await;
    runtime_legacy.assert_quiet();
    runtime_b.assert_quiet();
}

#[tokio::test]
async fn encoded_separators_and_dot_segments_cannot_reach_existing_bridges() {
    let relay = Relay::spawn().await;
    let mut runtime_a = TaggedRuntime::spawn("runtime-a").await;
    let mut hidden = Vec::new();
    for id in ["..", ".", "a/b", "a\\b", "bell\u{7}id"] {
        let runtime = TaggedRuntime::spawn("runtime-hidden").await;
        let bridge = relay.bridge(id, &runtime).await;
        hidden.push((runtime, bridge));
    }
    let _bridge_a = relay.bridge(SERVER_A, &runtime_a).await;
    let proxy = multiplex_proxy(&relay, SERVER_A, &[SERVER_B]).await;

    for path in [
        "/r/%2E%2E",
        "/r/%2e%2e/ws",
        "/r/%2E",
        "/r/a%2Fb",
        "/r/a%2fb/ws",
        "/r/a%5Cb",
        "/r/bell%07id",
        "/r/server-a%2Fws",
        "/r/server-a%00",
    ] {
        assert_rejected_before_upgrade(&proxy, path).await;
    }
    for (runtime, _) in &hidden {
        assert_eq!(runtime.connections(), 0);
    }
    let mut cli = connect(&proxy, "/ws").await;
    round_trip(&mut cli, &mut runtime_a, "default after encoded rejections").await;
}

#[tokio::test]
async fn allowed_target_without_bridge_closes_cleanly_and_recovers_when_bridge_arrives() {
    let relay = Relay::spawn().await;
    let mut runtime_a = TaggedRuntime::spawn("runtime-a").await;
    let mut runtime_late = TaggedRuntime::spawn("runtime-late").await;
    let _bridge_a = relay.bridge(SERVER_A, &runtime_a).await;
    let proxy = multiplex_proxy(&relay, SERVER_A, &["server-late"]).await;
    let mut cli_a = connect(&proxy, "/ws").await;
    round_trip(&mut cli_a, &mut runtime_a, "before missing").await;

    let mut missing = connect(&proxy, "/r/server-late/ws").await;
    match next(&mut missing).await {
        Some(Message::Close(Some(frame))) => assert_eq!(frame.code, CloseCode::Again),
        other => panic!("missing bridge must close with 1013, got {other:?}"),
    }
    assert!(next(&mut missing).await.is_none());

    // Other routed clients keep working, and the target recovers without restarting the proxy.
    round_trip(&mut cli_a, &mut runtime_a, "after missing").await;
    let _bridge_late = relay.bridge("server-late", &runtime_late).await;
    let mut late = connect(&proxy, "/r/server-late").await;
    round_trip(&mut late, &mut runtime_late, "late bridge").await;
    runtime_a.assert_quiet();
}

#[tokio::test]
async fn replacing_one_bridge_only_disconnects_its_routed_clients() {
    let relay = Relay::spawn().await;
    let mut runtime_a = TaggedRuntime::spawn("runtime-a").await;
    let mut runtime_b = TaggedRuntime::spawn("runtime-b").await;
    let mut runtime_c = TaggedRuntime::spawn("runtime-c").await;
    let mut runtime_b2 = TaggedRuntime::spawn("runtime-b2").await;
    let _bridge_a = relay.bridge(SERVER_A, &runtime_a).await;
    let mut bridge_b = relay.bridge(SERVER_B, &runtime_b).await;
    let _bridge_c = relay.bridge(SERVER_C, &runtime_c).await;
    let proxy = multiplex_proxy(&relay, SERVER_A, &[SERVER_B, SERVER_C]).await;

    let mut cli_a = connect(&proxy, "/").await;
    let mut cli_b = connect(&proxy, "/r/server-b/ws").await;
    let mut cli_c = connect(&proxy, "/r/server-c").await;
    round_trip(&mut cli_a, &mut runtime_a, "a before").await;
    round_trip(&mut cli_b, &mut runtime_b, "b before").await;
    round_trip(&mut cli_c, &mut runtime_c, "c before").await;

    let _bridge_b2 = run_bridge(BridgeConfig {
        relay_url: relay.url(),
        local_runtime_url: runtime_b2.url.clone(),
        server_id: SERVER_B.to_owned(),
        relay_token: TOKEN.to_owned(),
    })
    .await
    .expect("replacement bridge should connect");
    assert_closed(&mut cli_b).await;
    timeout(STEP, bridge_b.wait())
        .await
        .expect("superseded bridge must stop")
        .expect("superseded bridge should exit cleanly");

    // The same proxy connections to the untouched targets continue uninterrupted.
    round_trip(&mut cli_a, &mut runtime_a, "a after").await;
    round_trip(&mut cli_c, &mut runtime_c, "c after").await;
    let mut new_b = connect(&proxy, "/r/server-b").await;
    round_trip(&mut new_b, &mut runtime_b2, "b after").await;

    for runtime in [
        &mut runtime_a,
        &mut runtime_b,
        &mut runtime_c,
        &mut runtime_b2,
    ] {
        runtime.assert_quiet();
    }
    assert_eq!(runtime_a.connections(), 1);
    assert_eq!(runtime_c.connections(), 1);
}

#[tokio::test]
async fn percent_encoded_route_ids_match_the_decoded_allowlist() {
    const SPACED: &str = "team runtime";
    const UNICODE: &str = "ünïcode rüntime";
    let relay = Relay::spawn().await;
    let mut runtimes = [
        TaggedRuntime::spawn("runtime-a").await,
        TaggedRuntime::spawn("runtime-spaced").await,
        TaggedRuntime::spawn("runtime-unicode").await,
        TaggedRuntime::spawn("runtime-ws").await,
        TaggedRuntime::spawn("runtime-question").await,
        TaggedRuntime::spawn("runtime-hash").await,
        TaggedRuntime::spawn("runtime-percent").await,
    ];
    let named = [SPACED, UNICODE, "ws", "a?b", "a#b", "a%41"];
    let mut bridges = Vec::new();
    for (id, runtime) in std::iter::once(SERVER_A).chain(named).zip(&runtimes) {
        bridges.push(relay.bridge(id, runtime).await);
    }
    let proxy = multiplex_proxy(&relay, SERVER_A, &named).await;

    let unicode_path = format!("/r/{}", percent_encode(UNICODE));
    for (path, target) in [
        ("/r/team%20runtime".to_owned(), 1),
        ("/r/team%20runtime/ws?serverId=server-a".to_owned(), 1),
        (unicode_path.clone(), 2),
        (format!("{unicode_path}/ws"), 2),
        ("/r/ws".to_owned(), 3),
        ("/r/ws/ws?serverId=server-a".to_owned(), 3),
        // Reserved characters in an ID use standard exact segment encoding.
        ("/r/a%3Fb".to_owned(), 4),
        ("/r/a%3fb/ws".to_owned(), 4),
        ("/r/a%23b".to_owned(), 5),
        ("/r/a%23b/ws".to_owned(), 5),
        ("/r/a%2541".to_owned(), 6),
        ("/r/a%2541/ws?serverId=server-a".to_owned(), 6),
        ("/r/server%2Da".to_owned(), 0),
        ("/ws?serverId=team%20runtime".to_owned(), 0),
    ] {
        let mut cli = connect(&proxy, &path).await;
        round_trip(&mut cli, &mut runtimes[target], &path).await;
        let _ = cli.close(None).await;
    }

    for path in [
        "/r/team%20other",
        "/r/team%2520runtime",
        "/r/team",
        "/r/%C3%BCn%C3%AFcode",
        "/r/ws%20",
        "/r/a?b",
        "/r/a%41",
        "/r/a%2541%20",
    ] {
        assert_rejected_before_upgrade(&proxy, path).await;
    }
    for runtime in &mut runtimes {
        runtime.assert_quiet();
    }
}
