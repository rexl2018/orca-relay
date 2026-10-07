use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use anyhow::{anyhow, bail, Context, Result};
use axum::{
    extract::{
        ws::{close_code, CloseFrame, Message, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::{
    sync::{mpsc, Mutex, RwLock},
    task::JoinHandle,
};

type Tx = mpsc::Sender<Message>;
const QUEUE_CAPACITY: usize = 8;
const WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;
const RELAY_CLIENT_DISCONNECTED: &str = "relay client disconnected";
// Standard Ping/Pong, so bridges that never ping the relay stay registered while they answer.
const HOST_HEARTBEAT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);
const HOST_HEARTBEAT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
const HOST_HEARTBEAT: &[u8] = b"orca-relay";

#[derive(Clone)]
struct AppState {
    config: RelayConfig,
    sessions: Arc<RwLock<HashMap<String, Session>>>,
}

#[derive(Clone, Default)]
struct Session {
    server: Option<Peer>,
    clients: HashMap<String, ClientPeer>,
}

/// One relay socket: a bounded data queue plus a close slot that never waits behind data.
#[derive(Clone)]
struct Peer {
    data: Tx,
    control: Tx,
    retired: Arc<AtomicBool>,
}

impl Peer {
    fn new() -> (Self, mpsc::Receiver<Message>, mpsc::Receiver<Message>) {
        let (data, data_rx) = mpsc::channel(QUEUE_CAPACITY);
        let (control, control_rx) = mpsc::channel(1);
        let peer = Self {
            data,
            control,
            retired: Arc::new(AtomicBool::new(false)),
        };
        (peer, data_rx, control_rx)
    }

    fn same(&self, other: &Peer) -> bool {
        self.data.same_channel(&other.data)
    }

    fn is_retired(&self) -> bool {
        self.retired.load(Ordering::Acquire)
    }

    /// Shutdown state is published before the close is queued, so no later lookup forwards into it.
    fn retire(&self, code: u16, reason: &'static str) {
        if !self.retired.swap(true, Ordering::AcqRel) {
            let _ = self.control.try_send(close_message(code, reason));
        }
    }
}

#[derive(Clone)]
struct ClientPeer {
    client_id: String,
    peer: Peer,
    /// The host this socket was admitted to; lifecycle closes never reach a successor host.
    server: Peer,
    connections: Arc<Mutex<ClientConnections>>,
}

#[derive(Default)]
struct ClientConnections {
    open: HashSet<String>,
    retired: bool,
}

pub fn rewrite_pairing_code(input: &str, local_endpoint: &str) -> Result<String> {
    let pairing_code = parse_pairing_code_input(input)?;
    let decoded = URL_SAFE_NO_PAD
        .decode(pairing_code.payload.as_bytes())
        .context("invalid pairing code encoding")?;
    let mut offer: Value =
        serde_json::from_slice(&decoded).context("invalid pairing code payload")?;
    let offer_object = offer
        .as_object_mut()
        .ok_or_else(|| anyhow!("invalid pairing code payload"))?;

    if offer_object.get("v").and_then(Value::as_u64) != Some(2) {
        bail!("unsupported pairing code version");
    }

    for field in ["endpoint", "deviceToken", "publicKeyB64"] {
        if !matches!(offer_object.get(field), Some(value) if value.is_string()) {
            bail!("invalid pairing code payload");
        }
    }

    offer_object.insert(
        "endpoint".to_string(),
        Value::String(local_endpoint.to_string()),
    );

    let encoded = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&offer).context("failed to encode pairing code payload")?);

    Ok(match pairing_code.shape {
        PairingCodeShape::Bare => encoded,
        PairingCodeShape::DeepLink => format!("orca://pair?code={encoded}"),
        PairingCodeShape::WebClient { prefix, suffix } => {
            let inner = format!("orca://pair?code={encoded}");
            format!("{prefix}{}{suffix}", encode_uri_component(&inner))
        }
    })
}

struct PairingCodeInput<'a> {
    payload: Cow<'a, str>,
    shape: PairingCodeShape<'a>,
}

enum PairingCodeShape<'a> {
    Bare,
    DeepLink,
    WebClient { prefix: &'a str, suffix: &'a str },
}

fn parse_pairing_code_input(input: &str) -> Result<PairingCodeInput<'_>> {
    let input = input.trim();
    if input.is_empty() {
        bail!("invalid pairing code payload");
    }

    if starts_with_ignore_ascii_case(input, "orca://") {
        return parse_orca_pairing_link(input);
    }

    if starts_with_ignore_ascii_case(input, "http://")
        || starts_with_ignore_ascii_case(input, "https://")
    {
        return parse_web_client_pairing_link(input);
    }

    Ok(PairingCodeInput {
        payload: Cow::Borrowed(input),
        shape: PairingCodeShape::Bare,
    })
}

fn parse_orca_pairing_link(input: &str) -> Result<PairingCodeInput<'_>> {
    Ok(PairingCodeInput {
        payload: Cow::Borrowed(pairing_payload_from_orca_link(input)?),
        shape: PairingCodeShape::DeepLink,
    })
}

fn pairing_payload_from_orca_link(input: &str) -> Result<&str> {
    let rest = &input["orca://".len()..];
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let host = &rest[..authority_end];
    if !host.eq_ignore_ascii_case("pair") {
        bail!("invalid pairing code link");
    }

    let after_authority = &rest[authority_end..];
    let path_end = after_authority
        .find(['?', '#'])
        .unwrap_or(after_authority.len());
    let path = &after_authority[..path_end];
    if !path.is_empty() && path != "/" {
        bail!("invalid pairing code link");
    }

    if let Some(query_start) = input.find('?') {
        let query_end = input[query_start + 1..]
            .find('#')
            .map_or(input.len(), |offset| query_start + 1 + offset);
        for pair in input[query_start + 1..query_end].split('&') {
            if let Some(payload) = pair
                .strip_prefix("code=")
                .filter(|payload| !payload.is_empty())
            {
                return Ok(payload);
            }
        }
    }

    if let Some(hash_start) = input.find('#') {
        let payload = &input[hash_start + 1..];
        if !payload.is_empty() {
            return Ok(payload);
        }
    }

    bail!("invalid pairing code link");
}

fn parse_web_client_pairing_link(input: &str) -> Result<PairingCodeInput<'_>> {
    let fragment_start = input
        .find('#')
        .ok_or_else(|| anyhow!("invalid web client pairing link"))?
        + 1;
    let mut cursor = fragment_start;

    while cursor <= input.len() {
        let segment_end = input[cursor..]
            .find('&')
            .map_or(input.len(), |offset| cursor + offset);
        let segment = &input[cursor..segment_end];

        if let Some(value_offset) = segment.find('=') {
            if &segment[..value_offset] == "pairing" {
                let value_start = cursor + value_offset + 1;
                if value_start == segment_end {
                    bail!("invalid web client pairing link");
                }
                let decoded = percent_decode_fragment_value(&input[value_start..segment_end])?;
                let payload = if starts_with_ignore_ascii_case(&decoded, "orca://") {
                    pairing_payload_from_orca_link(&decoded)?.to_string()
                } else {
                    decoded
                };
                return Ok(PairingCodeInput {
                    payload: Cow::Owned(payload),
                    shape: PairingCodeShape::WebClient {
                        prefix: &input[..value_start],
                        suffix: &input[segment_end..],
                    },
                });
            }
        }

        if segment_end == input.len() {
            break;
        }
        cursor = segment_end + 1;
    }

    bail!("invalid web client pairing link");
}

fn percent_decode_fragment_value(input: &str) -> Result<String> {
    let mut output = Vec::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = bytes
                .get(index + 1)
                .and_then(|byte| hex_value(*byte))
                .ok_or_else(|| anyhow!("invalid web client pairing link"))?;
            let low = bytes
                .get(index + 2)
                .and_then(|byte| hex_value(*byte))
                .ok_or_else(|| anyhow!("invalid web client pairing link"))?;
            output.push(high << 4 | low);
            index += 3;
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }

    String::from_utf8(output).context("invalid web client pairing link")
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn encode_uri_component(input: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";

    let mut output = String::with_capacity(input.len());
    for byte in input.bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')'
            )
        {
            output.push(byte as char);
        } else {
            output.push('%');
            output.push(HEX[(byte >> 4) as usize] as char);
            output.push(HEX[(byte & 0x0f) as usize] as char);
        }
    }
    output
}

fn starts_with_ignore_ascii_case(input: &str, prefix: &str) -> bool {
    input
        .get(..prefix.len())
        .is_some_and(|actual| actual.eq_ignore_ascii_case(prefix))
}

pub fn app(config: RelayConfig) -> Router {
    let state = AppState {
        config,
        sessions: Arc::new(RwLock::new(HashMap::new())),
    };

    Router::new()
        .route("/health", get(health))
        .route("/ws", get(ws_handler))
        .with_state(state)
}

#[derive(Clone, Debug)]
pub struct RelayConfig {
    pub version: String,
    pub relay_token: String,
}

impl RelayConfig {
    pub fn new(version: impl Into<String>, relay_token: impl Into<String>) -> Self {
        Self {
            version: version.into(),
            relay_token: relay_token.into(),
        }
    }
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    version: String,
}

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        version: state.config.version,
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WsParams {
    role: String,
    server_id: String,
    client_id: Option<String>,
    v: String,
}

async fn ws_handler(
    State(state): State<AppState>,
    Query(params): Query<WsParams>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    if !authorized(&headers, &state.config.relay_token) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if params.v != "1" {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let ws = ws
        .max_message_size(MAX_MESSAGE_SIZE)
        .max_frame_size(MAX_MESSAGE_SIZE);
    match params.role.as_str() {
        "server" => ws
            .on_upgrade(move |socket| handle_server(socket, state, params.server_id))
            .into_response(),
        "client" => {
            let Some(client_id) = params.client_id else {
                return StatusCode::BAD_REQUEST.into_response();
            };
            let has_server = {
                let sessions = state.sessions.read().await;
                sessions
                    .get(&params.server_id)
                    .and_then(|session| session.server.as_ref())
                    .is_some()
            };
            if !has_server {
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            }

            ws.on_upgrade(move |socket| handle_client(socket, state, params.server_id, client_id))
                .into_response()
        }
        _ => StatusCode::BAD_REQUEST.into_response(),
    }
}

fn authorized(headers: &HeaderMap, token: &str) -> bool {
    let Some(value) = headers.get(AUTHORIZATION) else {
        return false;
    };
    value
        .to_str()
        .map(|value| value == format!("Bearer {token}"))
        .unwrap_or(false)
}

async fn handle_server(socket: WebSocket, state: AppState, server_id: String) {
    let (peer, data_rx, control_rx) = Peer::new();
    {
        let mut sessions = state.sessions.write().await;
        let session = sessions.entry(server_id.clone()).or_default();
        // Retire under the lock: a predecessor that sees itself non-current is already closing.
        if let Some(old_server) = session.server.replace(peer.clone()) {
            old_server.retire(close_code::NORMAL, "server replaced");
        }
        for client in std::mem::take(&mut session.clients).into_values() {
            client.peer.retire(close_code::AGAIN, "server replaced");
        }
    }
    let (writer, mut reader) = socket.split();
    let mut writer_task = spawn_writer(writer, data_rx, control_rx, true);
    let mut writer_finished = false;
    let mut close_reason = "server closed";
    let mut liveness = tokio::time::interval(HOST_HEARTBEAT_INTERVAL);
    liveness.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_pong = tokio::time::Instant::now();
    loop {
        let message = tokio::select! {
            message = reader.next() => message,
            _ = &mut writer_task => {
                writer_finished = true;
                break;
            }
            _ = liveness.tick() => {
                // A silent host must not keep admitting clients whose frames it will never answer.
                if last_pong.elapsed() >= HOST_HEARTBEAT_TIMEOUT {
                    close_reason = "server heartbeat timed out";
                    break;
                }
                continue;
            }
        };
        let Some(Ok(message)) = message else { break };
        // A retired host socket must never deliver replies into its successor's sessions.
        let Some(client) = server_route(&state, &server_id, &peer, &message).await else {
            break;
        };
        match message {
            Message::Binary(frame) => {
                if let Some(client) = client {
                    forward_to_client(&state, &server_id, &client, frame).await;
                }
            }
            Message::Ping(payload) => {
                let _ = peer.data.try_send(Message::Pong(payload));
            }
            Message::Pong(payload) if payload == HOST_HEARTBEAT => {
                last_pong = tokio::time::Instant::now();
            }
            Message::Close(_) => break,
            _ => {}
        }
    }
    peer.retire(close_code::NORMAL, close_reason);
    let clients = {
        let mut sessions = state.sessions.write().await;
        let current = sessions
            .get(&server_id)
            .and_then(|session| session.server.as_ref())
            .is_some_and(|server| server.same(&peer));
        if current {
            sessions
                .remove(&server_id)
                .map(|session| session.clients)
                .unwrap_or_default()
        } else {
            HashMap::new()
        }
    };
    for client in clients.into_values() {
        client.peer.retire(close_code::AGAIN, "server unavailable");
    }
    finish_writer(writer_task, writer_finished).await;
}

/// `None` when this host socket is no longer current; otherwise the live client a frame targets.
async fn server_route(
    state: &AppState,
    server_id: &str,
    peer: &Peer,
    message: &Message,
) -> Option<Option<ClientPeer>> {
    let sessions = state.sessions.read().await;
    let session = sessions
        .get(server_id)
        .filter(|session| session.server.as_ref().is_some_and(|s| s.same(peer)))?;
    let Message::Binary(frame) = message else {
        return Some(None);
    };
    Some(relay_header(frame).and_then(|header| session.clients.get(&header.client_id).cloned()))
}

/// Never waits on a client: a full or closed queue retires that client instead of dropping bytes mid-stream.
async fn forward_to_client(state: &AppState, server_id: &str, client: &ClientPeer, frame: Vec<u8>) {
    if client.peer.is_retired() {
        return;
    }
    if client.peer.data.try_send(Message::Binary(frame)).is_err() {
        retire_client(
            state,
            server_id,
            client,
            close_code::AGAIN,
            "client queue overflow",
        )
        .await;
    }
}

async fn retire_client(
    state: &AppState,
    server_id: &str,
    client: &ClientPeer,
    code: u16,
    reason: &'static str,
) {
    client.peer.retire(code, reason);
    let mut sessions = state.sessions.write().await;
    if let Some(session) = sessions.get_mut(server_id) {
        if session
            .clients
            .get(&client.client_id)
            .is_some_and(|current| current.peer.same(&client.peer))
        {
            session.clients.remove(&client.client_id);
        }
        if session.server.is_none() && session.clients.is_empty() {
            sessions.remove(server_id);
        }
    }
}

type WsWriter = futures_util::stream::SplitSink<WebSocket, Message>;

fn spawn_writer(
    mut writer: WsWriter,
    mut data: mpsc::Receiver<Message>,
    mut control: mpsc::Receiver<Message>,
    heartbeat: bool,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut heartbeat = heartbeat.then(|| {
            let start = tokio::time::Instant::now() + HOST_HEARTBEAT_INTERVAL;
            let mut interval = tokio::time::interval_at(start, HOST_HEARTBEAT_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            interval
        });
        loop {
            // A pending close preempts queued data and any write stalled on a slow peer.
            // Pings bypass the bounded data queue so a backlog cannot starve liveness probes.
            let message = tokio::select! {
                biased;
                close = control.recv() => Err(close),
                _ = next_heartbeat(&mut heartbeat) => Ok(Some(Message::Ping(HOST_HEARTBEAT.to_vec()))),
                message = data.recv() => Ok(message),
            };
            let message = match message {
                Ok(Some(message)) => message,
                Ok(None) => return,
                Err(close) => return send_close(&mut writer, close).await,
            };
            let close = tokio::select! {
                biased;
                close = control.recv() => Some(close),
                sent = tokio::time::timeout(WRITE_TIMEOUT, writer.send(message)) => {
                    if !matches!(sent, Ok(Ok(()))) {
                        return;
                    }
                    None
                }
            };
            if let Some(close) = close {
                return send_close(&mut writer, close).await;
            }
        }
    })
}

async fn next_heartbeat(heartbeat: &mut Option<tokio::time::Interval>) {
    match heartbeat {
        Some(interval) => {
            interval.tick().await;
        }
        None => std::future::pending().await,
    }
}

async fn send_close(writer: &mut WsWriter, close: Option<Message>) {
    if let Some(close) = close {
        let _ = tokio::time::timeout(WRITE_TIMEOUT, writer.send(close)).await;
    }
}

/// Gives a queued close a bounded chance to reach the peer before the socket is dropped.
async fn finish_writer(mut writer_task: JoinHandle<()>, finished: bool) {
    if !finished
        && tokio::time::timeout(WRITE_TIMEOUT * 2, &mut writer_task)
            .await
            .is_err()
    {
        writer_task.abort();
    }
}

fn close_message(code: u16, reason: &'static str) -> Message {
    Message::Close(Some(CloseFrame {
        code,
        reason: reason.into(),
    }))
}

async fn handle_client(socket: WebSocket, state: AppState, server_id: String, client_id: String) {
    let (peer, data_rx, control_rx) = Peer::new();
    let (client, old_client) = {
        let mut sessions = state.sessions.write().await;
        let Some(session) = sessions.get_mut(&server_id) else {
            return;
        };
        let Some(server) = session.server.clone() else {
            return;
        };
        let client = ClientPeer {
            client_id: client_id.clone(),
            peer: peer.clone(),
            server,
            connections: Arc::default(),
        };
        let old_client = session.clients.insert(client_id.clone(), client.clone());
        if let Some(old_client) = &old_client {
            old_client
                .peer
                .retire(close_code::NORMAL, "client replaced");
        }
        (client, old_client)
    };
    if let Some(old_client) = old_client {
        // The successor's first frame must not overtake its predecessor's lifecycle close.
        notify_client_gone(&old_client).await;
    }
    let (writer, mut reader) = socket.split();
    let mut writer_task = spawn_writer(writer, data_rx, control_rx, false);
    let mut writer_finished = false;
    loop {
        let message = tokio::select! {
            message = reader.next() => message,
            _ = &mut writer_task => {
                writer_finished = true;
                break;
            }
        };
        let Some(Ok(message)) = message else { break };
        match message {
            Message::Binary(frame) => {
                // Routing metadata is bound to the authenticated socket, not trusted from the frame.
                let Some(header) = relay_header(&frame) else {
                    break;
                };
                if header.client_id != client_id
                    || !forward_to_server(&state, &server_id, &client, &header, frame).await
                {
                    break;
                }
            }
            Message::Ping(payload) => {
                let _ = peer.data.try_send(Message::Pong(payload));
            }
            Message::Close(_) => break,
            _ => {}
        }
    }
    retire_client(
        &state,
        &server_id,
        &client,
        close_code::NORMAL,
        "client closed",
    )
    .await;
    notify_client_gone(&client).await;
    finish_writer(writer_task, writer_finished).await;
}

async fn forward_to_server(
    state: &AppState,
    server_id: &str,
    client: &ClientPeer,
    header: &RelayHeader,
    frame: Vec<u8>,
) -> bool {
    // Held across the send so this socket's lifecycle close is always ordered after its data.
    let mut connections = client.connections.lock().await;
    if connections.retired || client.peer.is_retired() {
        return false;
    }
    let current = {
        let sessions = state.sessions.read().await;
        sessions.get(server_id).is_some_and(|session| {
            session
                .clients
                .get(&client.client_id)
                .is_some_and(|current| current.peer.same(&client.peer))
                && session
                    .server
                    .as_ref()
                    .is_some_and(|server| server.same(&client.server))
        })
    };
    if !current {
        return false;
    }
    if let Some(connection_id) = header.adapter_connection_id() {
        if header.is_close() {
            connections.open.remove(connection_id);
        } else {
            connections.open.insert(connection_id.to_owned());
        }
    }
    let sent = tokio::time::timeout(
        WRITE_TIMEOUT,
        client.server.data.send(Message::Binary(frame)),
    )
    .await;
    matches!(sent, Ok(Ok(())))
}

/// Closes the adapter connections a departed socket opened, once, on the host that admitted it.
async fn notify_client_gone(client: &ClientPeer) {
    let mut connections = client.connections.lock().await;
    if std::mem::replace(&mut connections.retired, true) {
        return;
    }
    let open = std::mem::take(&mut connections.open);
    if client.server.is_retired() {
        return;
    }
    for connection_id in open {
        let Ok(frame) = lifecycle_close_frame(&client.client_id, &connection_id) else {
            continue;
        };
        let sent = tokio::time::timeout(
            WRITE_TIMEOUT,
            client.server.data.send(Message::Binary(frame)),
        )
        .await;
        if !matches!(sent, Ok(Ok(()))) {
            break;
        }
    }
}

fn lifecycle_close_frame(client_id: &str, connection_id: &str) -> Result<Vec<u8>> {
    let mut payload = close_code::AWAY.to_be_bytes().to_vec();
    payload.extend_from_slice(RELAY_CLIENT_DISCONNECTED.as_bytes());
    adapter::encode_adapter_frame(&adapter::AdapterFrame {
        header: adapter::AdapterFrameHeader {
            client_id: client_id.to_owned(),
            connection_id: connection_id.to_owned(),
            direction: adapter::AdapterDirection::ClientToServer,
            opcode: adapter::AdapterOpcode::Close,
            close_code: Some(close_code::AWAY),
            close_reason: Some(RELAY_CLIENT_DISCONNECTED.to_owned()),
        },
        payload,
    })
}

/// Routing metadata only; payload bytes stay opaque and legacy frames need just `clientId`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RelayHeader {
    client_id: String,
    connection_id: Option<Value>,
    direction: Option<Value>,
    opcode: Option<Value>,
}

impl RelayHeader {
    fn adapter_connection_id(&self) -> Option<&str> {
        let to_server = self.direction.as_ref().and_then(Value::as_str) == Some("client_to_server");
        self.connection_id
            .as_ref()
            .and_then(Value::as_str)
            .filter(|_| to_server)
    }

    fn is_close(&self) -> bool {
        self.opcode.as_ref().and_then(Value::as_str) == Some("close")
    }
}

fn relay_header(frame: &[u8]) -> Option<RelayHeader> {
    let header_len = u32::from_be_bytes(frame.get(0..4)?.try_into().ok()?) as usize;
    let header_end = 4usize.checked_add(header_len)?;
    serde_json::from_slice(frame.get(4..header_end)?).ok()
}

pub mod adapter {
    use std::{
        collections::{HashMap, HashSet},
        fmt::Write as _,
        net::SocketAddr,
        sync::{
            atomic::{AtomicU64, Ordering},
            Arc,
        },
        time::Duration,
    };

    use anyhow::{anyhow, bail, Context, Result};
    use axum::{
        extract::{
            rejection::PathRejection,
            ws::{
                rejection::WebSocketUpgradeRejection, CloseFrame as AxumCloseFrame,
                Message as AxumMessage, WebSocket, WebSocketUpgrade,
            },
            Path, State,
        },
        http::StatusCode,
        response::{IntoResponse, Response},
        routing::get,
        Router,
    };
    use futures_util::{SinkExt, StreamExt};
    use rustls::crypto::{ring, CryptoProvider};
    use serde::{Deserialize, Serialize};
    use tokio::{net::TcpListener, sync::mpsc, task::JoinHandle};
    use tokio_tungstenite::{
        connect_async,
        tungstenite::{
            client::IntoClientRequest,
            http::{header::AUTHORIZATION as WS_AUTHORIZATION, HeaderValue},
            protocol::{frame::coding::CloseCode, CloseFrame as TungsteniteCloseFrame},
            Message as TungsteniteMessage,
        },
        MaybeTlsStream, WebSocketStream,
    };

    type RelayWebSocket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
    const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
    const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(15);
    const MAX_RETRY_DELAY: Duration = Duration::from_secs(15);
    const HEARTBEAT: &[u8] = b"orca-relay";
    const RETIRED_TTL: Duration = Duration::from_secs(60);
    const MAX_RETIRED_CONNECTIONS: usize = 4096;

    fn retire_connection(
        retired: &mut HashMap<(String, String), tokio::time::Instant>,
        key: (String, String),
    ) {
        if retired.len() >= MAX_RETIRED_CONNECTIONS {
            if let Some(oldest) = retired
                .iter()
                .min_by_key(|(_, at)| **at)
                .map(|(key, _)| key.clone())
            {
                retired.remove(&oldest);
            }
        }
        retired.insert(key, tokio::time::Instant::now());
    }

    struct RuntimeConnection {
        tx: mpsc::Sender<TungsteniteMessage>,
        task: JoinHandle<()>,
    }
    impl Drop for RuntimeConnection {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum AdapterDirection {
        ClientToServer,
        ServerToClient,
    }

    #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum AdapterOpcode {
        Text,
        Binary,
        Close,
    }

    #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct AdapterFrameHeader {
        pub client_id: String,
        pub connection_id: String,
        pub direction: AdapterDirection,
        pub opcode: AdapterOpcode,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub close_code: Option<u16>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub close_reason: Option<String>,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct AdapterFrame {
        pub header: AdapterFrameHeader,
        pub payload: Vec<u8>,
    }

    #[derive(Clone, Debug)]
    pub struct ProxyConfig {
        pub bind_addr: SocketAddr,
        pub relay_url: String,
        pub server_id: String,
        pub relay_token: String,
        pub client_id: String,
    }

    #[derive(Clone, Debug)]
    pub struct BridgeConfig {
        pub relay_url: String,
        pub local_runtime_url: String,
        pub server_id: String,
        pub relay_token: String,
    }

    pub struct ProxyHandle {
        local_addr: SocketAddr,
        task: JoinHandle<()>,
    }

    impl ProxyHandle {
        pub fn local_addr(&self) -> SocketAddr {
            self.local_addr
        }
    }

    impl Drop for ProxyHandle {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    pub struct BridgeHandle {
        task: JoinHandle<Result<()>>,
    }
    impl BridgeHandle {
        pub async fn wait(&mut self) -> Result<()> {
            (&mut self.task).await.context("bridge task failed")?
        }
    }

    impl Drop for BridgeHandle {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    pub fn encode_adapter_frame(frame: &AdapterFrame) -> Result<Vec<u8>> {
        let header =
            serde_json::to_vec(&frame.header).context("failed to encode adapter header")?;
        let header_len = u32::try_from(header.len()).context("adapter header too large")?;
        let mut encoded = Vec::with_capacity(4 + header.len() + frame.payload.len());
        encoded.extend_from_slice(&header_len.to_be_bytes());
        encoded.extend_from_slice(&header);
        encoded.extend_from_slice(&frame.payload);
        Ok(encoded)
    }

    pub fn decode_adapter_frame(frame: &[u8]) -> Result<AdapterFrame> {
        if frame.len() < 4 {
            bail!("adapter frame missing header length");
        }

        let header_len =
            u32::from_be_bytes(frame[0..4].try_into().expect("slice has 4 bytes")) as usize;
        let header_end = 4usize
            .checked_add(header_len)
            .ok_or_else(|| anyhow!("adapter header length overflow"))?;
        let header = frame
            .get(4..header_end)
            .ok_or_else(|| anyhow!("adapter frame shorter than declared header length"))?;

        Ok(AdapterFrame {
            header: serde_json::from_slice(header).context("failed to decode adapter header")?,
            payload: frame[header_end..].to_vec(),
        })
    }

    pub async fn run_proxy(config: ProxyConfig) -> Result<ProxyHandle> {
        run_proxy_with_server_ids(config, Vec::new()).await
    }

    /// Runs the local proxy with `config.server_id` fixed as the target for `/` and `/ws`.
    /// Each explicitly listed ID, plus the default when it is route-safe, may also be selected
    /// per connection via `/r/:server_id` or `/r/:server_id/ws`; any other ID is rejected with
    /// 404 before upgrade.
    pub async fn run_proxy_with_server_ids(
        config: ProxyConfig,
        server_ids: Vec<String>,
    ) -> Result<ProxyHandle> {
        let mut allowed_server_ids = HashSet::with_capacity(server_ids.len() + 1);
        for server_id in server_ids {
            let server_id = server_id.trim();
            if server_id.is_empty() {
                bail!("additional server ids must not be blank");
            }
            if !route_safe_server_id(server_id) {
                bail!("additional server ids must be usable as a single route segment");
            }
            allowed_server_ids.insert(server_id.to_string());
        }
        // The default stays opaque for `/` and `/ws`; it is only named-routable when route-safe.
        if route_safe_server_id(&config.server_id) {
            allowed_server_ids.insert(config.server_id.clone());
        }
        install_tls_provider();
        let listener = TcpListener::bind(config.bind_addr)
            .await
            .context("failed to bind local proxy listener")?;
        let local_addr = listener
            .local_addr()
            .context("failed to read local proxy address")?;
        let state = ProxyState {
            relay_url: config.relay_url,
            server_id: config.server_id,
            relay_token: config.relay_token,
            client_id: config.client_id,
            instance_id: format!(
                "{:x}-{:x}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_nanos(),
                std::process::id()
            ),
            next_connection_id: Arc::new(AtomicU64::new(1)),
            allowed_server_ids: Arc::new(allowed_server_ids),
        };
        let app = Router::new()
            .route("/", get(proxy_ws_handler))
            .route("/ws", get(proxy_ws_handler))
            .route("/r/:server_id", get(proxy_routed_ws_handler))
            .route("/r/:server_id/ws", get(proxy_routed_ws_handler))
            .with_state(state);
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        Ok(ProxyHandle { local_addr, task })
    }

    pub async fn run_bridge(config: BridgeConfig) -> Result<BridgeHandle> {
        install_tls_provider();
        let relay_url = relay_url(
            &config.relay_url,
            &[
                ("role", "server"),
                ("serverId", &config.server_id),
                ("v", "1"),
            ],
        );
        let relay = connect_with_bearer(&relay_url, &config.relay_token)
            .await
            .context("failed to connect bridge to relay")?;
        let task = tokio::spawn(async move {
            let mut relay = relay;
            loop {
                if matches!(
                    bridge_loop(&config, relay).await,
                    Ok(BridgeExit::Superseded)
                ) {
                    eprintln!("bridge superseded by another host connection; stopped");
                    return Ok(());
                }
                eprintln!("bridge connection lost; reconnecting");
                let mut delay = Duration::from_secs(1);
                relay = loop {
                    tokio::time::sleep(delay).await;
                    match connect_with_bearer(&relay_url, &config.relay_token).await {
                        Ok(relay) => {
                            eprintln!("bridge reconnected");
                            break relay;
                        }
                        Err(_) => {
                            delay = (delay * 2).min(MAX_RETRY_DELAY);
                        }
                    }
                };
            }
        });
        tokio::task::yield_now().await;
        Ok(BridgeHandle { task })
    }

    fn route_safe_server_id(server_id: &str) -> bool {
        !server_id.is_empty()
            && server_id != "."
            && server_id != ".."
            && !server_id
                .chars()
                .any(|ch| ch == '/' || ch == '\\' || ch.is_control())
    }

    #[derive(Clone)]
    struct ProxyState {
        relay_url: String,
        server_id: String,
        relay_token: String,
        client_id: String,
        instance_id: String,
        next_connection_id: Arc<AtomicU64>,
        allowed_server_ids: Arc<HashSet<String>>,
    }

    impl ProxyState {
        fn next_connection_id(&self) -> String {
            let id = self.next_connection_id.fetch_add(1, Ordering::Relaxed);
            format!("{}-{}-{id}", self.client_id, self.instance_id)
        }
    }

    async fn proxy_ws_handler(State(state): State<ProxyState>, ws: WebSocketUpgrade) -> Response {
        let server_id = state.server_id.clone();
        upgrade_proxy_ws(ws, state, server_id)
    }

    // The selected ID is resolved per request and never written back into shared state.
    async fn proxy_routed_ws_handler(
        State(state): State<ProxyState>,
        server_id: Result<Path<String>, PathRejection>,
        ws: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
    ) -> Response {
        let Some(server_id) = server_id
            .ok()
            .map(|Path(server_id)| server_id)
            .filter(|server_id| state.allowed_server_ids.contains(server_id))
        else {
            return StatusCode::NOT_FOUND.into_response();
        };
        match ws {
            Ok(ws) => upgrade_proxy_ws(ws, state, server_id),
            Err(rejection) => rejection.into_response(),
        }
    }

    fn upgrade_proxy_ws(ws: WebSocketUpgrade, state: ProxyState, server_id: String) -> Response {
        ws.max_message_size(super::MAX_MESSAGE_SIZE)
            .max_frame_size(super::MAX_MESSAGE_SIZE)
            .on_upgrade(move |socket| async move {
                let _ = handle_proxy_ws(socket, state, server_id).await;
            })
    }

    async fn handle_proxy_ws(
        socket: WebSocket,
        state: ProxyState,
        server_id: String,
    ) -> Result<()> {
        let connection_id = state.next_connection_id();
        let client_id = connection_id.clone();
        let relay_url = relay_url(
            &state.relay_url,
            &[
                ("role", "client"),
                ("serverId", &server_id),
                ("clientId", &client_id),
                ("v", "1"),
            ],
        );
        let relay = match connect_with_bearer(&relay_url, &state.relay_token).await {
            Ok(relay) => relay,
            Err(_) => {
                let mut socket = socket;
                let _ = tokio::time::timeout(
                    super::WRITE_TIMEOUT,
                    socket.send(AxumMessage::Close(Some(AxumCloseFrame {
                        code: 1013,
                        reason: "relay unavailable".into(),
                    }))),
                )
                .await;
                return Ok(());
            }
        };
        let (mut local_tx, mut local_rx) = socket.split();
        let (mut relay_tx, mut relay_rx) = relay.split();
        let mut heartbeat = tokio::time::interval(HEARTBEAT_INTERVAL);
        heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        heartbeat.tick().await;
        let mut last_pong = tokio::time::Instant::now();
        let result: Result<()> = async {
            loop {
                tokio::select! {
                    _ = heartbeat.tick() => {
                        if last_pong.elapsed() >= HEARTBEAT_TIMEOUT { bail!("proxy relay heartbeat timed out"); }
                        tokio::time::timeout(super::WRITE_TIMEOUT, relay_tx.send(TungsteniteMessage::Ping(HEARTBEAT.to_vec()))).await??;
                    }
                    message = local_rx.next() => {
                        let Some(message) = message else { break };
                        let message = message.context("local websocket read failed")?;
                        if let AxumMessage::Ping(payload) = message {
                            tokio::time::timeout(super::WRITE_TIMEOUT, local_tx.send(AxumMessage::Pong(payload))).await??;
                            continue;
                        }
                        if let Some((frame, closing)) = adapter_frame_from_axum(message, &client_id, &connection_id) {
                            tokio::time::timeout(super::WRITE_TIMEOUT, relay_tx.send(TungsteniteMessage::Binary(encode_adapter_frame(&frame)?))).await??;
                            if closing { break; }
                        }
                    }
                    message = relay_rx.next() => {
                        let Some(message) = message else { break };
                        match message.context("relay websocket read failed")? {
                            TungsteniteMessage::Binary(bytes) => {
                                let frame = decode_adapter_frame(&bytes)?;
                                if frame.header.connection_id != connection_id || frame.header.direction != AdapterDirection::ServerToClient { continue; }
                                let closing = frame.header.opcode == AdapterOpcode::Close;
                                tokio::time::timeout(super::WRITE_TIMEOUT, local_tx.send(axum_message_from_adapter_frame(frame)?)).await??;
                                if closing { break; }
                            }
                            TungsteniteMessage::Ping(payload) => {
                                tokio::time::timeout(super::WRITE_TIMEOUT, relay_tx.send(TungsteniteMessage::Pong(payload))).await??;
                            }
                            TungsteniteMessage::Pong(payload) if payload == HEARTBEAT => { last_pong = tokio::time::Instant::now(); }
                            TungsteniteMessage::Close(_) => break,
                            _ => {}
                        }
                    }
                }
            }
            Ok(())
        }.await;
        // Abrupt phone disconnects must retire the corresponding local runtime too.
        let mut close = close_frame(&client_id, &connection_id, 1001, "client disconnected");
        close.header.direction = AdapterDirection::ClientToServer;
        if let Ok(bytes) = encode_adapter_frame(&close) {
            let _ = tokio::time::timeout(
                super::WRITE_TIMEOUT,
                relay_tx.send(TungsteniteMessage::Binary(bytes)),
            )
            .await;
        }
        let _ = tokio::time::timeout(
            super::WRITE_TIMEOUT,
            local_tx.send(AxumMessage::Close(None)),
        )
        .await;
        let _ = tokio::time::timeout(super::WRITE_TIMEOUT, relay_tx.close()).await;
        result
    }

    enum BridgeExit {
        Disconnected,
        Superseded,
    }

    async fn bridge_loop(config: &BridgeConfig, relay: RelayWebSocket) -> Result<BridgeExit> {
        let (mut writer, mut reader) = relay.split();
        let (relay_tx, mut relay_rx) = mpsc::channel::<AdapterFrame>(super::QUEUE_CAPACITY);
        let mut runtimes = HashMap::<(String, String), RuntimeConnection>::new();
        let mut retired = HashMap::new();
        let mut heartbeat = tokio::time::interval(HEARTBEAT_INTERVAL);
        heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        heartbeat.tick().await;
        let mut last_pong = tokio::time::Instant::now();
        loop {
            tokio::select! {
                _ = heartbeat.tick() => {
                    if last_pong.elapsed() >= HEARTBEAT_TIMEOUT { bail!("relay heartbeat timed out"); }
                    tokio::time::timeout(super::WRITE_TIMEOUT, writer.send(TungsteniteMessage::Ping(HEARTBEAT.to_vec()))).await??;
                    let finished: Vec<_> = runtimes.iter().filter(|(_, runtime)| runtime.task.is_finished()).map(|(key, _)| key.clone()).collect();
                    for key in finished {
                        runtimes.remove(&key);
                        // The task's terminal close is already queued after its replies.
                        retire_connection(&mut retired, key);
                    }
                    retired.retain(|_, at| at.elapsed() < RETIRED_TTL);
                }
                frame = relay_rx.recv() => {
                    if let Some(frame) = frame {
                        if frame.header.opcode == AdapterOpcode::Close {
                            let key = (frame.header.client_id.clone(), frame.header.connection_id.clone());
                            runtimes.remove(&key);
                            retire_connection(&mut retired, key);
                        }
                        tokio::time::timeout(super::WRITE_TIMEOUT, writer.send(TungsteniteMessage::Binary(encode_adapter_frame(&frame)?))).await??;
                    }
                }
                message = reader.next() => {
                    let Some(message) = message else { return Ok(BridgeExit::Disconnected) };
                    match message.context("bridge relay read failed")? {
                        TungsteniteMessage::Binary(bytes) => {
                            // Malformed adapter metadata must not take other clients offline.
                            let Ok(frame) = decode_adapter_frame(&bytes) else { continue };
                            if frame.header.direction != AdapterDirection::ClientToServer { continue; }
                            let key = (frame.header.client_id.clone(), frame.header.connection_id.clone());
                            if frame.header.opcode == AdapterOpcode::Close {
                                if frame.header.close_reason.as_deref() == Some(super::RELAY_CLIENT_DISCONNECTED) {
                                    runtimes.remove(&key);
                                    retired.remove(&key);
                                    continue;
                                }
                                retire_connection(&mut retired, key.clone());
                                if let Some(runtime) = runtimes.get(&key) {
                                    if !tungstenite_message_from_adapter_frame(frame).ok().is_some_and(|message| runtime.tx.try_send(message).is_ok()) {
                                        runtimes.remove(&key);
                                    }
                                }
                                continue;
                            }
                            if retired.contains_key(&key) { continue; }
                            let message = match tungstenite_message_from_adapter_frame(frame) {
                                Ok(message) => message,
                                Err(_) => {
                                    runtimes.remove(&key);
                                    retire_connection(&mut retired, key.clone());
                                    let close = close_frame(&key.0, &key.1, 1007, "invalid adapter payload");
                                    tokio::time::timeout(super::WRITE_TIMEOUT, writer.send(TungsteniteMessage::Binary(encode_adapter_frame(&close)?))).await??;
                                    continue;
                                }
                            };
                            if !runtimes.contains_key(&key) {
                                let runtime = open_runtime_connection(&config.local_runtime_url, key.0.clone(), key.1.clone(), relay_tx.clone());
                                runtimes.insert(key.clone(), runtime);
                            }
                            let runtime = &runtimes[&key];
                            // Never wait for one runtime while its reply queue waits on this loop.
                            if runtime.tx.try_send(message).is_err() {
                                runtimes.remove(&key);
                                retire_connection(&mut retired, key.clone());
                                let close = close_frame(&key.0, &key.1, 1013, "runtime queue unavailable");
                                tokio::time::timeout(super::WRITE_TIMEOUT, writer.send(TungsteniteMessage::Binary(encode_adapter_frame(&close)?))).await??;
                            }
                        }
                        TungsteniteMessage::Ping(payload) => {
                            tokio::time::timeout(super::WRITE_TIMEOUT, writer.send(TungsteniteMessage::Pong(payload))).await??;
                        }
                        TungsteniteMessage::Pong(payload) if payload == HEARTBEAT => { last_pong = tokio::time::Instant::now(); }
                        // The Rust relay and Cloudflare Worker use different replacement reasons.
                        TungsteniteMessage::Close(Some(close)) if close.reason == "server replaced" || close.reason == "bridge replaced" => { return Ok(BridgeExit::Superseded); }
                        TungsteniteMessage::Close(_) => { return Ok(BridgeExit::Disconnected); }
                        _ => {}
                    }
                }
            }
        }
    }

    fn close_frame(client_id: &str, connection_id: &str, code: u16, reason: &str) -> AdapterFrame {
        AdapterFrame {
            header: AdapterFrameHeader {
                client_id: client_id.to_owned(),
                connection_id: connection_id.to_owned(),
                direction: AdapterDirection::ServerToClient,
                opcode: AdapterOpcode::Close,
                close_code: Some(code),
                close_reason: Some(reason.to_owned()),
            },
            payload: close_payload(code, reason),
        }
    }

    fn open_runtime_connection(
        local_runtime_url: &str,
        client_id: String,
        connection_id: String,
        relay_tx: mpsc::Sender<AdapterFrame>,
    ) -> RuntimeConnection {
        let local_runtime_url = local_runtime_url.to_owned();
        let (tx, mut rx) = mpsc::channel::<TungsteniteMessage>(super::QUEUE_CAPACITY);
        let task = tokio::spawn(async move {
            // A stalled local handshake must not stop relay heartbeat or other clients.
            let runtime = match tokio::time::timeout(
                CONNECT_TIMEOUT,
                connect_async(&local_runtime_url),
            )
            .await
            {
                Ok(Ok((runtime, _))) => runtime,
                _ => {
                    let close = close_frame(
                        &client_id,
                        &connection_id,
                        1013,
                        "local runtime unavailable",
                    );
                    let _ = relay_tx.send(close).await;
                    return;
                }
            };
            let (mut writer, mut reader) = runtime.split();
            let mut forwarded_close = false;
            let result: Result<()> = async {
                loop {
                    tokio::select! {
                        message = rx.recv() => {
                            let Some(message) = message else { break };
                            let closing = matches!(message, TungsteniteMessage::Close(_));
                            tokio::time::timeout(super::WRITE_TIMEOUT, writer.send(message)).await??;
                            if closing { break; }
                        }
                        message = reader.next() => {
                            let Some(message) = message else { break };
                            let message = message?;
                            if let TungsteniteMessage::Ping(payload) = message {
                                tokio::time::timeout(super::WRITE_TIMEOUT, writer.send(TungsteniteMessage::Pong(payload))).await??;
                                continue;
                            }
                            if let Some(frame) = adapter_frame_from_tungstenite(message, &client_id, &connection_id, AdapterDirection::ServerToClient) {
                                let closing = frame.header.opcode == AdapterOpcode::Close;
                                tokio::time::timeout(super::WRITE_TIMEOUT, relay_tx.send(frame)).await??;
                                if closing { forwarded_close = true; return Ok(()); }
                            }
                        }
                    }
                }
                Ok(())
            }.await;
            if forwarded_close {
                return;
            }
            let (code, reason) = if result.is_ok() {
                (1001, "runtime disconnected")
            } else {
                (1011, "runtime connection failed")
            };
            // This per-runtime task may wait for queue space. The bridge still drains
            // replies; losing its uplink drops RuntimeConnection and aborts this task.
            // Keeping the terminal close in the same FIFO avoids reply/close reordering.
            let _ = relay_tx
                .send(close_frame(&client_id, &connection_id, code, reason))
                .await;
        });
        RuntimeConnection { tx, task }
    }

    fn install_tls_provider() {
        if CryptoProvider::get_default().is_none() {
            let _ = ring::default_provider().install_default();
        }
    }

    async fn connect_with_bearer(url: &str, token: &str) -> Result<RelayWebSocket> {
        let mut request = url
            .into_client_request()
            .context("invalid relay websocket URL")?;
        let header_value = HeaderValue::from_str(&format!("Bearer {token}"))
            .context("invalid relay authorization header")?;
        request.headers_mut().insert(WS_AUTHORIZATION, header_value);
        let (socket, _) = tokio::time::timeout(CONNECT_TIMEOUT, connect_async(request))
            .await
            .context("relay connection timed out")?
            .context("relay websocket connection failed")?;
        Ok(socket)
    }

    fn adapter_frame_from_axum(
        message: AxumMessage,
        client_id: &str,
        connection_id: &str,
    ) -> Option<(AdapterFrame, bool)> {
        let (opcode, payload, close_code, close_reason, closes_connection) = match message {
            AxumMessage::Text(text) => (AdapterOpcode::Text, text.into_bytes(), None, None, false),
            AxumMessage::Binary(bytes) => (AdapterOpcode::Binary, bytes, None, None, false),
            AxumMessage::Close(close) => {
                let (close_code, close_reason, payload) = axum_close_parts(close);
                (
                    AdapterOpcode::Close,
                    payload,
                    close_code,
                    close_reason,
                    true,
                )
            }
            AxumMessage::Ping(_) | AxumMessage::Pong(_) => return None,
        };

        Some((
            AdapterFrame {
                header: AdapterFrameHeader {
                    client_id: client_id.to_string(),
                    connection_id: connection_id.to_string(),
                    direction: AdapterDirection::ClientToServer,
                    opcode,
                    close_code,
                    close_reason,
                },
                payload,
            },
            closes_connection,
        ))
    }

    fn adapter_frame_from_tungstenite(
        message: TungsteniteMessage,
        client_id: &str,
        connection_id: &str,
        direction: AdapterDirection,
    ) -> Option<AdapterFrame> {
        let (opcode, payload, close_code, close_reason) = match message {
            TungsteniteMessage::Text(text) => (AdapterOpcode::Text, text.into_bytes(), None, None),
            TungsteniteMessage::Binary(bytes) => (AdapterOpcode::Binary, bytes, None, None),
            TungsteniteMessage::Close(close) => {
                let (close_code, close_reason, payload) = tungstenite_close_parts(close);
                (AdapterOpcode::Close, payload, close_code, close_reason)
            }
            _ => return None,
        };

        Some(AdapterFrame {
            header: AdapterFrameHeader {
                client_id: client_id.to_string(),
                connection_id: connection_id.to_string(),
                direction,
                opcode,
                close_code,
                close_reason,
            },
            payload,
        })
    }

    fn axum_message_from_adapter_frame(frame: AdapterFrame) -> Result<AxumMessage> {
        match frame.header.opcode {
            AdapterOpcode::Text => Ok(AxumMessage::Text(
                String::from_utf8(frame.payload).context("adapter text payload was not UTF-8")?,
            )),
            AdapterOpcode::Binary => Ok(AxumMessage::Binary(frame.payload)),
            AdapterOpcode::Close => Ok(axum_close_message(&frame.header)),
        }
    }

    fn tungstenite_message_from_adapter_frame(frame: AdapterFrame) -> Result<TungsteniteMessage> {
        match frame.header.opcode {
            AdapterOpcode::Text => Ok(TungsteniteMessage::Text(
                String::from_utf8(frame.payload).context("adapter text payload was not UTF-8")?,
            )),
            AdapterOpcode::Binary => Ok(TungsteniteMessage::Binary(frame.payload)),
            AdapterOpcode::Close => Ok(tungstenite_close_message(&frame.header)),
        }
    }

    fn axum_close_message(header: &AdapterFrameHeader) -> AxumMessage {
        AxumMessage::Close(header.close_code.map(|code| AxumCloseFrame {
            code,
            reason: header.close_reason.clone().unwrap_or_default().into(),
        }))
    }

    fn tungstenite_close_message(header: &AdapterFrameHeader) -> TungsteniteMessage {
        TungsteniteMessage::Close(header.close_code.map(|code| TungsteniteCloseFrame {
            code: CloseCode::from(code),
            reason: header.close_reason.clone().unwrap_or_default().into(),
        }))
    }

    fn axum_close_parts(
        close: Option<AxumCloseFrame<'static>>,
    ) -> (Option<u16>, Option<String>, Vec<u8>) {
        match close {
            Some(close) => {
                let reason = close.reason.into_owned();
                let payload = close_payload(close.code, &reason);
                (Some(close.code), Some(reason), payload)
            }
            None => (None, None, Vec::new()),
        }
    }

    fn tungstenite_close_parts(
        close: Option<TungsteniteCloseFrame<'static>>,
    ) -> (Option<u16>, Option<String>, Vec<u8>) {
        match close {
            Some(close) => {
                let code = u16::from(close.code);
                let reason = close.reason.into_owned();
                let payload = close_payload(code, &reason);
                (Some(code), Some(reason), payload)
            }
            None => (None, None, Vec::new()),
        }
    }

    fn close_payload(code: u16, reason: &str) -> Vec<u8> {
        let mut payload = Vec::with_capacity(2 + reason.len());
        payload.extend_from_slice(&code.to_be_bytes());
        payload.extend_from_slice(reason.as_bytes());
        payload
    }

    fn relay_url(base: &str, params: &[(&str, &str)]) -> String {
        let mut url = String::from(base);
        url.push(if base.contains('?') { '&' } else { '?' });
        for (index, (key, value)) in params.iter().enumerate() {
            if index > 0 {
                url.push('&');
            }
            url.push_str(key);
            url.push('=');
            push_query_component(&mut url, value);
        }
        url
    }

    fn push_query_component(url: &mut String, value: &str) {
        for byte in value.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                    url.push(byte as char);
                }
                _ => {
                    let _ = write!(url, "%{byte:02X}");
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::route_safe_server_id;

        #[test]
        fn route_safe_server_id_rejects_only_unrepresentable_segments() {
            for id in ["", ".", "..", "a/b", "a\\b", "a\nb", "a\u{7f}b"] {
                assert!(!route_safe_server_id(id));
            }
            for id in ["ws", "alpha", "two words", "\u{670d}\u{52a1}", "...", "%2F"] {
                assert!(route_safe_server_id(id));
            }
        }
    }
}
