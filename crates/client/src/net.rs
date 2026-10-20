//! Networking: connect to the relay, send/receive encrypted envelopes.
//!
//! The client encrypts each message with the recipient's public key using
//! the sealed-box construction, wraps it in an `Envelope`, and hands it to
//! the server. Incoming envelopes are decrypted with our private key and
//! stored locally.
//!
//! The **public key is the identity**: envelopes are routed by key, and
//! messages are stored by key. Usernames are resolved to keys on the way out
//! (when sending) and back to usernames only for display (when receiving).
//!
//! A chat session holds a single persistent connection. A background reader
//! task owns the socket and handles both incoming deliveries and outgoing
//! sends (driven by messages on a channel from the main loop).

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use crypto_box::PublicKey;
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use tracing::warn;

use echat_common::crypto;
use echat_common::keys::Identity;
use echat_common::protocol::{self, Envelope, Message, PROTOCOL_VERSION};

use crate::db::{key_hex, Store};

/// A connected WebSocket stream.
pub type Conn = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Commands the main loop sends to the reader task.
pub enum ClientMsg {
    /// Send a message to a recipient (by username; resolved to a key).
    Send { recipient: String, body: String },
}

/// Connect to the relay, perform the version handshake, and register.
pub async fn connect(server: &str, id: &Identity) -> Result<Conn> {
    let (ws, _) = tokio_tungstenite::connect_async(server)
        .await
        .with_context(|| format!("failed to connect to {server}"))?;
    let (mut sink, mut stream) = ws.split();

    // Version handshake.
    handshake(&mut sink, &mut stream).await?;

    // Register.
    let reg = Message::Register {
        username: id.username.clone(),
        public_key: id.public_key.to_bytes(),
    };
    sink.send(ws_text(reg)).await.context("send register")?;

    // Reunite the split halves so the caller can use the full stream.
    sink.reunite(stream).context("reunite websocket")
}

/// Perform the version handshake on an already-connected socket.
async fn handshake(
    sink: &mut futures_util::stream::SplitSink<Conn, WsMessage>,
    stream: &mut futures_util::stream::SplitStream<Conn>,
) -> Result<()> {
    sink.send(ws_text(Message::Hello {
        version: PROTOCOL_VERSION,
    }))
    .await
    .context("send hello")?;
    match stream.next().await {
        Some(Ok(WsMessage::Text(text))) => match protocol::from_wire(&text)? {
            Message::HelloOk => Ok(()),
            Message::HelloError { reason } => anyhow::bail!("handshake rejected: {reason}"),
            _ => anyhow::bail!("unexpected handshake response"),
        },
        _ => anyhow::bail!("connection closed during handshake"),
    }
}

/// Register with the relay (one-shot, used by the `register` command).
pub async fn register(server: &str, id: &Identity) -> Result<()> {
    let conn = connect(server, id).await?;
    // Wait for the RegisterOk / RegisterError response.
    let mut stream = conn.split().1;
    while let Some(Ok(msg)) = stream.next().await {
        if let WsMessage::Text(text) = msg {
            match protocol::from_wire(&text)? {
                Message::RegisterOk => return Ok(()),
                Message::RegisterError { reason } => anyhow::bail!("registration failed: {reason}"),
                _ => {}
            }
        }
    }
    anyhow::bail!("connection closed before registration response")
}

/// Look up a user's public key on the relay.
pub async fn lookup(server: &str, username: &str) -> Result<Option<[u8; 32]>> {
    let (ws, _) = tokio_tungstenite::connect_async(server)
        .await
        .with_context(|| format!("failed to connect to {server}"))?;
    let (mut sink, mut stream) = ws.split();
    handshake(&mut sink, &mut stream).await?;
    sink.send(ws_text(Message::Lookup {
        username: username.to_string(),
    }))
    .await
    .context("send lookup")?;
    while let Some(Ok(msg)) = stream.next().await {
        if let WsMessage::Text(text) = msg {
            if let Message::LookupResult { public_key, .. } = protocol::from_wire(&text)? {
                return Ok(public_key);
            }
        }
    }
    Ok(None)
}

/// Resolve a public key to its username on the relay (for display).
pub async fn resolve_key(server: &str, key: &[u8; 32]) -> Result<Option<String>> {
    let (ws, _) = tokio_tungstenite::connect_async(server)
        .await
        .with_context(|| format!("failed to connect to {server}"))?;
    let (mut sink, mut stream) = ws.split();
    handshake(&mut sink, &mut stream).await?;
    sink.send(ws_text(Message::ResolveKey { key: *key }))
        .await
        .context("send resolve key")?;
    while let Some(Ok(msg)) = stream.next().await {
        if let WsMessage::Text(text) = msg {
            if let Message::ResolveKeyResult { username } = protocol::from_wire(&text)? {
                return Ok(username);
            }
        }
    }
    Ok(None)
}

/// Fetch the list of registered usernames from the relay.
pub async fn list_users(server: &str) -> Result<Vec<String>> {
    let (ws, _) = tokio_tungstenite::connect_async(server)
        .await
        .with_context(|| format!("failed to connect to {server}"))?;
    let (mut sink, mut stream) = ws.split();
    handshake(&mut sink, &mut stream).await?;
    sink.send(ws_text(Message::ListUsers)).await.context("send list users")?;
    while let Some(Ok(msg)) = stream.next().await {
        if let WsMessage::Text(text) = msg {
            if let Message::UserList { usernames } = protocol::from_wire(&text)? {
                return Ok(usernames);
            }
        }
    }
    Ok(Vec::new())
}

/// Run the network loop: receive envelopes and handle outgoing sends.
///
/// This runs as a background task for the duration of a chat session. It
/// owns the socket; the main loop drives sends through `rx`. If the
/// connection drops, it reconnects with backoff and re-syncs (safe because
/// delivery is at-least-once with client-side dedup).
pub async fn run_reader(
    id: Identity,
    store: Arc<Store>,
    server: String,
    mut rx: mpsc::Receiver<ClientMsg>,
) {
    // In-flight sends awaiting a SendOk/SendError, keyed by message id.
    let mut pending: std::collections::HashMap<String, PendingSend> =
        std::collections::HashMap::new();

    let mut backoff = Duration::from_millis(500);
    loop {
        let conn = match connect(&server, &id).await {
            Ok(c) => c,
            Err(e) => {
                warn!("connect failed: {e:#}; retrying in {}ms", backoff.as_millis());
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(30));
                continue;
            }
        };
        backoff = Duration::from_millis(500);

        // Run the session until the connection drops.
        if session(conn, &id, &store, &server, &mut rx, &mut pending).await {
            break; // rx closed (main loop exited)
        }
        warn!("connection lost; reconnecting");
    }
}

/// A send awaiting its acknowledgment from the server.
struct PendingSend {
    /// Recipient's public key (hex) — used for local storage.
    recipient_key: String,
    /// Recipient's username — used for display.
    recipient_name: String,
    body: String,
}

/// Run one connected session. Returns true if the main loop closed `rx`
/// (we should stop), false if the connection dropped (we should reconnect).
async fn session(
    conn: Conn,
    id: &Identity,
    store: &Arc<Store>,
    server: &str,
    rx: &mut mpsc::Receiver<ClientMsg>,
    pending: &mut std::collections::HashMap<String, PendingSend>,
) -> bool {
    let (mut sink, mut stream) = conn.split();

    // Request any queued messages on connect.
    if let Err(e) = sink.send(ws_text(Message::Sync)).await {
        warn!("failed to send sync: {e}");
        return false;
    }

    loop {
        tokio::select! {
            // Incoming from the server.
            msg = stream.next() => {
                match msg {
                    Some(Ok(WsMessage::Text(text))) => {
                        let parsed = match protocol::from_wire(&text) {
                            Ok(m) => m,
                            Err(e) => { warn!("bad message: {e}"); continue; }
                        };
                        match parsed {
                            Message::Deliver { envelope } => {
                                handle_deliver(id, store, server, &envelope).await;
                                // ACK so the server drops it.
                                let _ = sink.send(ws_text(Message::Ack { id: envelope.id })).await;
                            }
                            Message::SendOk { id: msg_id } => {
                                if let Some(p) = pending.remove(&msg_id) {
                                    let _ = store.save_outgoing(
                                        &key_hex(&id.public_key.to_bytes()),
                                        &p.recipient_key,
                                        &p.body,
                                    );
                                    println!("sent to {}", p.recipient_name);
                                    print_prompt();
                                }
                            }
                            Message::SendError { id: msg_id, reason } => {
                                if let Some(p) = pending.remove(&msg_id) {
                                    println!("failed to send to {}: {reason}", p.recipient_name);
                                    print_prompt();
                                }
                            }
                            _ => {}
                        }
                    }
                    Some(Ok(WsMessage::Close(_))) | None => return false,
                    _ => {}
                }
            }
            // Outgoing from the main loop.
            cmd = rx.recv() => {
                match cmd {
                    Some(ClientMsg::Send { recipient, body }) => {
                        if let Err(e) = send_over(&mut sink, id, store, server, &recipient, &body, pending).await {
                            warn!("failed to send to {recipient}: {e:#}");
                        }
                    }
                    None => return true,
                }
            }
        }
    }
}

/// Encrypt and send a message over an existing connection.
///
/// Resolves the recipient username to a key, seals the message, and records
/// the send as pending so the SendOk/SendError reply can be correlated.
async fn send_over(
    sink: &mut futures_util::stream::SplitSink<Conn, WsMessage>,
    id: &Identity,
    store: &Store,
    server: &str,
    recipient: &str,
    body: &str,
    pending: &mut std::collections::HashMap<String, PendingSend>,
) -> Result<()> {
    // Resolve the recipient's username to their public key.
    let pk_bytes = lookup(server, recipient)
        .await?
        .with_context(|| format!("recipient '{recipient}' not found on server"))?;
    let recipient_pk = PublicKey::from(pk_bytes);

    // Cache the recipient's key -> username mapping for display.
    let _ = store.set_contact(&key_hex(&pk_bytes), recipient);

    // Seal the message with our secret key (authenticates us as the sender).
    let sealed = crypto::seal(body.as_bytes(), &recipient_pk, &id.secret_key)?;

    let envelope = Envelope {
        id: uuid::Uuid::new_v4().to_string(),
        from: id.public_key.to_bytes(),
        to: pk_bytes,
        created_at: chrono::Utc::now().timestamp_millis() as u64,
        nonce: sealed.nonce,
        ciphertext: sealed.ciphertext,
    };

    // Record as pending before sending.
    pending.insert(
        envelope.id.clone(),
        PendingSend {
            recipient_key: key_hex(&pk_bytes),
            recipient_name: recipient.to_string(),
            body: body.to_string(),
        },
    );

    sink.send(ws_text(Message::Send {
        to: pk_bytes,
        envelope,
    }))
    .await
    .context("send message")?;
    Ok(())
}

/// Print the input prompt (used after async output so the prompt is visible).
fn print_prompt() {
    print!("> ");
    use std::io::Write;
    let _ = std::io::stdout().flush();
}

/// Decrypt and store a delivered envelope, printing it to the console.
///
/// The sender's key (`envelope.from`) is used to derive the shared secret.
/// The sender's username is resolved for display and cached locally.
async fn handle_deliver(id: &Identity, store: &Store, server: &str, envelope: &Envelope) {
    let sealed = echat_common::crypto::SealedMessage {
        sender_pk: envelope.from,
        nonce: envelope.nonce,
        ciphertext: envelope.ciphertext.clone(),
    };
    match crypto::open(&sealed, &id.secret_key) {
        Ok(plaintext) => {
            let body = String::from_utf8_lossy(&plaintext).into_owned();
            let from_hex = key_hex(&envelope.from);
            let to_hex = key_hex(&envelope.to);
            let _ = store.save_incoming(&envelope.id, &from_hex, &to_hex, &body, envelope.created_at);

            // Resolve the sender's username for display (and cache it).
            let sender_name = resolve_key(server, &envelope.from)
                .await
                .ok()
                .flatten()
                .unwrap_or_else(|| short_key(&from_hex));
            let _ = store.set_contact(&from_hex, &sender_name);

            println!("\n[{}] {}: {}", sender_name, sender_name, body);
            print_prompt();
        }
        Err(e) => {
            warn!("failed to decrypt message from key {:?}: {e}", &envelope.from[..4]);
        }
    }
}

/// A short, readable form of a hex key for display when no username is known.
fn short_key(hex: &str) -> String {
    format!("{}…{}", &hex[..8], &hex[hex.len() - 8..])
}

/// Build a text WebSocket message from a protocol message.
fn ws_text(msg: Message) -> WsMessage {
    WsMessage::Text(protocol::to_wire(&msg).expect("serialize protocol message"))
}