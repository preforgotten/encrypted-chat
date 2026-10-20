//! The echat relay server.
//!
//! The server is a dumb relay: it only ever sees ciphertext envelopes and
//! routing metadata. It holds messages in a per-recipient queue until the
//! recipient ACKs them, then deletes them. Old messages are dropped after a
//! TTL, so the server has no long-term memory.

mod state;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tracing::{info, warn};

use echat_common::protocol::{self, Message, PROTOCOL_VERSION};

use crate::state::ServerState;

/// Maximum accepted size (bytes) for a single incoming text frame.
const MAX_FRAME_BYTES: usize = 1 << 20; // 1 MiB

/// The echat relay server.
#[derive(Parser, Debug)]
#[command(name = "echat-server", about = "Encrypted chat relay server")]
struct Args {
    /// Address to bind, e.g. 127.0.0.1:8080
    #[arg(long, default_value = "127.0.0.1:8080")]
    bind: SocketAddr,

    /// How long to keep undelivered messages before dropping them.
    #[arg(long, default_value = "604800")]
    ttl_secs: u64,

    /// Directory for server data (registered users). Defaults to the
    /// configured server dir under ~/.encrypted-chat.
    #[arg(long)]
    data_dir: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args = Args::parse();

    // Resolve the server data dir: explicit flag, else the configured one.
    let data_dir = match &args.data_dir {
        Some(d) => echat_common::paths::expand_tilde(d),
        None => echat_common::paths::TopConfig::load().server_dir(),
    };
    let state = Arc::new(ServerState::new(Duration::from_secs(args.ttl_secs), &data_dir)?);
    info!("server data dir: {}", data_dir.display());

    let listener = TcpListener::bind(args.bind)
        .await
        .with_context(|| format!("failed to bind {}", args.bind))?;
    info!("echat server listening on {}", args.bind);

    // Background task to reap expired messages.
    let reap_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            reap_state.reap_expired();
        }
    });

    loop {
        let (stream, addr) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(state, stream, addr).await {
                warn!("connection {addr} ended: {e:#}");
            }
        });
    }
}

/// Handle a single WebSocket connection.
async fn handle_connection(
    state: Arc<ServerState>,
    stream: TcpStream,
    addr: SocketAddr,
) -> Result<()> {
    let ws = tokio_tungstenite::accept_async(stream)
        .await
        .context("websocket handshake failed")?;
    let (mut ws_sink, mut ws_stream) = ws.split();

    // A channel to push outgoing messages to this connection.
    let (tx, mut rx) = mpsc::channel::<WsMessage>(256);

    // The public key this connection is registered as, if any.
    let mut my_key: Option<[u8; 32]> = None;

    // Whether the version handshake has completed.
    let mut handshaken = false;

    // Task that drains the outgoing channel to the socket.
    let sink_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if ws_sink.send(msg).await.is_err() {
                break;
            }
        }
    });

    while let Some(Ok(msg)) = ws_stream.next().await {
        match msg {
            WsMessage::Text(text) => {
                if text.len() > MAX_FRAME_BYTES {
                    warn!("{addr}: frame too large ({} bytes)", text.len());
                    break;
                }
                let parsed = match protocol::from_wire(&text) {
                    Ok(m) => m,
                    Err(e) => {
                        warn!("{addr}: bad message: {e}");
                        continue;
                    }
                };

                // The version handshake must be the first message.
                if !handshaken {
                    match parsed {
                        Message::Hello { version } if version == PROTOCOL_VERSION => {
                            handshaken = true;
                            let _ = tx.send(ws_text(Message::HelloOk)).await;
                        }
                        Message::Hello { version } => {
                            let _ = tx
                                .send(ws_text(Message::HelloError {
                                    reason: format!(
                                        "unsupported protocol version {version} (server is {PROTOCOL_VERSION})"
                                    ),
                                }))
                                .await;
                            break;
                        }
                        _ => {
                            warn!("{addr}: expected Hello handshake first");
                            break;
                        }
                    }
                    continue;
                }

                match parsed {
                    Message::Register { username: u, public_key } => {
                        if state.register(&u, public_key) {
                            my_key = Some(public_key);
                            state.connect(&public_key, tx.clone());
                            let _ = tx.send(ws_text(Message::RegisterOk)).await;
                            info!("{addr}: registered as {u}");
                        } else {
                            let _ = tx
                                .send(ws_text(Message::RegisterError {
                                    reason: "username or key already registered".into(),
                                }))
                                .await;
                        }
                    }
                    Message::Lookup { username: u } => {
                        let pk = state.lookup(&u);
                        let _ = tx
                            .send(ws_text(Message::LookupResult {
                                username: u,
                                public_key: pk,
                            }))
                            .await;
                    }
                    Message::ResolveKey { key } => {
                        let _ = tx
                            .send(ws_text(Message::ResolveKeyResult {
                                username: state.resolve(&key),
                            }))
                            .await;
                    }
                    Message::ListUsers => {
                        let _ = tx
                            .send(ws_text(Message::UserList {
                                usernames: state.list_users(),
                            }))
                            .await;
                    }
                    Message::Send { to, envelope } => {
                        // Only accept sends from a registered connection.
                        let from = match &my_key {
                            Some(k) => *k,
                            None => {
                                warn!("{addr}: send from unregistered connection");
                                continue;
                            }
                        };
                        // Trust the envelope's `from` field to match the
                        // registered key.
                        let mut env = envelope;
                        env.from = from;
                        let id = env.id.clone();
                        if state.enqueue(&to, env).await {
                            info!("send queued for key {:?}", &to[..4]);
                            let _ = tx.send(ws_text(Message::SendOk { id })).await;
                        } else {
                            warn!("recipient key not found");
                            let _ = tx
                                .send(ws_text(Message::SendError {
                                    id,
                                    reason: "recipient not found".into(),
                                }))
                                .await;
                        }
                    }
                    Message::Ack { id } => {
                        if let Some(k) = &my_key {
                            state.ack(k, &id);
                        }
                    }
                    Message::Sync => {
                        if let Some(k) = &my_key {
                            let pending = state.pending_messages(k);
                            for env in pending {
                                let _ = tx
                                    .send(ws_text(Message::Deliver { envelope: env }))
                                    .await;
                            }
                        }
                    }
                    _ => {
                        warn!("{addr}: unexpected message");
                    }
                }
            }
            WsMessage::Close(_) => break,
            WsMessage::Ping(_) | WsMessage::Pong(_) => {}
            _ => {}
        }
    }

    // Connection closed: remove from the online map.
    if let Some(k) = &my_key {
        state.disconnect(k);
    }
    sink_task.abort();
    Ok(())
}

/// Build a text WebSocket message from a protocol message.
fn ws_text(msg: Message) -> WsMessage {
    WsMessage::Text(protocol::to_wire(&msg).expect("serialize protocol message"))
}