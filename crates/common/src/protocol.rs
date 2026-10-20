//! The wire protocol between client and server.
//!
//! The server only ever sees `Envelope`s (ciphertext + routing metadata).
//! It never sees plaintext.
//!
//! Delivery is at-least-once: the server's per-recipient queue is the single
//! source of truth. Every message is queued first, and is removed from the
//! queue only when the recipient ACKs it (after saving it locally). If the
//! recipient is online, a copy is also pushed to their live connection, but
//! the queued copy stays until the ACK. Old messages are dropped after a
//! TTL, so the server has no long-term memory.

use serde::{Deserialize, Serialize};

/// The current protocol version. Bump on any incompatible wire change.
pub const PROTOCOL_VERSION: u32 = 1;

/// A message sent between client and server over the WebSocket.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Message {
    /// Client → Server: version handshake (must be the first message).
    Hello { version: u32 },
    /// Server → Client: handshake accepted.
    HelloOk,
    /// Server → Client: handshake rejected (e.g. version mismatch).
    HelloError { reason: String },

    /// Client → Server: register a username + public key.
    Register {
        username: String,
        public_key: [u8; 32],
    },
    /// Server → Client: registration result.
    RegisterOk,
    /// Server → Client: registration failed (e.g. username taken).
    RegisterError { reason: String },

    /// Client → Server: request a user's public key.
    Lookup { username: String },
    /// Server → Client: the requested public key (or not found).
    LookupResult {
        username: String,
        public_key: Option<[u8; 32]>,
    },

    /// Client → Server: resolve a public key to its username (for display).
    ResolveKey { key: [u8; 32] },
    /// Server → Client: the username for a key, if registered.
    ResolveKeyResult { username: Option<String> },

    /// Client → Server: request the list of registered usernames.
    ListUsers,
    /// Server → Client: the list of registered usernames.
    UserList { usernames: Vec<String> },

    /// Client → Server: deliver an envelope to a recipient.
    Send {
        /// The recipient's public key (routing only; server never decrypts).
        to: [u8; 32],
        /// The encrypted payload.
        envelope: Envelope,
    },
    /// Server → Client: the envelope was accepted and queued.
    SendOk { id: String },
    /// Server → Client: the envelope was rejected (e.g. recipient unknown).
    SendError { id: String, reason: String },
    /// Server → Client: an envelope queued for us.
    Deliver { envelope: Envelope },
    /// Client → Server: acknowledge receipt of a message (by id).
    Ack { id: String },

    /// Client → Server: fetch all queued messages (used after reconnect).
    Sync,
}

/// A single encrypted message as seen by the server.
///
/// `from` and `to` are the sender's and recipient's **public keys** (their
/// real identities). Usernames are not used for routing; they are resolved
/// to keys at the client and back to usernames only for display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    /// Unique message id (client-generated) for dedup + ACK.
    pub id: String,
    /// Sender's public key (identity).
    pub from: [u8; 32],
    /// Recipient's public key (identity).
    pub to: [u8; 32],
    /// When the sender created it (Unix millis).
    pub created_at: u64,
    /// Random per-message nonce.
    pub nonce: [u8; 24],
    /// The sealed ciphertext. Opaque to the server.
    pub ciphertext: Vec<u8>,
}

/// Serialize a protocol message to a JSON string for the wire.
pub fn to_wire(msg: &Message) -> Result<String, serde_json::Error> {
    serde_json::to_string(msg)
}

/// Parse a protocol message from a JSON string off the wire.
pub fn from_wire(data: &str) -> Result<Message, serde_json::Error> {
    serde_json::from_str(data)
}