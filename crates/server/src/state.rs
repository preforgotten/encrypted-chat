//! Server state: user directory + per-recipient message queues.
//!
//! All state is in-memory and ephemeral. Messages are held until the
//! recipient ACKs them or they expire after a TTL; the server never stores
//! history long-term.
//!
//! The **public key is the identity**. Usernames are unique aliases used
//! only at the UX boundary. Routing, queues, and online tracking are all
//! keyed by public key; usernames are resolved to keys on the way in and
//! back to usernames only for display.

use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message as WsMessage;

use echat_common::protocol::Envelope;

/// The on-disk form of the user directory.
#[derive(Debug, Default, Serialize, Deserialize)]
struct UserDirectory {
    /// username -> public key.
    by_username: std::collections::BTreeMap<String, [u8; 32]>,
}

/// The server's in-memory state.
pub struct ServerState {
    /// username -> public key (the alias index).
    by_username: DashMap<String, [u8; 32]>,
    /// public key -> username (the identity index).
    by_key: DashMap<[u8; 32], String>,
    /// public key -> queued undelivered envelopes.
    queues: DashMap<[u8; 32], Vec<QueuedEnvelope>>,
    /// public key -> sender for their live connection (if online).
    online: DashMap<[u8; 32], mpsc::Sender<WsMessage>>,
    /// How long to keep undelivered messages.
    ttl: Duration,
    /// Path to the persisted user directory (users.json).
    users_file: std::path::PathBuf,
}

/// An envelope plus when it was queued, so we can expire it.
struct QueuedEnvelope {
    envelope: Envelope,
    queued_at: Instant,
}

impl ServerState {
    pub fn new(ttl: Duration, data_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(data_dir)
            .with_context(|| format!("failed to create data dir {}", data_dir.display()))?;
        let users_file = data_dir.join("users.json");

        let state = Self {
            by_username: DashMap::new(),
            by_key: DashMap::new(),
            queues: DashMap::new(),
            online: DashMap::new(),
            ttl,
            users_file,
        };
        state.load_users()?;
        Ok(state)
    }

    /// Load the persisted user directory, if any.
    fn load_users(&self) -> Result<()> {
        if !self.users_file.exists() {
            return Ok(());
        }
        let data = std::fs::read(&self.users_file).context("read users file")?;
        let dir: UserDirectory = serde_json::from_slice(&data).context("parse users file")?;
        for (username, key) in dir.by_username {
            self.by_username.insert(username.clone(), key);
            self.by_key.insert(key, username);
        }
        Ok(())
    }

    /// Persist the user directory to disk.
    fn save_users(&self) -> Result<()> {
        let mut dir = UserDirectory::default();
        for e in self.by_username.iter() {
            dir.by_username.insert(e.key().clone(), *e.value());
        }
        let data = serde_json::to_vec_pretty(&dir).context("serialize users")?;
        std::fs::write(&self.users_file, data).context("write users file")?;
        Ok(())
    }

    /// Register a username + public key.
    ///
    /// Returns false if the username is taken by a different key, or if the
    /// key is already registered under a different username. Re-registering
    /// the same (username, key) pair (e.g. a reconnect) is allowed.
    pub fn register(&self, username: &str, public_key: [u8; 32]) -> bool {
        // Username taken by a different key → reject.
        if let Some(existing) = self.by_username.get(username) {
            return *existing == public_key;
        }
        // Key already registered under a different username → reject.
        if let Some(owner) = self.by_key.get(&public_key) {
            return owner.as_str() == username;
        }
        self.by_username.insert(username.to_string(), public_key);
        self.by_key.insert(public_key, username.to_string());
        // Persist the updated directory (best-effort; a failure here shouldn't
        // reject the registration, but it's worth logging).
        if let Err(e) = self.save_users() {
            eprintln!("warning: failed to persist users: {e}");
        }
        true
    }

    /// Look up a username's public key.
    pub fn lookup(&self, username: &str) -> Option<[u8; 32]> {
        self.by_username.get(username).map(|pk| *pk)
    }

    /// Resolve a public key to its username, if registered.
    pub fn resolve(&self, key: &[u8; 32]) -> Option<String> {
        self.by_key.get(key).map(|u| u.clone())
    }

    /// List all registered usernames, sorted.
    pub fn list_users(&self) -> Vec<String> {
        let mut names: Vec<String> = self.by_username.iter().map(|e| e.key().clone()).collect();
        names.sort();
        names
    }

    /// Queue an envelope for a recipient and, if they're online, push it
    /// immediately. Returns false if the recipient key isn't registered.
    ///
    /// The envelope is ALWAYS queued first — the queue is the source of
    /// truth. It is only removed when the recipient ACKs it (after saving
    /// locally). This guarantees no message is lost if the connection drops
    /// between the push and the ACK.
    pub async fn enqueue(&self, to: &[u8; 32], envelope: Envelope) -> bool {
        if !self.by_key.contains_key(to) {
            return false;
        }
        // Always queue first.
        self.queues
            .entry(*to)
            .or_default()
            .push(QueuedEnvelope {
                envelope: envelope.clone(),
                queued_at: Instant::now(),
            });
        // If online, also push a copy to the live connection. The queued
        // copy stays until the client ACKs, so a mid-delivery drop is safe.
        if let Some(tx) = self.online.get(to) {
            let msg = deliver_message(&envelope);
            let _ = tx.send(msg).await;
        }
        true
    }

    /// Return copies of all queued envelopes for a user WITHOUT removing
    /// them. Used on Sync: the client ACKs each one after saving it locally,
    /// and only then is it removed from the queue.
    pub fn pending_messages(&self, key: &[u8; 32]) -> Vec<Envelope> {
        self.queues
            .get(key)
            .map(|q| q.iter().map(|qe| qe.envelope.clone()).collect())
            .unwrap_or_default()
    }

    /// Acknowledge delivery of a message by id, removing it from the queue.
    pub fn ack(&self, key: &[u8; 32], id: &str) {
        if let Some(mut q) = self.queues.get_mut(key) {
            q.retain(|qe| qe.envelope.id != id);
        }
    }

    /// Mark a user as connected, storing their outgoing channel.
    pub fn connect(&self, key: &[u8; 32], tx: mpsc::Sender<WsMessage>) {
        self.online.insert(*key, tx);
    }

    /// Mark a user as disconnected.
    pub fn disconnect(&self, key: &[u8; 32]) {
        self.online.remove(key);
    }

    /// Drop messages that have been queued longer than the TTL.
    pub fn reap_expired(&self) {
        let now = Instant::now();
        for mut q in self.queues.iter_mut() {
            q.retain(|qe| now.duration_since(qe.queued_at) < self.ttl);
        }
    }
}

/// Build a `Deliver` WebSocket message for an envelope.
fn deliver_message(envelope: &Envelope) -> WsMessage {
    WsMessage::Text(
        serde_json::to_string(&echat_common::protocol::Message::Deliver {
            envelope: envelope.clone(),
        })
        .expect("serialize deliver"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use echat_common::protocol::Envelope;

    fn env(id: &str, to: [u8; 32]) -> Envelope {
        Envelope {
            id: id.to_string(),
            from: [9u8; 32],
            to,
            created_at: 0,
            nonce: [0u8; 24],
            ciphertext: vec![],
        }
    }

    #[tokio::test]
    async fn offline_message_stays_queued_until_acked() {
        let state = ServerState::new(Duration::from_secs(3600), Path::new("/tmp/echat-test-a")).unwrap();
        let bob_key = [1u8; 32];
        state.register("bob", bob_key);

        // Bob is offline: message should be queued.
        assert!(state.enqueue(&bob_key, env("m1", bob_key)).await);
        assert_eq!(state.pending_messages(&bob_key).len(), 1);

        // Sync delivers a copy but does NOT remove it.
        let delivered = state.pending_messages(&bob_key);
        assert_eq!(delivered.len(), 1);
        // Still queued (not yet ACKed).
        assert_eq!(state.pending_messages(&bob_key).len(), 1);

        // Only the ACK removes it.
        state.ack(&bob_key, "m1");
        assert_eq!(state.pending_messages(&bob_key).len(), 0);
    }

    #[tokio::test]
    async fn online_push_keeps_queued_copy_until_acked() {
        let state = ServerState::new(Duration::from_secs(3600), Path::new("/tmp/echat-test-b")).unwrap();
        let bob_key = [1u8; 32];
        state.register("bob", bob_key);

        // Bob is online with a live channel.
        let (tx, mut rx) = mpsc::channel::<WsMessage>(16);
        state.connect(&bob_key, tx);

        // Enqueue while online: pushed AND still queued.
        assert!(state.enqueue(&bob_key, env("m1", bob_key)).await);

        // The push arrived on the live channel.
        let pushed = rx.try_recv().expect("message should be pushed");
        assert!(matches!(pushed, WsMessage::Text(_)));

        // But it is still queued (not yet ACKed) — so a drop is safe.
        assert_eq!(state.pending_messages(&bob_key).len(), 1);

        // Simulate the connection dropping before ACK: disconnect, then
        // reconnect and Sync. The message must still be there.
        state.disconnect(&bob_key);
        assert_eq!(state.pending_messages(&bob_key).len(), 1);

        // After the client ACKs, it is removed.
        state.ack(&bob_key, "m1");
        assert_eq!(state.pending_messages(&bob_key).len(), 0);
    }

    #[test]
    fn username_unique_per_key() {
        let state = ServerState::new(Duration::from_secs(3600), Path::new("/tmp/echat-test-c")).unwrap();
        let key = [1u8; 32];
        assert!(state.register("alice", key));
        // Same username, different key → rejected.
        assert!(!state.register("alice", [2u8; 32]));
        // Same username, same key (reconnect) → allowed.
        assert!(state.register("alice", key));
    }

    #[test]
    fn key_unique_per_username() {
        let state = ServerState::new(Duration::from_secs(3600), Path::new("/tmp/echat-test-d")).unwrap();
        let key = [1u8; 32];
        assert!(state.register("alice", key));
        // Same key, different username → rejected.
        assert!(!state.register("bob", key));
    }

    #[test]
    fn resolve_key_to_username() {
        let state = ServerState::new(Duration::from_secs(3600), Path::new("/tmp/echat-test-e")).unwrap();
        let key = [1u8; 32];
        state.register("alice", key);
        assert_eq!(state.resolve(&key).as_deref(), Some("alice"));
        assert_eq!(state.resolve(&[9u8; 32]), None);
    }
}