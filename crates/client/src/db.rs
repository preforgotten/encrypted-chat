//! Local message store backed by SQLite.
//!
//! All conversations are persisted locally so the server doesn't need to
//! remember history. The private key itself lives in the identity file
//! (encrypted at rest); this store holds decrypted message history on the
//! client's own machine.
//!
//! The **public key is the identity**: messages are stored by the sender's
//! and recipient's public keys (hex-encoded). Usernames are resolved via a
//! local `contacts` table (key -> username) purely for display.

use std::path::Path;
use std::sync::Mutex;

use anyhow::{Context, Result};
use rusqlite::Connection;

/// Encode a 32-byte public key as a hex string for storage.
pub fn key_hex(key: &[u8; 32]) -> String {
    key.iter().map(|b| format!("{b:02x}")).collect()
}

/// A single stored message. `from`/`to` are hex-encoded public keys.
#[derive(Debug, Clone)]
pub struct StoredMessage {
    pub from: String,
    pub to: String,
    pub body: String,
    pub created_at: u64,
    /// true if we sent it, false if we received it.
    pub outgoing: bool,
}

/// A conversation with one other user (identified by their public key),
/// derived from local history.
#[derive(Debug, Clone)]
pub struct Conversation {
    /// The other user's public key (hex).
    pub partner_key: String,
    /// The most recent message body.
    pub last_body: String,
    /// Timestamp of the most recent message.
    pub last_at: u64,
    /// Total number of messages in the conversation.
    pub count: u64,
}

/// The local message store.
pub struct Store {
    conn: Mutex<Connection>,
}

impl Store {
    /// Open (creating if needed) the SQLite store at `path`.
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path).context("open local store")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                from_key TEXT NOT NULL,
                to_key TEXT NOT NULL,
                body TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                outgoing INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS contacts (
                key TEXT PRIMARY KEY,
                username TEXT NOT NULL
            );",
        )
        .context("create tables")?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Save an outgoing message. `from`/`to` are hex-encoded keys.
    pub fn save_outgoing(&self, from: &str, to: &str, body: &str) -> Result<()> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().timestamp_millis() as u64;
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO messages (id, from_key, to_key, body, created_at, outgoing)
             VALUES (?1, ?2, ?3, ?4, ?5, 1)",
            rusqlite::params![id, from, to, body, now],
        )
        .context("save outgoing message")?;
        Ok(())
    }

    /// Save an incoming message (dedup by id). `from`/`to` are hex keys.
    pub fn save_incoming(
        &self,
        id: &str,
        from: &str,
        to: &str,
        body: &str,
        created_at: u64,
    ) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let inserted = conn
            .execute(
                "INSERT OR IGNORE INTO messages (id, from_key, to_key, body, created_at, outgoing)
                 VALUES (?1, ?2, ?3, ?4, ?5, 0)",
                rusqlite::params![id, from, to, body, created_at],
            )
            .context("save incoming message")?;
        Ok(inserted > 0)
    }

    /// Remember the username for a key (for display). Upsert.
    pub fn set_contact(&self, key: &str, username: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO contacts (key, username) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET username = excluded.username",
            rusqlite::params![key, username],
        )
        .context("save contact")?;
        Ok(())
    }

    /// Resolve a key to its known username, if any.
    pub fn contact_username(&self, key: &str) -> Result<Option<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT username FROM contacts WHERE key = ?1")
            .context("prepare contact query")?;
        let mut rows = stmt.query_map(rusqlite::params![key], |row| row.get::<_, String>(0))?;
        Ok(rows.next().transpose()?)
    }

    /// List recent messages, newest first.
    pub fn recent(&self, limit: usize) -> Result<Vec<StoredMessage>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT id, from_key, to_key, body, created_at, outgoing
                 FROM messages ORDER BY created_at DESC LIMIT ?1",
            )
            .context("prepare recent query")?;
        let rows = stmt
            .query_map(rusqlite::params![limit as i64], |row| {
                Ok(StoredMessage {
                    from: row.get(1)?,
                    to: row.get(2)?,
                    body: row.get(3)?,
                    created_at: row.get(4)?,
                    outgoing: row.get::<_, i64>(5)? != 0,
                })
            })
            .context("query recent messages")?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.context("read recent message")?);
        }
        Ok(out)
    }

    /// List messages in a conversation with `partner_key`, oldest first.
    pub fn history(&self, me_key: &str, partner_key: &str, limit: usize) -> Result<Vec<StoredMessage>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT id, from_key, to_key, body, created_at, outgoing
                 FROM messages
                 WHERE (from_key = ?1 AND to_key = ?2)
                    OR (from_key = ?2 AND to_key = ?1)
                 ORDER BY created_at ASC LIMIT ?3",
            )
            .context("prepare history query")?;
        let rows = stmt
            .query_map(rusqlite::params![me_key, partner_key, limit as i64], |row| {
                Ok(StoredMessage {
                    from: row.get(1)?,
                    to: row.get(2)?,
                    body: row.get(3)?,
                    created_at: row.get(4)?,
                    outgoing: row.get::<_, i64>(5)? != 0,
                })
            })
            .context("query history")?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.context("read history message")?);
        }
        Ok(out)
    }

    /// List conversations, each grouped by the other user's key, most recent
    /// first.
    ///
    /// A conversation exists only if we've exchanged at least one message
    /// with that user (sending the first message "creates" it). This is a
    /// purely client-side model derived from local history.
    pub fn conversations(&self) -> Result<Vec<Conversation>> {
        use std::collections::HashMap;

        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT from_key, to_key, body, created_at, outgoing
                 FROM messages ORDER BY created_at ASC",
            )
            .context("prepare conversations query")?;
        let rows = stmt
            .query_map([], |row| {
                Ok(StoredMessage {
                    from: row.get(0)?,
                    to: row.get(1)?,
                    body: row.get(2)?,
                    created_at: row.get(3)?,
                    outgoing: row.get::<_, i64>(4)? != 0,
                })
            })
            .context("query messages for conversations")?;

        // Group by the other party's key, tracking the latest message + count.
        let mut by_partner: HashMap<String, Conversation> = HashMap::new();
        for r in rows {
            let m = r.context("read conversation message")?;
            let (partner, body) = if m.outgoing {
                (m.to.clone(), m.body.clone())
            } else {
                (m.from.clone(), m.body.clone())
            };
            let conv = by_partner.entry(partner.clone()).or_insert_with(|| Conversation {
                partner_key: String::new(),
                last_body: String::new(),
                last_at: 0,
                count: 0,
            });
            conv.partner_key = partner;
            conv.last_body = body;
            conv.last_at = m.created_at;
            conv.count += 1;
        }

        let mut out: Vec<Conversation> = by_partner.into_values().collect();
        out.sort_by_key(|c| std::cmp::Reverse(c.last_at));
        Ok(out)
    }
}