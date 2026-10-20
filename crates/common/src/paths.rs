//! Shared path resolution for the echat data tree.
//!
//! Layout under the base directory (default `~/.encrypted-chat`):
//!
//! ```text
//! ~/.encrypted-chat/
//! ├── config.json     # top-level: server_path, client_path (relative)
//! ├── server/         # server data (users.json)
//! └── client/         # client data (config.json + data/<name>/)
//! ```
//!
//! The top-level `config.json` records `server_path` and `client_path` as
//! paths relative to the base directory, so the whole tree can be relocated.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The base directory for all echat state: ~/.encrypted-chat.
pub fn base_dir() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".encrypted-chat")
}

/// The path to the top-level config file.
pub fn config_path() -> PathBuf {
    base_dir().join("config.json")
}

/// The top-level config: where the server and client data live.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopConfig {
    /// Path to the server data dir, relative to the base dir.
    pub server_path: PathBuf,
    /// Path to the client data dir, relative to the base dir.
    pub client_path: PathBuf,
}

impl Default for TopConfig {
    fn default() -> Self {
        Self {
            server_path: PathBuf::from("server"),
            client_path: PathBuf::from("client"),
        }
    }
}

impl TopConfig {
    /// Load the top-level config, using defaults if it doesn't exist.
    pub fn load() -> Self {
        let path = config_path();
        if !path.exists() {
            return Self::default();
        }
        std::fs::read(&path)
            .ok()
            .and_then(|data| serde_json::from_slice(&data).ok())
            .unwrap_or_default()
    }

    /// Save the top-level config, creating the base dir if needed.
    pub fn save(&self) -> std::io::Result<()> {
        let path = config_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let data = serde_json::to_vec_pretty(self).expect("serialize top config");
        std::fs::write(path, data)
    }

    /// The absolute server data directory.
    pub fn server_dir(&self) -> PathBuf {
        resolve_relative(&base_dir(), &self.server_path)
    }

    /// The absolute client data directory.
    pub fn client_dir(&self) -> PathBuf {
        resolve_relative(&base_dir(), &self.client_path)
    }
}

/// Resolve a possibly-relative path against a base, expanding `~`.
pub fn resolve_relative(base: &Path, p: &Path) -> PathBuf {
    if p.is_absolute() {
        return p.to_path_buf();
    }
    base.join(p)
}

/// Expand a leading `~` in a path to the user's home directory.
pub fn expand_tilde(path: &Path) -> PathBuf {
    let Some(s) = path.to_str() else {
        return path.to_path_buf();
    };
    if s == "~" {
        return base_dir();
    }
    if let Some(rest) = s.strip_prefix("~/") {
        let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
        return home.join(rest);
    }
    path.to_path_buf()
}