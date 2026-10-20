//! Local user registry: maps usernames to their data directories.
//!
//! The registry lives in the client data dir (`~/.encrypted-chat/client/`),
//! at `config.json`. User data paths are stored **relative** to the client
//! dir (e.g. `data/alice`), so the whole tree can be relocated.

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use echat_common::paths::TopConfig;

/// The on-disk user registry.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Config {
    /// username -> data directory (relative to the client dir).
    users: BTreeMap<String, PathBuf>,
    /// The currently active user (for commands that omit `--user`).
    #[serde(default)]
    active_user: Option<String>,
}

impl Config {
    /// The path to the client config file.
    pub fn path() -> PathBuf {
        TopConfig::load().client_dir().join("config.json")
    }

    /// The client data directory (absolute).
    pub fn client_dir() -> PathBuf {
        TopConfig::load().client_dir()
    }

    /// Load the config from the client dir, or an empty one if absent.
    pub fn load() -> Result<Self> {
        let path = Self::path();
        if !path.exists() {
            return Ok(Self::default());
        }
        let data = std::fs::read(&path).context("read config")?;
        let cfg = serde_json::from_slice(&data).context("parse config")?;
        Ok(cfg)
    }

    /// Save the config to the client dir, creating parent dirs.
    pub fn save(&self) -> Result<()> {
        let path = Self::path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).context("create config dir")?;
        }
        let data = serde_json::to_vec_pretty(self).context("serialize config")?;
        std::fs::write(path, data).context("write config")?;
        Ok(())
    }

    /// The absolute data directory for `username`, if registered.
    pub fn user_dir(&self, username: &str) -> Option<PathBuf> {
        self.users
            .get(username)
            .map(|rel| Self::client_dir().join(rel))
    }

    /// Register `username` at a path relative to the client dir.
    /// Returns false if the name is taken.
    pub fn add_user(&mut self, username: &str, rel: PathBuf) -> bool {
        if self.users.contains_key(username) {
            return false;
        }
        self.users.insert(username.to_string(), rel);
        true
    }

    /// Update the data directory for `username` (relative to client dir).
    /// Returns false if unknown.
    pub fn set_user_dir(&mut self, username: &str, rel: PathBuf) -> bool {
        if !self.users.contains_key(username) {
            return false;
        }
        self.users.insert(username.to_string(), rel);
        true
    }

    /// Remove `username` from the registry. Returns false if unknown.
    pub fn remove_user(&mut self, username: &str) -> bool {
        self.users.remove(username).is_some()
    }

    /// All (username, absolute dir) pairs, sorted by username.
    pub fn entries(&self) -> Vec<(String, PathBuf)> {
        let client = Self::client_dir();
        self.users
            .iter()
            .map(|(k, v)| (k.clone(), client.join(v)))
            .collect()
    }

    /// The currently active user, if any.
    pub fn active_user(&self) -> Option<&str> {
        self.active_user.as_deref()
    }

    /// Set the active user. Returns false if the user isn't registered.
    pub fn set_active_user(&mut self, username: &str) -> bool {
        if !self.users.contains_key(username) {
            return false;
        }
        self.active_user = Some(username.to_string());
        true
    }
}

/// The default relative data directory for a user: data/<name>.
pub fn default_user_rel(username: &str) -> PathBuf {
    PathBuf::from("data").join(username)
}