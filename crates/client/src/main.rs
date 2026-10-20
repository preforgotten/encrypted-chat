//! The echat client.
//!
//! Responsibilities:
//! - Manage local users (identity keypairs) via a config registry.
//! - Persist all conversations locally in an encrypted SQLite store.
//! - Connect to the relay, send/receive encrypted envelopes, and ACK them.
//! - Provide a small interactive CLI.

mod config;
mod db;
mod net;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tokio::sync::mpsc;
use tracing_subscriber::EnvFilter;

use echat_common::keys;
use echat_common::paths::expand_tilde;

use crate::config::{default_user_rel, Config};
use crate::db::{key_hex, Store};

/// The echat client.
#[derive(Parser, Debug)]
#[command(name = "echat-client", about = "Encrypted chat client")]
struct Args {
    /// The user to act as (resolves to their configured data directory).
    #[arg(long)]
    user: Option<String>,

    /// Override the data directory for the selected user (advanced).
    /// Defaults to the user's configured path.
    #[arg(long)]
    data_dir: Option<PathBuf>,

    /// Relay server address.
    #[arg(long, default_value = "ws://127.0.0.1:8080")]
    server: String,

    #[command(subcommand)]
    command: Command,
}

/// Resolve the data directory for the current invocation.
///
/// Precedence: explicit `--data-dir` > `--user` > the active user > a bare
/// default. The directory is created if needed.
fn resolve_data_dir(args: &Args) -> Result<PathBuf> {
    if let Some(d) = &args.data_dir {
        let dir = expand_tilde(d);
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("failed to create data dir {}", dir.display()))?;
        return Ok(dir);
    }
    if let Some(u) = &args.user {
        return resolve_user_dir(u);
    }
    // No explicit user: fall back to the active user.
    let cfg = Config::load()?;
    if let Some(u) = cfg.active_user() {
        return resolve_user_dir(u);
    }
    // No user at all: fall back to a bare default under the client dir.
    let dir = Config::client_dir().join(default_user_rel("default"));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Resolve a registered user's data directory, creating it if needed.
fn resolve_user_dir(username: &str) -> Result<PathBuf> {
    let cfg = Config::load()?;
    if let Some(dir) = cfg.user_dir(username) {
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("failed to create data dir {}", dir.display()))?;
        return Ok(dir);
    }
    anyhow::bail!(
        "user '{username}' is not registered. Create it with: echat-client user create {username}"
    )
}

/// Path to the identity key file for the resolved data dir.
fn identity_path(dir: &Path) -> PathBuf {
    dir.join("identity.json")
}

/// Path to the local message store for the resolved data dir.
fn db_path(dir: &Path) -> PathBuf {
    dir.join("echat.db")
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Manage local users (create, move, clean, list).
    User {
        #[command(subcommand)]
        action: UserAction,
    },
    /// Print your public key fingerprint (for out-of-band verification).
    Fingerprint,
    /// Register your identity with the relay server.
    Register,
    /// Look up another user's public key on the server.
    Lookup {
        username: String,
    },
    /// Start the interactive chat session.
    Chat,
}

#[derive(Subcommand, Debug)]
enum UserAction {
    /// Create a new user (generates an identity keypair).
    Create {
        /// The username.
        username: String,
    },
    /// Show, or move, a user's data directory.
    Path {
        /// The username.
        username: String,
        /// Optional new location to move the user's data to.
        new_path: Option<PathBuf>,
    },
    /// Delete a user's local data (identity + message history).
    Clean {
        /// The username.
        username: String,
    },
    /// List all registered users and their data directories.
    List,
    /// Set the active user (so `--user` can be omitted).
    Use {
        /// The username.
        username: String,
    },
    /// Show the currently active user.
    Active,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args = Args::parse();

    match args.command {
        Command::User { action } => match action {
            UserAction::Create { username } => user_create(&username)?,
            UserAction::Path { username, new_path } => user_path(&username, new_path)?,
            UserAction::Clean { username } => user_clean(&username)?,
            UserAction::List => user_list()?,
            UserAction::Use { username } => user_use(&username)?,
            UserAction::Active => user_active()?,
        },
        Command::Fingerprint => fingerprint(&args)?,
        Command::Register => register(&args).await?,
        Command::Lookup { ref username } => lookup(&args, username).await?,
        Command::Chat => chat(&args).await?,
    }
    Ok(())
}

/// Prompt for a passphrase on the terminal (no echo).
fn prompt_passphrase(prompt: &str) -> Result<String> {
    use std::io::{BufRead, Write};
    use std::process::Command as Proc;

    // Use `stty -echo` to hide input, restoring it afterwards.
    let _ = Proc::new("stty").arg("-echo").status();
    print!("{prompt}");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    let _ = Proc::new("stty").arg("echo").status();
    println!();
    Ok(line.trim().to_string())
}

/// Prompt for a yes/no confirmation.
fn prompt_confirm(prompt: &str) -> Result<bool> {
    use std::io::{BufRead, Write};
    print!("{prompt} [y/N] ");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    let a = line.trim().to_lowercase();
    Ok(a == "y" || a == "yes")
}

/// Create a new user: generate an identity in the default location and
/// register it in the config.
fn user_create(username: &str) -> Result<()> {
    let mut cfg = Config::load()?;
    if cfg.user_dir(username).is_some() {
        anyhow::bail!("user '{username}' already exists");
    }

    let rel = default_user_rel(username);
    let dir = Config::client_dir().join(&rel);
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create {}", dir.display()))?;
    let identity = identity_path(&dir);
    if identity.exists() {
        anyhow::bail!("identity file already exists at {}", identity.display());
    }

    let pass = prompt_passphrase("Choose a passphrase: ")?;
    if pass.is_empty() {
        anyhow::bail!("passphrase cannot be empty");
    }
    let confirm = prompt_passphrase("Confirm passphrase: ")?;
    if pass != confirm {
        anyhow::bail!("passphrases do not match");
    }

    let id = keys::generate_and_save(&identity, username, &pass)?;
    cfg.add_user(username, rel);
    cfg.save()?;

    println!(
        "Created user '{username}'.\nData: {}\nPublic key fingerprint: {}\nKeep your passphrase safe.",
        dir.display(),
        id.fingerprint()
    );
    Ok(())
}

/// Show or move a user's data directory.
fn user_path(username: &str, new_path: Option<PathBuf>) -> Result<()> {
    let mut cfg = Config::load()?;
    let current = cfg
        .user_dir(username)
        .with_context(|| format!("user '{username}' is not registered"))?;

    match new_path {
        None => {
            println!("{}: {}", username, current.display());
            Ok(())
        }
        Some(new) => {
            let new = expand_tilde(&new);
            if new == current {
                println!("{}: {}", username, current.display());
                return Ok(());
            }
            if new.exists() {
                anyhow::bail!("destination already exists: {}", new.display());
            }
            // Move the data directory.
            if let Some(parent) = new.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("failed to create {}", parent.display()))?;
            }
            std::fs::rename(&current, &new)
                .with_context(|| format!("failed to move {} to {}", current.display(), new.display()))?;
            // Store the new path relative to the client dir.
            let client = Config::client_dir();
            let rel = new
                .strip_prefix(&client)
                .unwrap_or(&new)
                .to_path_buf();
            cfg.set_user_dir(username, rel);
            cfg.save()?;
            println!("Moved '{username}' data to {}", new.display());
            Ok(())
        }
    }
}

/// Delete a user's local data (identity + message history).
fn user_clean(username: &str) -> Result<()> {
    let mut cfg = Config::load()?;
    let dir = cfg
        .user_dir(username)
        .with_context(|| format!("user '{username}' is not registered"))?;

    if !prompt_confirm(&format!(
        "Delete all local data for '{username}' at {}?",
        dir.display()
    ))? {
        println!("aborted");
        return Ok(());
    }

    std::fs::remove_dir_all(&dir)
        .with_context(|| format!("failed to remove {}", dir.display()))?;
    cfg.remove_user(username);
    cfg.save()?;
    println!("Cleaned data for '{username}'.");
    Ok(())
}

/// List all registered users and their data directories.
fn user_list() -> Result<()> {
    let cfg = Config::load()?;
    let entries = cfg.entries();
    if entries.is_empty() {
        println!("(no users. Create one with: echat-client user create <name>)");
    } else {
        for (name, dir) in entries {
            println!("{name}: {}", dir.display());
        }
    }
    Ok(())
}

/// Set the active user.
fn user_use(username: &str) -> Result<()> {
    let mut cfg = Config::load()?;
    if !cfg.set_active_user(username) {
        anyhow::bail!(
            "user '{username}' is not registered. Create it with: echat-client user create {username}"
        );
    }
    cfg.save()?;
    println!("Active user set to '{username}'.");
    Ok(())
}

/// Show the currently active user.
fn user_active() -> Result<()> {
    let cfg = Config::load()?;
    match cfg.active_user() {
        Some(u) => println!("{u}"),
        None => println!("(no active user. Set one with: echat-client user use <name>)"),
    }
    Ok(())
}

/// Print the fingerprint of the selected user's identity.
fn fingerprint(args: &Args) -> Result<()> {
    let dir = resolve_data_dir(args)?;
    let identity = identity_path(&dir);
    let pass = prompt_passphrase("Passphrase: ")?;
    let id = keys::load(&identity, &pass).context("failed to load identity")?;
    println!("{}: {}", id.username, id.fingerprint());
    Ok(())
}

/// Register the selected user's identity with the relay server.
async fn register(args: &Args) -> Result<()> {
    let dir = resolve_data_dir(args)?;
    let identity = identity_path(&dir);
    let pass = prompt_passphrase("Passphrase: ")?;
    let id = keys::load(&identity, &pass).context("failed to load identity")?;
    net::register(&args.server, &id).await?;
    println!("Registered {} with {}", id.username, args.server);
    Ok(())
}

/// Look up a user's public key on the server.
async fn lookup(args: &Args, username: &str) -> Result<()> {
    let pk = net::lookup(&args.server, username).await?;
    match pk {
        Some(pk) => {
            let fp = echat_common::crypto::fingerprint(&crypto_box::PublicKey::from(pk));
            println!("{username}: {fp}");
        }
        None => println!("{username}: not found"),
    }
    Ok(())
}

/// Run the interactive chat session.
async fn chat(args: &Args) -> Result<()> {
    let dir = resolve_data_dir(args)?;
    let identity = identity_path(&dir);
    let pass = prompt_passphrase("Passphrase: ")?;
    let id = keys::load(&identity, &pass).context("failed to load identity")?;

    let store = Arc::new(Store::open(&db_path(&dir))?);

    println!("Connected as {}. Type /help for commands.", id.username);

    // Channel for the main loop to drive sends through the reader task.
    let (tx, rx) = mpsc::channel(256);

    // Spawn the network reader loop (handles connect + auto-reconnect).
    let store_rx = store.clone();
    let id_rx = id.clone();
    let server_rx = args.server.clone();
    let net_task = tokio::spawn(net::run_reader(id_rx, store_rx, server_rx, rx));

    // Main input loop.
    let mut input = String::new();
    loop {
        input.clear();
        use std::io::Write;
        print!("> ");
        std::io::stdout().flush()?;
        let n = std::io::stdin().read_line(&mut input)?;
        if n == 0 {
            break;
        }
        let line = input.trim().to_string();
        if line.is_empty() {
            continue;
        }
        if let Some(cmd) = line.strip_prefix('/') {
            match cmd.split_whitespace().next().unwrap_or("") {
                "help" => print_help(),
                "quit" | "exit" => break,
                "sync" => {
                    println!("messages are fetched automatically on connect");
                }
                "lookup" => {
                    let name = cmd.split_whitespace().nth(1).unwrap_or("");
                    if name.is_empty() {
                        println!("usage: /lookup <username>");
                    } else {
                        let pk = net::lookup(&args.server, name).await?;
                        match pk {
                            Some(pk) => {
                                let fp = echat_common::crypto::fingerprint(
                                    &crypto_box::PublicKey::from(pk),
                                );
                                println!("{name}: {fp}");
                            }
                            None => println!("{name}: not found"),
                        }
                    }
                }
                "history" => {
                    let name = cmd.split_whitespace().nth(1);
                    let msgs = match name {
                        Some(partner) => {
                            // Resolve the partner's username to a key.
                            let pk = net::lookup(&args.server, partner).await?;
                            match pk {
                                Some(pk) => store.history(
                                    &key_hex(&id.public_key.to_bytes()),
                                    &key_hex(&pk),
                                    100,
                                )?,
                                None => {
                                    println!("user '{partner}' not found");
                                    continue;
                                }
                            }
                        }
                        None => store.recent(50)?,
                    };
                    if msgs.is_empty() {
                        println!("(no messages)");
                    } else {
                        let my_key = key_hex(&id.public_key.to_bytes());
                        for m in msgs {
                            let from = display_name(&store, &my_key, &id.username, &m.from);
                            let to = display_name(&store, &my_key, &id.username, &m.to);
                            println!("[{}] {} -> {}: {}", m.created_at, from, to, m.body);
                        }
                    }
                }
                "chats" => {
                    let convs = store.conversations()?;
                    if convs.is_empty() {
                        println!("(no conversations yet — send a message to start one)");
                    } else {
                        let my_key = key_hex(&id.public_key.to_bytes());
                        for c in convs {
                            let name = display_name(&store, &my_key, &id.username, &c.partner_key);
                            println!("{}: {} ({} msg)", name, c.last_body, c.count);
                        }
                    }
                }
                "users" => {
                    let users = net::list_users(&args.server).await?;
                    if users.is_empty() {
                        println!("(no users registered)");
                    } else {
                        println!("registered users:");
                        for u in users {
                            println!("  {u}");
                        }
                    }
                }
                other => println!("unknown command: /{other}"),
            }
            continue;
        }

        // Parse "recipient: message" form.
        let (recipient, body) = match line.split_once(':') {
            Some((r, b)) if !b.trim().is_empty() => (r.trim().to_string(), b.trim().to_string()),
            _ => {
                println!("usage: <recipient>: <message>  (or /help)");
                continue;
            }
        };

        // Hand the send to the reader task over the persistent connection.
        let _ = tx
            .send(net::ClientMsg::Send { recipient, body })
            .await;
    }

    net_task.abort();
    Ok(())
}

fn print_help() {
    println!(
        "Commands:\n  /help            show this help\n  /users           list registered users\n  /lookup <user>   look up a user's key fingerprint\n  /chats           show your conversations\n  /history [user]  show messages (optionally for one user)\n  /quit            exit\n\nSend a message with:  <recipient>: <message>"
    );
}

/// Resolve a hex key to a display name: our own username, a known contact
/// username, or a short key.
fn display_name(store: &Store, my_key: &str, my_name: &str, key_hex: &str) -> String {
    if key_hex == my_key {
        return my_name.to_string();
    }
    store
        .contact_username(key_hex)
        .ok()
        .flatten()
        .unwrap_or_else(|| short_key(key_hex))
}

/// A short, readable form of a hex key for display when no username is known.
fn short_key(hex: &str) -> String {
    format!("{}…{}", &hex[..8], &hex[hex.len() - 8..])
}