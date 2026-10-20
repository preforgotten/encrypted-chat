# echat — a simple end-to-end encrypted chat

A small, casual end-to-end encrypted chat for friend groups, written in Rust.

- **End-to-end encrypted**: messages are sealed with the recipient's public
  key before they ever leave your machine. The server only ever sees
  ciphertext and routing metadata — it cannot read your messages.
- **Store-and-forward**: the server holds messages in a per-recipient queue
  until you're online to receive them, then forgets them. Your full history
  lives locally on your own machine.
- **Lossless by design**: a message leaves the server's queue only when the
  recipient confirms (ACKs) that they've stored it locally. Online or
  offline, connected or dropped — no message is lost.
- **No long-term server memory**: undelivered messages are dropped after a
  TTL (default 7 days). The server is a dumb relay.

## Architecture

```
┌──────────┐   WSS    ┌─────────────────┐   WSS   ┌──────────┐
│  Alice   │ ◄──────► │   Relay Server  │ ◄─────► │   Bob    │
│ (client) │          │  (queue, auth)  │         │ (client) │
└──────────┘          └─────────────────┘         └──────────┘
     │ SQLite local        ephemeral only               │ SQLite local
     └── message history   └── no long-term storage    └── message history
```

Three crates:

| Crate | Role |
|-------|------|
| `crates/common` | Wire protocol, crypto (sealed box), key storage |
| `crates/server` | WebSocket relay with per-user queues + TTL |
| `crates/client` | Identity, encryption, local SQLite history, CLI |

## Transport & protocol

Clients and the server talk over a single **WebSocket** connection
(`tokio-tungstenite`), with JSON-serialized protocol frames. The transport
is plain WebSocket (no TLS by default); confidentiality comes from the
end-to-end encryption, not the channel.

A chat session holds **one persistent connection** owned by a background
reader task, which handles both incoming deliveries and outgoing sends. The
protocol frames are:

| Frame | Direction | Purpose |
|-------|-----------|---------|
| `Hello` / `HelloOk` / `HelloError` | C↔S | Version handshake (must be first) |
| `Register` / `RegisterOk` / `RegisterError` | C↔S | Claim a username + publish your public key |
| `Lookup` / `LookupResult` | C↔S | Resolve a username to its public key |
| `ResolveKey` / `ResolveKeyResult` | C↔S | Resolve a public key to its username (display) |
| `ListUsers` / `UserList` | C↔S | List registered usernames |
| `Send` / `SendOk` / `SendError` | C↔S | Deliver an envelope; server confirms acceptance |
| `Deliver` | S→C | An envelope queued for you |
| `Ack` | C→S | Confirm receipt so the server can drop it |
| `Sync` | C→S | Pull queued messages (sent on connect) |

The protocol is versioned (`PROTOCOL_VERSION`); a mismatched client and
server fail loudly at the `Hello` handshake instead of silently misbehaving.
The server also rejects frames larger than 1 MiB to bound resource use.

### Delivery model

The server's queue is the **single source of truth**. The invariant:

> A message enters the queue, and leaves it only when the recipient ACKs it
> after saving it locally.

- Every `Send` is queued first. If the recipient is online, a copy is also
  pushed to their live connection — but the queued copy stays until ACKed.
- `Sync` (sent on connect) returns copies of queued messages without
  removing them; the client ACKs each one after storing it.
- This gives **at-least-once** delivery with client-side dedup by message id.
  A dropped connection is safe: the message simply stays queued until the
  client reconnects and ACKs.

Sessions are just delivery channels — they don't affect correctness.

If the connection drops, the client **auto-reconnects with exponential
backoff** and re-syncs. Because delivery is at-least-once with client-side
dedup, reconnecting never loses or duplicates a message. The sender also
learns the real outcome of each send: `SendOk` confirms the server accepted
and queued it, `SendError` reports a rejection (e.g. unknown recipient).

## Crypto

Each user has a long-term X25519 keypair. **The public key is the real
identity**; the username is a unique alias used only for display. Messages
are routed, stored, and encrypted by key; usernames are resolved to keys on
the way out and back to usernames only for display.

Messages use the classic NaCl `crypto_box` construction:

1. Sender derives a shared secret from their secret key + recipient's public
   key (X25519 ECDH).
2. A random 24-byte nonce is generated per message.
3. The message is encrypted with ChaCha20-Poly1305, giving confidentiality
   and authenticity (only the sender holds their secret key).
4. Recipient derives the same shared secret and decrypts.

The private key never leaves your machine. It is stored encrypted at rest,
protected by a passphrase (Argon2id).

**Known tradeoff (accepted for v1):** because the shared secret is derived
from long-term keys, an attacker who later leaks a user's long-term private
key could decrypt previously recorded messages. This is the forward-secrecy
gap; a Double Ratchet would close it in a future version.

## Usage

### 1. Start the server

```sh
cargo run -p echat-server -- --bind 127.0.0.1:8080
```

The server stores registered users in `~/.encrypted-chat/server/users.json`
by default. Use `--data-dir <path>` to store server data elsewhere.

### 2. Create a user (account)

```sh
cargo run -p echat-client -- user create alice
# prompts for a passphrase
```

Each user is an **account** managed by the client. A user's identity and
message history live in a data directory, and a local registry maps
usernames to their directories.

Default layout:

```
~/.encrypted-chat/
├── config.json            # top-level: server_path, client_path (relative)
├── server/                # server data
│   └── users.json         # persisted username ↔ key directory
└── client/                # client data
    ├── config.json        # user registry (relative paths) + active user
    └── data/<name>/       # per-user data
        ├── identity.json  # keypair (private key encrypted with passphrase)
        └── echat.db       # local message history (SQLite)
```

The top-level `config.json` records where the server and client data live
(relative to `~/.encrypted-chat`), so the whole tree can be relocated. The
server persists its user directory to `server/users.json`, so registered
users survive a server restart; the message queue itself stays ephemeral.

### 3. Manage users

```sh
cargo run -p echat-client -- user list                 # list users and paths
cargo run -p echat-client -- user path alice           # show alice's data path
cargo run -p echat-client -- user path alice ~/alice   # move alice's data
cargo run -p echat-client -- user clean alice          # delete alice's local data
cargo run -p echat-client -- user use alice            # set alice as the active user
cargo run -p echat-client -- user active               # show the active user
```

### 4. Register with the server

```sh
cargo run -p echat-client -- register
```

### 5. Chat

```sh
cargo run -p echat-client -- chat
```

Every command acts as the **active user** (set with `user use <name>`), so
`--user` can be omitted. `--user <name>` still overrides the active user for
a single command, and `--data-dir` remains a low-level override.

In the chat session:

```
> bob: hello, this is encrypted!
sent to bob
> /users          # list registered users
> /lookup bob     # show bob's key fingerprint
> /chats          # show your conversations (from local history)
> /history bob    # show the messages in your chat with bob
> /quit
```

`/users` lists who is registered on the server so you can discover who to
message. `/chats` shows your existing conversations, derived from local
history — sending the first message to a user "creates" a chat with them.
This is a purely client-side model; the server doesn't track conversations.
`/history <user>` shows the messages in one conversation; `/history` with no
argument shows recent messages across all conversations. Because the client
is multi-user, each history line shows both the sender and the receiver
(e.g. `alice -> bob: hello`).

Messages are delivered in real time if the recipient is online, or queued
on the server and delivered when they next connect. Because delivery is
at-least-once with client-side dedup, reconnecting never loses or duplicates
a message.

### Verifying identities (optional)

The server is a convenient directory, but not a trusted one. To be sure
you're talking to the real Bob, compare key fingerprints out-of-band:

```sh
cargo run -p echat-client -- fingerprint
```

## Security notes

- The server never sees plaintext or your private key.
- Your local message history is stored in plaintext SQLite. The *private
  key* is encrypted at rest, but the decrypted message bodies are not. If
  you want the message store itself encrypted, that's a future enhancement.
- Registration is idempotent: reconnecting with the same key is allowed;
  a different key cannot steal an existing username. Both usernames and
  public keys are unique per server.
- The server persists its **user directory** (username ↔ key) to disk, so
  registered users survive a restart. The **message queue is in-memory
  only**: a server restart clears undelivered messages. This matches the
  "server doesn't remember old messages" intent, while keeping identities
  durable.
- The client **auto-reconnects** with exponential backoff if the socket
  drops, and re-syncs on reconnect. The queue makes this safe (no loss).

## Future ideas

- Double Ratchet for forward secrecy
- Group chats (encrypt one envelope per member)
- Encrypted local message store
- Key rotation
- Read receipts
- Request/response correlation ids (the protocol currently relies on frame
  ordering for `Lookup`/`Register` replies)