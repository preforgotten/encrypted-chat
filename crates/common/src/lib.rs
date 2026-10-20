//! Shared wire protocol, crypto helpers, and key storage for echat.
//!
//! The server only ever sees ciphertext envelopes; all plaintext handling
//! happens client-side. See `protocol` for the wire format and `crypto` for
//! the sealed-box construction described in the design.

pub mod crypto;
pub mod keys;
pub mod paths;
pub mod protocol;
pub mod util;

/// A convenience alias for a boxed error used across the crates.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;