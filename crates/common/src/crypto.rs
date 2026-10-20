//! End-to-end encryption helpers built on `crypto_box`.
//!
//! This implements the classic NaCl `crypto_box` construction:
//!
//! 1. The sender derives a shared secret from their long-term secret key and
//!    the recipient's public key (X25519 ECDH).
//! 2. A random 24-byte nonce is generated per message.
//! 3. The message is encrypted with ChaCha20-Poly1305 (via `crypto_box`),
//!    which provides both confidentiality and authenticity.
//! 4. The recipient derives the same shared secret from their private key
//!    and the sender's public key, then decrypts.
//!
//! Using the sender's *long-term* key means the recipient can verify the
//! message really came from the sender (only the sender holds their secret
//! key). The random per-message nonce prevents nonce reuse between the same
//! two users.
//!
//! Tradeoff (accepted for v1): because the shared secret is derived from
//! long-term keys, an attacker who later leaks a user's long-term private
//! key could decrypt previously recorded messages. This is the forward-
//! secrecy gap we deferred; a Double Ratchet would close it later.
//!
//! The server never sees the plaintext or the shared secret — only the
//! ciphertext, the sender's public key, and the nonce needed to decrypt.

use crypto_box::aead::{Aead, Payload};
use crypto_box::{ChaChaBox, PublicKey, SecretKey};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// A message encrypted for a single recipient.
///
/// `sender_pk` is the sender's long-term public key (needed to decrypt and
/// to verify authenticity). `nonce` is a random per-message value.
#[derive(Debug, Clone)]
pub struct SealedMessage {
    /// Sender's long-term public key.
    pub sender_pk: [u8; 32],
    /// Random per-message nonce.
    pub nonce: [u8; 24],
    /// The encrypted payload.
    pub ciphertext: Vec<u8>,
}

/// Encrypt `plaintext` for `recipient_pk`, authenticating as `sender_secret`.
///
/// The returned `SealedMessage` is safe to hand to the server.
pub fn seal(
    plaintext: &[u8],
    recipient_pk: &PublicKey,
    sender_secret: &SecretKey,
) -> Result<SealedMessage, crypto_box::aead::Error> {
    // Derive the shared secret from sender secret + recipient public key.
    let box_ = ChaChaBox::new(recipient_pk, sender_secret);

    // Random per-message nonce (required because the shared secret is static).
    let mut nonce_bytes = [0u8; 24];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = crypto_box::Nonce::from_slice(&nonce_bytes);

    // No AAD: crypto_box does not support associated data.
    let ciphertext = box_.encrypt(nonce, Payload { msg: plaintext, aad: &[] })?;

    Ok(SealedMessage {
        sender_pk: sender_secret.public_key().to_bytes(),
        nonce: nonce_bytes,
        ciphertext,
    })
}

/// Decrypt a `SealedMessage` using our private key.
///
/// `sender_pk` from the message is used to derive the shared secret; if the
/// message was not sealed by the claimed sender, decryption fails.
pub fn open(
    sealed: &SealedMessage,
    our_secret: &SecretKey,
) -> Result<Zeroizing<Vec<u8>>, crypto_box::aead::Error> {
    let sender_pk = PublicKey::from(sealed.sender_pk);
    let box_ = ChaChaBox::new(&sender_pk, our_secret);

    let nonce = crypto_box::Nonce::from_slice(&sealed.nonce);
    let plaintext = box_.decrypt(nonce, Payload { msg: &sealed.ciphertext, aad: &[] })?;
    Ok(Zeroizing::new(plaintext))
}

/// A short fingerprint of a public key, for out-of-band verification.
/// Displayed as hex so users can compare it with a friend.
pub fn fingerprint(pk: &PublicKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(pk.as_bytes());
    let digest = hasher.finalize();
    // First 8 bytes, hex-encoded, colon-separated for readability.
    digest[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn seal_open_roundtrip() {
        let alice = SecretKey::generate(&mut OsRng);
        let bob = SecretKey::generate(&mut OsRng);
        let bob_pk = bob.public_key();

        let msg = b"hello bob, this is encrypted!";
        let sealed = seal(msg, &bob_pk, &alice).expect("seal");
        let opened = open(&sealed, &bob).expect("open");
        assert_eq!(opened.as_slice(), msg);
    }

    #[test]
    fn wrong_recipient_fails() {
        let alice = SecretKey::generate(&mut OsRng);
        let bob = SecretKey::generate(&mut OsRng);
        let eve = SecretKey::generate(&mut OsRng);

        let sealed = seal(b"secret", &bob.public_key(), &alice).expect("seal");
        // Eve tries to decrypt with her own key.
        assert!(open(&sealed, &eve).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let alice = SecretKey::generate(&mut OsRng);
        let bob = SecretKey::generate(&mut OsRng);

        let mut sealed = seal(b"secret", &bob.public_key(), &alice).expect("seal");
        sealed.ciphertext[0] ^= 0xff;
        assert!(open(&sealed, &bob).is_err());
    }
}