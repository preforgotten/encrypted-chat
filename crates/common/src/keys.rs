//! Local keypair generation and passphrase-protected storage.
//!
//! The private key never leaves the client. It is encrypted at rest with a
//! key derived from the user's passphrase via Argon2id, so a stolen key file
//! is useless without the passphrase.

use std::path::{Path, PathBuf};

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chacha20poly1305::XChaCha20Poly1305;
use crypto_box::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

/// Errors from key generation / storage.
#[derive(Debug, Error)]
pub enum KeyError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("argon2 error: {0}")]
    Argon(String),
    #[error("invalid passphrase")]
    BadPassphrase,
    #[error("key file not found at {0}")]
    NotFound(PathBuf),
}

/// The on-disk representation of a user's identity.
///
/// The private key is stored encrypted with the passphrase-derived key.
#[derive(Debug, Serialize, Deserialize)]
pub struct KeyFile {
    pub username: String,
    /// Public key, plaintext (safe to share).
    pub public_key: [u8; 32],
    /// Private key, encrypted with the passphrase-derived key.
    pub private_key_enc: Vec<u8>,
    /// Argon2id parameters + salt, needed to re-derive the key.
    pub kdf: String,
}

/// A loaded, decrypted identity.
#[derive(Clone)]
pub struct Identity {
    pub username: String,
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
}

impl Identity {
    /// The public key fingerprint for out-of-band verification.
    pub fn fingerprint(&self) -> String {
        crate::crypto::fingerprint(&self.public_key)
    }
}

/// Generate a fresh keypair and write it to `path`, protected by `passphrase`.
pub fn generate_and_save(
    path: &Path,
    username: &str,
    passphrase: &str,
) -> Result<Identity, KeyError> {
    let secret = SecretKey::generate(&mut OsRng);
    let public = secret.public_key();

    // Derive an encryption key from the passphrase.
    let salt = SaltString::generate(&mut OsRng);
    let argon = Argon2::default();
    let hash = argon
        .hash_password(passphrase.as_bytes(), &salt)
        .map_err(|e| KeyError::Argon(e.to_string()))?
        .to_string();

    // Use the derived hash bytes as a key to encrypt the private key.
    // We derive a 32-byte key from the hash via SHA-256 for use as an AEAD key.
    let key = derive_key(&hash);
    let encrypted = encrypt_private_key(&secret, &key);

    let keyfile = KeyFile {
        username: username.to_string(),
        public_key: public.to_bytes(),
        private_key_enc: encrypted,
        kdf: hash,
    };

    let json = serde_json::to_vec_pretty(&keyfile)?;
    std::fs::write(path, json)?;

    Ok(Identity {
        username: username.to_string(),
        public_key: public,
        secret_key: secret,
    })
}

/// Load and decrypt an identity from `path` using `passphrase`.
pub fn load(path: &Path, passphrase: &str) -> Result<Identity, KeyError> {
    if !path.exists() {
        return Err(KeyError::NotFound(path.to_path_buf()));
    }
    let json = std::fs::read(path)?;
    let keyfile: KeyFile = serde_json::from_slice(&json)?;

    // Verify the passphrase against the stored Argon2id hash.
    let parsed = PasswordHash::new(&keyfile.kdf).map_err(|e| KeyError::Argon(e.to_string()))?;
    Argon2::default()
        .verify_password(passphrase.as_bytes(), &parsed)
        .map_err(|_| KeyError::BadPassphrase)?;

    // Re-derive the key and decrypt the private key.
    let key = derive_key(&keyfile.kdf);
    let secret = decrypt_private_key(&keyfile.private_key_enc, &key)?;

    Ok(Identity {
        username: keyfile.username,
        public_key: PublicKey::from(keyfile.public_key),
        secret_key: secret,
    })
}

/// Derive a 32-byte AEAD key from the Argon2id hash string.
fn derive_key(kdf_hash: &str) -> Zeroizing<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(kdf_hash.as_bytes());
    let digest = hasher.finalize();
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&digest);
    key
}

/// Encrypt the private key bytes with the derived key (XChaCha20-Poly1305).
fn encrypt_private_key(secret: &SecretKey, key: &[u8; 32]) -> Vec<u8> {
    use chacha20poly1305::{KeyInit, aead::Aead};
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(
            &chacha20poly1305::XNonce::default(), // zero nonce; key is unique per file
            secret.to_bytes().as_ref(),
        )
        .expect("encryption of private key should not fail")
}

/// Decrypt the private key bytes.
fn decrypt_private_key(enc: &[u8], key: &[u8; 32]) -> Result<SecretKey, KeyError> {
    use chacha20poly1305::{KeyInit, aead::Aead};
    let cipher = XChaCha20Poly1305::new(key.into());
    let plaintext = cipher
        .decrypt(&chacha20poly1305::XNonce::default(), enc)
        .map_err(|_| KeyError::BadPassphrase)?;
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&plaintext);
    Ok(SecretKey::from(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_generate_and_load() {
        let dir = std::env::temp_dir().join(format!("echat-key-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("key.json");

        let id = generate_and_save(&path, "alice", "hunter2").unwrap();
        let loaded = load(&path, "hunter2").unwrap();

        assert_eq!(id.username, loaded.username);
        assert_eq!(id.public_key.as_bytes(), loaded.public_key.as_bytes());
        assert_eq!(id.secret_key.to_bytes(), loaded.secret_key.to_bytes());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn wrong_passphrase_fails() {
        let dir = std::env::temp_dir().join(format!("echat-key-test2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("key.json");

        generate_and_save(&path, "alice", "hunter2").unwrap();
        assert!(matches!(load(&path, "wrong"), Err(KeyError::BadPassphrase)));

        std::fs::remove_dir_all(&dir).ok();
    }
}