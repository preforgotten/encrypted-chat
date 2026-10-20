//! Small shared helpers.

/// Encode a 32-byte public key as a hex string.
pub fn key_hex(key: &[u8; 32]) -> String {
    key.iter().map(|b| format!("{b:02x}")).collect()
}

/// Decode a hex string into a 32-byte key. Returns None on invalid input.
pub fn key_from_hex(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}