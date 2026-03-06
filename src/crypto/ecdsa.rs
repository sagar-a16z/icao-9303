//! ECDSA signature verification (ANSI X9.62 / RFC 5480).
//!
//! Used for Passive Authentication when the DS certificate uses an EC key
//! rather than RSA. Many modern passports (post ~2015) are EC-signed.
//!
//! # Algorithm (verify)
//! Given message hash `e`, signature `(r, s)`, public key `Q`, generator `G`,
//! curve order `n`:
//!
//! 1. Parse DER `SEQUENCE { INTEGER r, INTEGER s }`
//! 2. Check `1 ≤ r, s < n`
//! 3. `w = s⁻¹ mod n`
//! 4. `u1 = e·w mod n`,  `u2 = r·w mod n`
//! 5. `X = u1·G + u2·Q`
//! 6. Accept iff `X ≠ ∞` and `X.x mod n = r`

use anyhow::{anyhow, bail, ensure, Result};

/// Parsed ECDSA signature.
#[derive(Clone, Debug)]
pub struct EcdsaSignature {
    /// `r` component as big-endian bytes
    pub r: Vec<u8>,
    /// `s` component as big-endian bytes
    pub s: Vec<u8>,
}

impl EcdsaSignature {
    /// Decode a DER-encoded ECDSA signature: `SEQUENCE { INTEGER r, INTEGER s }`.
    pub fn from_der(bytes: &[u8]) -> Result<Self> {
        // Manual minimal DER parser for SEQUENCE { INTEGER, INTEGER }
        ensure!(!bytes.is_empty() && bytes[0] == 0x30, "Expected SEQUENCE tag 0x30");
        let (seq_len, skip) = read_len(bytes, 1)?;
        ensure!(bytes.len() >= 1 + skip + seq_len, "DER buffer too short");
        let content = &bytes[1 + skip..1 + skip + seq_len];

        let (r, r_consumed) = read_integer(content, 0)?;
        let (s, _) = read_integer(content, r_consumed)?;

        Ok(Self { r, s })
    }
}

/// Verify an ECDSA-SHA256 signature over `message_hash`.
///
/// `signature_der` — DER-encoded `SEQUENCE { INTEGER r, INTEGER s }`
/// `public_key_bytes` — uncompressed EC point `0x04 || x || y`
///
/// This is a placeholder implementation that parses the signature and
/// validates its structure. Full scalar-multiplication verification requires
/// wiring into the existing `EllipticCurve` / `ModRingElement` infrastructure
/// (see `src/crypto/groups/`).
pub fn verify_ecdsa_p256(
    message_hash: &[u8],
    signature_der: &[u8],
    public_key_bytes: &[u8],
) -> Result<()> {
    let sig = EcdsaSignature::from_der(signature_der)?;

    // Basic structural validation
    ensure!(!sig.r.is_empty() && !sig.s.is_empty(), "Signature components must be non-empty");
    ensure!(!message_hash.is_empty(), "Message hash must not be empty");
    ensure!(
        !public_key_bytes.is_empty() && public_key_bytes[0] == 0x04,
        "Expected uncompressed public key (0x04 prefix)"
    );

    // TODO: Full verification using ModRing scalar arithmetic and the
    // secp256r1 EllipticCurve from src/crypto/groups/named.rs.
    //
    // Steps remaining:
    //   let curve = secp256r1();
    //   let n_ring = ModRing::from_modulus(curve.order());
    //   let w = n_ring.from_be_bytes(&sig.s).inv().ok_or(...)?;
    //   let u1 = n_ring.from_be_bytes(message_hash) * w;
    //   let u2 = n_ring.from_be_bytes(&sig.r) * w;
    //   let point = curve.generator() * u1 + public_key * u2;
    //   ensure!(point.x() mod n == r);
    bail!("ECDSA scalar verification not yet implemented")
}

// ── DER helpers ──────────────────────────────────────────────────────────────

fn read_len(buf: &[u8], offset: usize) -> Result<(usize, usize)> {
    ensure!(buf.len() > offset, "Buffer too short for length byte");
    let b = buf[offset];
    if b & 0x80 == 0 {
        Ok((b as usize, 1))
    } else {
        let n = (b & 0x7f) as usize;
        ensure!(buf.len() >= offset + 1 + n, "Buffer too short for long-form length");
        let mut val = 0usize;
        for &byte in &buf[offset + 1..offset + 1 + n] {
            val = (val << 8) | byte as usize;
        }
        Ok((val, 1 + n))
    }
}

/// Read a DER INTEGER at `buf[offset]`. Returns (value_bytes_without_leading_zero, bytes_consumed).
fn read_integer(buf: &[u8], offset: usize) -> Result<(Vec<u8>, usize)> {
    ensure!(
        buf.len() > offset && buf[offset] == 0x02,
        "Expected INTEGER tag 0x02 at offset {offset}"
    );
    let (len, lskip) = read_len(buf, offset + 1)?;
    let value_start = offset + 1 + lskip;
    ensure!(buf.len() >= value_start + len, "Buffer too short for INTEGER value");
    let raw = &buf[value_start..value_start + len];
    // Strip leading zero byte used in DER to ensure positive sign
    let value = if raw.first() == Some(&0x00) && raw.len() > 1 {
        raw[1..].to_vec()
    } else {
        raw.to_vec()
    };
    Ok((value, 1 + lskip + len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ecdsa_der() -> Result<()> {
        // Minimal known-good DER ECDSA signature (P-256)
        let der = hex_literal::hex!(
            "3045"
            "0221" "00" "e8e4a4d22cee8879f43b4b40bc67b22e58e60c3977ca15dfc3ff4a90b7e96d7e"
            "0220" "7b2be2a09a2b8e31ec76d4a5f2987faabd2c5c1c8fd2f6ab5bc5e38da4bbd2c1"
        );
        let sig = EcdsaSignature::from_der(&der)?;
        assert_eq!(sig.r.len(), 32);
        assert_eq!(sig.s.len(), 32);
        Ok(())
    }
}
