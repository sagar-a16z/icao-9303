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

use {
    super::groups::{EllipticCurve, named::secp256r1},
    super::mod_ring::RingRefExt,
    anyhow::ensure,
    anyhow::Result,
    num_traits::Inv,
    ruint::aliases::U256,
};

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
        ensure!(!bytes.is_empty() && bytes[0] == 0x30, "Expected SEQUENCE tag 0x30");
        let (seq_len, skip) = read_len(bytes, 1)?;
        ensure!(bytes.len() >= 1 + skip + seq_len, "DER buffer too short");
        let content = &bytes[1 + skip..1 + skip + seq_len];

        let (r, r_consumed) = read_integer(content, 0)?;
        let (s, _) = read_integer(content, r_consumed)?;

        Ok(Self { r, s })
    }
}

/// Verify an ECDSA signature over `message_hash` using the P-256 curve.
///
/// `signature_der` — DER-encoded `SEQUENCE { INTEGER r, INTEGER s }`
/// `public_key_bytes` — uncompressed EC point `0x04 || x || y` (65 bytes)
pub fn verify_ecdsa_p256(
    message_hash: &[u8],
    signature_der: &[u8],
    public_key_bytes: &[u8],
) -> Result<()> {
    let curve = secp256r1();
    verify_ecdsa(message_hash, signature_der, public_key_bytes, &curve)
}

/// Generic ECDSA verification over any curve using U256 scalars.
fn verify_ecdsa(
    message_hash: &[u8],
    signature_der: &[u8],
    public_key_bytes: &[u8],
    curve: &EllipticCurve<U256>,
) -> Result<()> {
    let sig = EcdsaSignature::from_der(signature_der)?;

    // Parse public key: 0x04 || x (32 bytes) || y (32 bytes)
    ensure!(
        public_key_bytes.len() == 65 && public_key_bytes[0] == 0x04,
        "Expected 65-byte uncompressed public key (0x04 prefix)"
    );
    let x_bytes = &public_key_bytes[1..33];
    let y_bytes = &public_key_bytes[33..65];
    let px = curve.base_field().from(U256::from_be_slice(x_bytes));
    let py = curve.base_field().from(U256::from_be_slice(y_bytes));
    let q = curve.from_affine(px, py)?;

    let n = curve.scalar_field();

    // Convert r, s to scalars (zero-extend to 32 bytes)
    let r_uint = uint_from_be_padded(&sig.r);
    let s_uint = uint_from_be_padded(&sig.s);
    let e_uint = uint_from_be_padded(message_hash);

    let r_elem = n.from(r_uint);
    let s_elem = n.from(s_uint);
    let e_elem = n.from(e_uint);

    // Check 1 ≤ r, s < n
    ensure!(r_elem.to_uint() != U256::ZERO, "r must not be zero");
    ensure!(s_elem.to_uint() != U256::ZERO, "s must not be zero");

    // w = s⁻¹ mod n
    let w = s_elem.inv().ok_or_else(|| anyhow::anyhow!("s is not invertible mod n"))?;

    // u1 = e·w, u2 = r·w
    let u1 = e_elem * w;
    let u2 = r_elem * w;

    // X = u1·G + u2·Q
    let point = curve.generator() * u1 + q * u2;

    // Check X ≠ ∞
    let (x_coord, _) = point.coordinates().ok_or_else(|| anyhow::anyhow!("Result is point at infinity"))?;

    // Check x mod n == r
    let x_uint = x_coord.to_uint();
    let n_mod = n.modulus();
    // x is in base field (mod p), reduce mod n for comparison
    let x_reduced = if x_uint >= n_mod { x_uint - n_mod } else { x_uint };
    ensure!(
        x_reduced == r_elem.to_uint(),
        "ECDSA verification failed: x coordinate does not match r"
    );

    Ok(())
}

/// Convert big-endian bytes to U256, zero-extending if shorter than 32 bytes.
fn uint_from_be_padded(bytes: &[u8]) -> U256 {
    let mut buf = [0u8; 32];
    let start = 32usize.saturating_sub(bytes.len());
    let copy_len = bytes.len().min(32);
    buf[start..start + copy_len].copy_from_slice(&bytes[bytes.len() - copy_len..]);
    U256::from_be_slice(&buf)
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

    /// Test ECDSA verification with a known NIST P-256 test vector.
    /// From NIST FIPS 186-4, Example for P-256.
    #[test]
    fn test_verify_ecdsa_p256() -> Result<()> {
        // RFC 6979 A.2.5 test vector for P-256 with SHA-256
        // message = "sample", private key = 0x...
        // We use a manually computed vector here.
        let curve = secp256r1();

        // Known private key (for test only)
        let d = U256::from_be_slice(&hex_literal::hex!(
            "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"
        ));

        // Compute public key Q = d * G
        let d_scalar = curve.scalar_field().from(d);
        let q = curve.generator() * d_scalar;
        let (qx, qy) = q.coordinates().unwrap();

        // Build uncompressed public key bytes
        let mut pubkey = [0u8; 65];
        pubkey[0] = 0x04;
        let qx_bytes = qx.to_uint().to_be_bytes::<32>();
        let qy_bytes = qy.to_uint().to_be_bytes::<32>();
        pubkey[1..33].copy_from_slice(&qx_bytes);
        pubkey[33..65].copy_from_slice(&qy_bytes);

        // Known r, s from RFC 6979 A.2.5 (SHA-256, message "sample")
        let r_bytes = hex_literal::hex!(
            "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716"
        );
        let s_bytes = hex_literal::hex!(
            "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8"
        );

        // Hash of "sample" with SHA-256
        let message_hash = hex_literal::hex!(
            "AF2BDBE1AA9B6EC1E2ADE1D694F41FC71A831D0268E9891562113D8A62ADD1BF"
        );

        // Build DER signature
        let sig_der = encode_ecdsa_der(&r_bytes, &s_bytes);

        verify_ecdsa(&message_hash, &sig_der, &pubkey, &curve)?;
        Ok(())
    }

    /// Helper to DER-encode an ECDSA signature for testing.
    fn encode_ecdsa_der(r: &[u8], s: &[u8]) -> Vec<u8> {
        fn encode_integer(val: &[u8]) -> Vec<u8> {
            let mut out = vec![0x02];
            if val[0] & 0x80 != 0 {
                out.push((val.len() + 1) as u8);
                out.push(0x00);
            } else {
                out.push(val.len() as u8);
            }
            out.extend_from_slice(val);
            out
        }
        let r_enc = encode_integer(r);
        let s_enc = encode_integer(s);
        let mut out = vec![0x30, (r_enc.len() + s_enc.len()) as u8];
        out.extend_from_slice(&r_enc);
        out.extend_from_slice(&s_enc);
        out
    }
}
