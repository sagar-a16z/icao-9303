//! Fast P-256 ECDSA verification using NIST Solinas reduction + Shamir's trick.
//!
//! This replaces the generic `ruint`-based EC arithmetic for P-256 verification
//! with hand-tuned `[u64; 4]` limb arithmetic. ~10x faster on RISC-V.
//!
//! Optimizations over the generic path:
//! 1. NIST P-256 Solinas fast reduction (FIPS 186-4 D.2.3): reduces 512→256 bits
//!    via adds/subs of 32-bit slices, replacing a full 4×4 Montgomery reduction.
//! 2. a = -3 Jacobian doubling: `alpha = 3*(X-Z²)*(X+Z²)` saves 1 field mul vs generic.
//! 3. Shamir's trick: single-pass double scalar mul (256 doublings vs 512).
//! 4. Mixed Jacobian-affine addition: precomputed points have Z=1, saving 4 muls/add.

use anyhow::{ensure, Result};

// ── P-256 constants (little-endian u64 limbs) ───────────────────────────────

const P: [u64; 4] = [
    0xFFFFFFFFFFFFFFFF, 0x00000000FFFFFFFF,
    0x0000000000000000, 0xFFFFFFFF00000001,
];
const N: [u64; 4] = [
    0xF3B9CAC2FC632551, 0xBCE6FAADA7179E84,
    0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF00000000,
];
const GX: [u64; 4] = [
    0xF4A13945D898C296, 0x77037D812DEB33A0,
    0xF8BCE6E563A440F2, 0x6B17D1F2E12C4247,
];
const GY: [u64; 4] = [
    0xCBB6406837BF51F5, 0x2BCE33576B315ECE,
    0x8EE7EB4A7C0F9E16, 0x4FE342E2FE1A7F9B,
];

// ── 256-bit arithmetic ──────────────────────────────────────────────────────

#[inline(always)]
fn u256_is_zero(a: &[u64; 4]) -> bool {
    a[0] == 0 && a[1] == 0 && a[2] == 0 && a[3] == 0
}
#[inline(always)]
fn u256_eq(a: &[u64; 4], b: &[u64; 4]) -> bool {
    a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3]
}
#[inline(always)]
fn u256_gte(a: &[u64; 4], b: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] > b[i] { return true; }
        if a[i] < b[i] { return false; }
    }
    true
}
#[inline(always)]
fn u256_add(a: &[u64; 4], b: &[u64; 4]) -> ([u64; 4], bool) {
    let mut r = [0u64; 4];
    let mut carry = 0u128;
    for i in 0..4 {
        carry += a[i] as u128 + b[i] as u128;
        r[i] = carry as u64;
        carry >>= 64;
    }
    (r, carry != 0)
}
#[inline(always)]
fn u256_sub(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut r = [0u64; 4];
    let mut borrow = 0i128;
    for i in 0..4 {
        let diff = a[i] as i128 - b[i] as i128 - borrow;
        if diff < 0 { r[i] = (diff + (1i128 << 64)) as u64; borrow = 1; }
        else { r[i] = diff as u64; borrow = 0; }
    }
    r
}

// ── Field element (mod p) ───────────────────────────────────────────────────

#[derive(Clone)]
struct Fp([u64; 4]);

impl Fp {
    fn zero() -> Self { Fp([0; 4]) }
    fn one() -> Self { Fp([1, 0, 0, 0]) }
    fn is_zero(&self) -> bool { u256_is_zero(&self.0) }
    fn eq(&self, o: &Fp) -> bool { u256_eq(&self.0, &o.0) }
    fn add(&self, o: &Fp) -> Fp {
        let (s, c) = u256_add(&self.0, &o.0);
        if c || u256_gte(&s, &P) { Fp(u256_sub(&s, &P)) } else { Fp(s) }
    }
    fn sub(&self, o: &Fp) -> Fp {
        if u256_gte(&self.0, &o.0) { Fp(u256_sub(&self.0, &o.0)) }
        else { let (s, _) = u256_add(&self.0, &P); Fp(u256_sub(&s, &o.0)) }
    }
    fn dbl(&self) -> Fp { self.add(self) }
    fn tpl(&self) -> Fp { self.dbl().add(self) }
    fn mul(&self, o: &Fp) -> Fp { Fp(p256_field_mul(&self.0, &o.0)) }
    fn square(&self) -> Fp { self.mul(self) }
    fn div(&self, o: &Fp) -> Fp {
        let inv = pow_mod_p(&o.0, &u256_sub(&P, &[2, 0, 0, 0]));
        Fp(p256_field_mul(&self.0, &inv))
    }
}

fn p256_field_mul(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let product = schoolbook_mul_512(a, b);
    p256_reduce(&product)
}

fn pow_mod_p(base: &[u64; 4], exp: &[u64; 4]) -> [u64; 4] {
    let mut result = [1, 0, 0, 0];
    let mut b = *base;
    for i in 0..4 { for bit in 0..64 {
        if (exp[i] >> bit) & 1 == 1 { result = p256_field_mul(&result, &b); }
        b = p256_field_mul(&b, &b);
    }}
    result
}

// ── Scalar field (mod n) — Montgomery multiplication ─────────────────────────

/// Context for Montgomery arithmetic modulo the curve order N.
/// Computed once per verification; the cost is negligible (~512 additions).
struct ScalarMontCtx {
    n_inv: u64,          // -N[0]^{-1} mod 2^64
    r2_mod_n: [u64; 4],  // R² mod N, where R = 2^256
}

impl ScalarMontCtx {
    fn new() -> Self {
        // Compute -N[0]^{-1} mod 2^64 via Newton's method.
        // Newton iteration: x_{k+1} = x_k * (2 - N[0] * x_k) mod 2^{2^k}
        // After 6 iterations, correct mod 2^64.
        let n0 = N[0];
        let mut x: u64 = 1;
        for _ in 0..6 {
            x = x.wrapping_mul(2u64.wrapping_sub(n0.wrapping_mul(x)));
        }
        let n_inv = x.wrapping_neg();

        // Compute R² mod N = 2^512 mod N via repeated doubling.
        // Start at 1 and double 512 times, reducing mod N each step.
        let mut v = [1u64, 0, 0, 0];
        for _ in 0..512 {
            let (d, c) = u256_add(&v, &v);
            v = if c || u256_gte(&d, &N) { u256_sub(&d, &N) } else { d };
        }

        ScalarMontCtx { n_inv, r2_mod_n: v }
    }

    /// Montgomery reduction: T * R^{-1} mod N
    #[inline(always)]
    fn redc(&self, t: &[u64; 8]) -> [u64; 4] {
        let mut w = [0u64; 9];
        w[..8].copy_from_slice(t);
        for i in 0..4 {
            let m = w[i].wrapping_mul(self.n_inv);
            let mut carry = 0u128;
            for j in 0..4 {
                carry += w[i + j] as u128 + m as u128 * N[j] as u128;
                w[i + j] = carry as u64;
                carry >>= 64;
            }
            for k in (i + 4)..9 {
                carry += w[k] as u128;
                w[k] = carry as u64;
                carry >>= 64;
                if carry == 0 { break; }
            }
        }
        let result = [w[4], w[5], w[6], w[7]];
        if w[8] > 0 || u256_gte(&result, &N) { u256_sub(&result, &N) } else { result }
    }

    /// Montgomery multiplication: (a * b * R^{-1}) mod N
    #[inline(always)]
    fn mont_mul(&self, a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
        let product = schoolbook_mul_512(a, b);
        self.redc(&product)
    }

    /// Encode into Montgomery form: a → a*R mod N
    #[inline(always)]
    fn encode(&self, a: &[u64; 4]) -> [u64; 4] {
        self.mont_mul(a, &self.r2_mod_n)
    }

    /// Decode from Montgomery form: aR → a mod N
    #[inline(always)]
    fn decode(&self, a_mont: &[u64; 4]) -> [u64; 4] {
        let mut t = [0u64; 8];
        t[..4].copy_from_slice(a_mont);
        self.redc(&t)
    }

    /// Multiply two plain values: (a * b) mod N
    fn mul(&self, a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
        let am = self.encode(a);
        let bm = self.encode(b);
        self.decode(&self.mont_mul(&am, &bm))
    }

    /// Modular exponentiation: base^exp mod N
    fn pow(&self, base: &[u64; 4], exp: &[u64; 4]) -> [u64; 4] {
        let mut result = self.encode(&[1, 0, 0, 0]);
        let mut b = self.encode(base);
        for i in 0..4 {
            for bit in 0..64 {
                if (exp[i] >> bit) & 1 == 1 {
                    result = self.mont_mul(&result, &b);
                }
                b = self.mont_mul(&b, &b);
            }
        }
        self.decode(&result)
    }
}

// ── Schoolbook multiply ─────────────────────────────────────────────────────

fn schoolbook_mul_512(a: &[u64; 4], b: &[u64; 4]) -> [u64; 8] {
    let mut result = [0u64; 8];
    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..4 {
            let prod = a[i] as u128 * b[j] as u128 + result[i + j] as u128 + carry;
            result[i + j] = prod as u64;
            carry = prod >> 64;
        }
        result[i + 4] = carry as u64;
    }
    result
}

// ── NIST P-256 Solinas fast reduction (FIPS 186-4 D.2.3) ───────────────────

#[inline(always)]
fn w32(val: &[u64; 8], i: usize) -> u64 {
    (val[i / 2] >> ((i % 2) * 32)) & 0xFFFFFFFF
}
#[inline(always)]
fn b256(w0: u64, w1: u64, w2: u64, w3: u64, w4: u64, w5: u64, w6: u64, w7: u64) -> [u64; 4] {
    [w0 | (w1 << 32), w2 | (w3 << 32), w4 | (w5 << 32), w6 | (w7 << 32)]
}
fn p256_reduce(val: &[u64; 8]) -> [u64; 4] {
    let s1 = b256(w32(val,0), w32(val,1), w32(val,2), w32(val,3), w32(val,4), w32(val,5), w32(val,6), w32(val,7));
    let s2 = b256(0, 0, 0, w32(val,11), w32(val,12), w32(val,13), w32(val,14), w32(val,15));
    let s3 = b256(0, 0, 0, w32(val,12), w32(val,13), w32(val,14), w32(val,15), 0);
    let s4 = b256(w32(val,8), w32(val,9), w32(val,10), 0, 0, 0, w32(val,14), w32(val,15));
    let s5 = b256(w32(val,9), w32(val,10), w32(val,11), w32(val,13), w32(val,14), w32(val,15), w32(val,13), w32(val,8));
    let s6 = b256(w32(val,11), w32(val,12), w32(val,13), 0, 0, 0, w32(val,8), w32(val,10));
    let s7 = b256(w32(val,12), w32(val,13), w32(val,14), w32(val,15), 0, 0, w32(val,9), w32(val,11));
    let s8 = b256(w32(val,13), w32(val,14), w32(val,15), w32(val,8), w32(val,9), w32(val,10), 0, w32(val,12));
    let s9 = b256(w32(val,14), w32(val,15), 0, w32(val,9), w32(val,10), w32(val,11), 0, w32(val,13));

    // Accumulate with i64 carry to handle both overflow and underflow
    let mut acc = s1;
    let mut ac: i64 = 0; // signed carry — can go negative from subtractions

    // Helper: add 256-bit value to acc, update signed carry
    let do_add = |acc: &mut [u64; 4], ac: &mut i64, b: &[u64; 4]| {
        let mut carry = 0u128;
        for i in 0..4 { carry += acc[i] as u128 + b[i] as u128; acc[i] = carry as u64; carry >>= 64; }
        *ac += carry as i64;
    };
    let do_sub = |acc: &mut [u64; 4], ac: &mut i64, b: &[u64; 4]| {
        let mut borrow = 0i128;
        for i in 0..4 {
            let d = acc[i] as i128 - b[i] as i128 - borrow;
            if d < 0 { acc[i] = (d + (1i128 << 64)) as u64; borrow = 1; }
            else { acc[i] = d as u64; borrow = 0; }
        }
        *ac -= borrow as i64;
    };

    do_add(&mut acc, &mut ac, &s2); do_add(&mut acc, &mut ac, &s2); // +2*s2
    do_add(&mut acc, &mut ac, &s3); do_add(&mut acc, &mut ac, &s3); // +2*s3
    do_add(&mut acc, &mut ac, &s4);
    do_add(&mut acc, &mut ac, &s5);
    do_sub(&mut acc, &mut ac, &s6);
    do_sub(&mut acc, &mut ac, &s7);
    do_sub(&mut acc, &mut ac, &s8);
    do_sub(&mut acc, &mut ac, &s9);

    // Final normalization: bring into [0, p)
    while ac < 0 {
        do_add(&mut acc, &mut ac, &P);
    }
    while ac > 0 || u256_gte(&acc, &P) {
        do_sub(&mut acc, &mut ac, &P);
    }
    acc
}

// ── Jacobian projective point ───────────────────────────────────────────────

struct Jac { x: Fp, y: Fp, z: Fp }
impl Jac {
    fn inf() -> Self { Jac { x: Fp::one(), y: Fp::one(), z: Fp::zero() } }
    fn from_affine(x: Fp, y: Fp) -> Self { Jac { x, y, z: Fp::one() } }
    fn is_inf(&self) -> bool { self.z.is_zero() }

    // a = -3 optimized doubling (3M + 5S)
    fn double(&self) -> Jac {
        if self.is_inf() { return Jac::inf(); }
        let delta = self.z.square();
        let gamma = self.y.square();
        let beta = self.x.mul(&gamma);
        let alpha = self.x.sub(&delta).mul(&self.x.add(&delta)).tpl();
        let x3 = alpha.square().sub(&beta.dbl().dbl().dbl());
        let z3 = self.y.add(&self.z).square().sub(&gamma).sub(&delta);
        let y3 = alpha.mul(&beta.dbl().dbl().sub(&x3))
            .sub(&gamma.square().dbl().dbl().dbl());
        Jac { x: x3, y: y3, z: z3 }
    }

    // Mixed Jacobian-affine addition (7M + 4S)
    fn add_affine(&self, qx: &Fp, qy: &Fp) -> Jac {
        if self.is_inf() { return Jac::from_affine(qx.clone(), qy.clone()); }
        let z1z1 = self.z.square();
        let u2 = qx.mul(&z1z1);
        let s2 = qy.mul(&self.z.mul(&z1z1));
        let h = u2.sub(&self.x);
        let hh = h.square();
        let i = hh.dbl().dbl();
        let j = h.mul(&i);
        let rr = s2.sub(&self.y).dbl();
        if h.is_zero() {
            if rr.is_zero() { return self.double(); }
            else { return Jac::inf(); }
        }
        let v = self.x.mul(&i);
        let x3 = rr.square().sub(&j).sub(&v.dbl());
        let y3 = rr.mul(&v.sub(&x3)).sub(&self.y.dbl().mul(&j));
        let z3 = self.z.add(&h).square().sub(&z1z1).sub(&hh);
        Jac { x: x3, y: y3, z: z3 }
    }

    fn to_affine(&self) -> ([u64; 4], [u64; 4]) {
        assert!(!self.is_inf());
        let zi = Fp::one().div(&self.z);
        let zi2 = zi.square();
        let zi3 = zi2.mul(&zi);
        (self.x.mul(&zi2).0, self.y.mul(&zi3).0)
    }
}

// ── Shamir's trick ──────────────────────────────────────────────────────────

fn shamir(k1: &[u64; 4], p1x: &Fp, p1y: &Fp, k2: &[u64; 4], p2x: &Fp, p2y: &Fp) -> Jac {
    let jp = Jac::from_affine(p1x.clone(), p1y.clone()).add_affine(p2x, p2y);
    let (p12x, p12y) = jp.to_affine();
    let p12x = Fp(p12x);
    let p12y = Fp(p12y);
    let mut result = Jac::inf();
    for i in (0..4).rev() {
        for bit in (0..64).rev() {
            result = result.double();
            let b1 = (k1[i] >> bit) & 1;
            let b2 = (k2[i] >> bit) & 1;
            if b1 == 1 && b2 == 1 { result = result.add_affine(&p12x, &p12y); }
            else if b1 == 1 { result = result.add_affine(p1x, p1y); }
            else if b2 == 1 { result = result.add_affine(p2x, p2y); }
        }
    }
    result
}

// ── Public API ──────────────────────────────────────────────────────────────

/// Convert big-endian bytes to little-endian u64 limbs.
fn be_bytes_to_limbs(bytes: &[u8]) -> [u64; 4] {
    let mut buf = [0u8; 32];
    let start = 32usize.saturating_sub(bytes.len());
    let n = bytes.len().min(32);
    buf[start..start + n].copy_from_slice(&bytes[bytes.len() - n..]);
    // buf is big-endian, convert to little-endian limbs
    [
        u64::from_be_bytes([buf[24], buf[25], buf[26], buf[27], buf[28], buf[29], buf[30], buf[31]]),
        u64::from_be_bytes([buf[16], buf[17], buf[18], buf[19], buf[20], buf[21], buf[22], buf[23]]),
        u64::from_be_bytes([buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15]]),
        u64::from_be_bytes([buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]]),
    ]
}

/// Fast P-256 ECDSA verification. Drop-in replacement for `verify_ecdsa_p256`.
///
/// Uses NIST Solinas fast reduction, a=-3 Jacobian doubling, Shamir's trick,
/// and mixed Jacobian-affine addition. ~10x faster than generic ruint path.
pub fn verify_ecdsa_p256_fast(
    message_hash: &[u8],
    signature_der: &[u8],
    public_key_bytes: &[u8],
) -> Result<()> {
    // Parse signature
    let sig = super::ecdsa::EcdsaSignature::from_der(signature_der)?;

    // Parse public key
    ensure!(
        public_key_bytes.len() == 65 && public_key_bytes[0] == 0x04,
        "Expected 65-byte uncompressed public key"
    );
    let qx = be_bytes_to_limbs(&public_key_bytes[1..33]);
    let qy = be_bytes_to_limbs(&public_key_bytes[33..65]);

    let r = be_bytes_to_limbs(&sig.r);
    let s = be_bytes_to_limbs(&sig.s);
    let e = be_bytes_to_limbs(message_hash);

    ensure!(!u256_is_zero(&r) && !u256_gte(&r, &N), "r out of range");
    ensure!(!u256_is_zero(&s) && !u256_gte(&s, &N), "s out of range");

    // Scalar field arithmetic via Montgomery multiplication
    let ctx = ScalarMontCtx::new();

    // w = s^{-1} mod n  (Fermat's little theorem)
    let w = ctx.pow(&s, &u256_sub(&N, &[2, 0, 0, 0]));

    // u1 = e*w mod n, u2 = r*w mod n
    let u1 = ctx.mul(&e, &w);
    let u2 = ctx.mul(&r, &w);

    // R = u1*G + u2*Q via Shamir's trick
    let rr = shamir(&u1, &Fp(GX), &Fp(GY), &u2, &Fp(qx), &Fp(qy));
    ensure!(!rr.is_inf(), "Result is point at infinity");
    let (rx, _) = rr.to_affine();

    // Check R.x mod n == r
    let rx_mod_n = if u256_gte(&rx, &N) { u256_sub(&rx, &N) } else { rx };
    ensure!(u256_eq(&rx_mod_n, &r), "ECDSA verification failed");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::mod_ring::RingRefExt;
    use ruint::aliases::U256;

    fn limbs_to_u256(l: &[u64; 4]) -> U256 {
        U256::from_limbs(*l)
    }
    fn u256_to_limbs(v: U256) -> [u64; 4] {
        v.into_limbs()
    }

    #[test]
    fn test_field_mul_basic() {
        let one = [1u64, 0, 0, 0];
        assert_eq!(p256_field_mul(&one, &one), one);

        // (p-1)^2 mod p = 1
        let pm1 = u256_sub(&P, &one);
        assert_eq!(p256_field_mul(&pm1, &pm1), one);
    }

    /// Cross-validate Solinas field mul against ruint mul_mod for random-ish vectors.
    #[test]
    fn test_field_mul_cross_validate() {
        let p_u256 = limbs_to_u256(&P);
        // Test vectors: various edge cases + pseudo-random values
        let test_vals: Vec<[u64; 4]> = vec![
            [0, 0, 0, 0],
            [1, 0, 0, 0],
            [2, 0, 0, 0],
            u256_sub(&P, &[1, 0, 0, 0]),  // p-1
            u256_sub(&P, &[2, 0, 0, 0]),  // p-2
            [0xFFFFFFFFFFFFFFFF, 0, 0, 0],
            [0, 0xFFFFFFFF, 0, 0],
            [0xDEADBEEF_CAFEBABE, 0x1234567890ABCDEF, 0xFEDCBA0987654321, 0x0102030405060708],
            [0xA5A5A5A5A5A5A5A5, 0x5A5A5A5A5A5A5A5A, 0x1111111111111111, 0xEEEEEEEE00000001],
            GX, GY,
        ];
        for a in &test_vals {
            // Reduce a mod p first
            let a_mod = u256_to_limbs(limbs_to_u256(a) % p_u256);
            for b in &test_vals {
                let b_mod = u256_to_limbs(limbs_to_u256(b) % p_u256);
                let fast = p256_field_mul(&a_mod, &b_mod);
                let expected = u256_to_limbs(limbs_to_u256(&a_mod).mul_mod(limbs_to_u256(&b_mod), p_u256));
                assert_eq!(fast, expected,
                    "field_mul mismatch: a={a_mod:?}, b={b_mod:?}");
            }
        }
    }

    /// Cross-validate scalar field Montgomery mul against ruint mul_mod.
    #[test]
    fn test_scalar_mul_cross_validate() {
        let ctx = ScalarMontCtx::new();
        let n_u256 = limbs_to_u256(&N);
        let test_vals: Vec<[u64; 4]> = vec![
            [1, 0, 0, 0],
            u256_sub(&N, &[1, 0, 0, 0]),
            u256_sub(&N, &[2, 0, 0, 0]),
            [0xDEADBEEF_CAFEBABE, 0x1234567890ABCDEF, 0xFEDCBA0987654321, 0x0102030405060708],
            GX,
        ];
        for a in &test_vals {
            let a_mod = u256_to_limbs(limbs_to_u256(a) % n_u256);
            for b in &test_vals {
                let b_mod = u256_to_limbs(limbs_to_u256(b) % n_u256);
                let fast = ctx.mul(&a_mod, &b_mod);
                let expected = u256_to_limbs(limbs_to_u256(&a_mod).mul_mod(limbs_to_u256(&b_mod), n_u256));
                assert_eq!(fast, expected,
                    "scalar_mul mismatch: a={a_mod:?}, b={b_mod:?}");
            }
        }
    }

    /// Verify Montgomery constants are correct.
    #[test]
    fn test_montgomery_constants() {
        let ctx = ScalarMontCtx::new();
        let n_u256 = limbs_to_u256(&N);

        // Verify N_INV: N[0] * N_INV ≡ -1 (mod 2^64)
        let check = N[0].wrapping_mul(ctx.n_inv);
        assert_eq!(check, u64::MAX, "N_INV incorrect: N[0]*N_INV should be 2^64 - 1");

        // Verify R^2: should equal (2^256)^2 mod N
        let r = U256::from(1u64) << 256; // This is 2^256, but U256 can't hold it...
        // Instead: R mod N = 2^256 mod N. Compute via ruint:
        // 2^256 mod N = -N mod 2^256 (wrapping)
        let r_mod_n_expected = U256::ZERO.wrapping_sub(n_u256);
        let r2_expected = r_mod_n_expected.mul_mod(r_mod_n_expected, n_u256);
        assert_eq!(limbs_to_u256(&ctx.r2_mod_n), r2_expected, "R^2 mod N incorrect");
    }

    /// Test the full ECDSA verification using the RFC 6979 test vector.
    #[test]
    fn test_verify_ecdsa_p256_fast() -> anyhow::Result<()> {
        use crate::crypto::groups::{EllipticCurve, named::secp256r1};
        use ruint::uint;

        let curve = secp256r1();
        let d = U256::from_be_slice(&hex_literal::hex!(
            "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"
        ));
        let d_scalar = curve.scalar_field().from(d);
        let q = curve.generator() * d_scalar;
        let (qx, qy) = q.coordinates().unwrap();
        let mut pubkey = [0u8; 65];
        pubkey[0] = 0x04;
        pubkey[1..33].copy_from_slice(&qx.to_uint().to_be_bytes::<32>());
        pubkey[33..65].copy_from_slice(&qy.to_uint().to_be_bytes::<32>());

        let r_bytes = hex_literal::hex!(
            "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716"
        );
        let s_bytes = hex_literal::hex!(
            "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8"
        );
        let message_hash = hex_literal::hex!(
            "AF2BDBE1AA9B6EC1E2ADE1D694F41FC71A831D0268E9891562113D8A62ADD1BF"
        );

        // Build DER signature
        fn encode_integer(val: &[u8]) -> Vec<u8> {
            let mut out = vec![0x02];
            if val[0] & 0x80 != 0 { out.push((val.len() + 1) as u8); out.push(0x00); }
            else { out.push(val.len() as u8); }
            out.extend_from_slice(val);
            out
        }
        let r_enc = encode_integer(&r_bytes);
        let s_enc = encode_integer(&s_bytes);
        let mut sig_der = vec![0x30, (r_enc.len() + s_enc.len()) as u8];
        sig_der.extend_from_slice(&r_enc);
        sig_der.extend_from_slice(&s_enc);

        verify_ecdsa_p256_fast(&message_hash, &sig_der, &pubkey)?;
        Ok(())
    }
}
