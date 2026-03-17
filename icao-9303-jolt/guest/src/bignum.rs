//! Bignum arithmetic for advice-based RSA modular exponentiation verification.
//!
//! Uses little-endian u64 limb representation (matches ruint's internal layout).
//! Only 2048-bit operations are implemented (32 u64 limbs).
//!
//! The guest never computes modexp directly — the host provides (quotient, remainder)
//! via advice for each step. The guest verifies: a*b == q*n + r AND r < n.

const N: usize = 32; // 2048 bits / 64 bits per limb
const W: usize = 64; // 2 * N for wide (4096-bit) products

/// Schoolbook multiply: a * b -> 4096-bit result.
/// 1024 u64×u64 multiplications.
fn mul_wide(a: &[u64; N], b: &[u64; N]) -> [u64; W] {
    let mut result = [0u64; W];
    for i in 0..N {
        let mut carry: u64 = 0;
        for j in 0..N {
            let prod = (a[i] as u128) * (b[j] as u128) + (result[i + j] as u128) + (carry as u128);
            result[i + j] = prod as u64;
            carry = (prod >> 64) as u64;
        }
        result[i + N] = carry;
    }
    result
}

/// Squaring with symmetry: a * a -> 4096-bit result.
/// Off-diagonal products a[i]*a[j] (i<j) appear twice, so compute once and double.
/// 528 multiplications vs 1024 for generic multiply (32 diagonal + 496 cross).
fn square_wide(a: &[u64; N]) -> [u64; W] {
    let mut result = [0u64; W];

    // Off-diagonal products: accumulate a[i]*a[j] for i < j
    for i in 0..N {
        let mut carry: u64 = 0;
        for j in (i + 1)..N {
            let prod = (a[i] as u128) * (a[j] as u128) + (result[i + j] as u128) + (carry as u128);
            result[i + j] = prod as u64;
            carry = (prod >> 64) as u64;
        }
        result[i + N] = carry;
    }

    // Double the off-diagonal sum (each cross-term appears twice)
    let mut carry: u64 = 0;
    for r in result.iter_mut() {
        let doubled = (*r as u128) * 2 + (carry as u128);
        *r = doubled as u64;
        carry = (doubled >> 64) as u64;
    }

    // Add diagonal products: a[i]*a[i] at positions result[2*i]
    let mut carry: u64 = 0;
    for i in 0..N {
        let prod = (a[i] as u128) * (a[i] as u128) + (result[2 * i] as u128) + (carry as u128);
        result[2 * i] = prod as u64;
        carry = (prod >> 64) as u64;
        let sum = (result[2 * i + 1] as u128) + (carry as u128);
        result[2 * i + 1] = sum as u64;
        carry = (sum >> 64) as u64;
    }

    result
}

/// Check that wide == base + ext, i.e. a*b == q*n + r.
fn verify_sum_eq(wide: &[u64; W], base: &[u64; W], ext: &[u64; N]) -> bool {
    let mut carry: u64 = 0;
    for i in 0..W {
        let ext_val = if i < N { ext[i] } else { 0 };
        let (s1, c1) = base[i].overflowing_add(ext_val);
        let (s2, c2) = s1.overflowing_add(carry);
        if s2 != wide[i] {
            return false;
        }
        carry = c1 as u64 + c2 as u64;
    }
    carry == 0
}

/// Verify a*b == q*n + r (modular multiplication).
pub fn verify_modmul(
    a: &[u64; N],
    b: &[u64; N],
    q: &[u64; N],
    n: &[u64; N],
    r: &[u64; N],
) -> bool {
    let ab = mul_wide(a, b);
    let qn = mul_wide(q, n);
    verify_sum_eq(&ab, &qn, r)
}

/// Verify a^2 == q*n + r (modular squaring, uses symmetry optimization).
pub fn verify_modsquare(
    a: &[u64; N],
    q: &[u64; N],
    n: &[u64; N],
    r: &[u64; N],
) -> bool {
    let a2 = square_wide(a);
    let qn = mul_wide(q, n);
    verify_sum_eq(&a2, &qn, r)
}

/// a < b (little-endian limb comparison).
pub fn lt(a: &[u64; N], b: &[u64; N]) -> bool {
    for i in (0..N).rev() {
        if a[i] < b[i] {
            return true;
        }
        if a[i] > b[i] {
            return false;
        }
    }
    false
}
