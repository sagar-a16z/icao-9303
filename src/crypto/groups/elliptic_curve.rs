use {
    super::{
        super::mod_ring::{ModRing, ModRingElementRef, RingRefExt, UintExp, UintMont},
        CryptoGroup,
    },
    anyhow::{ensure, Result},
    num_traits::Inv,
    std::{
        fmt::{self, Debug, Formatter},
        ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign},
    },
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq},
};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct EllipticCurve<U: UintMont> {
    base_field:      ModRing<U>,
    scalar_field:    ModRing<U>,
    a_monty:         U,
    b_monty:         U,
    cofactor:        U,
    generator_monty: (U, U),
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EllipticCurvePoint<'a, U: UintMont> {
    curve:       &'a EllipticCurve<U>,
    coordinates: Coordinates<'a, U>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Coordinates<'a, U: UintMont> {
    Infinity,
    Affine(ModRingElementRef<'a, U>, ModRingElementRef<'a, U>),
}

impl<U: UintMont> EllipticCurve<U> {
    pub fn new(modulus: U, a: U, b: U, x: U, y: U, order: U, cofactor: U) -> Result<Self> {
        let curve = Self::new_unchecked(modulus, a, b, x, y, order, cofactor)?;

        // Ensure generator has order `order` (expensive: full scalar multiply)
        let generator = curve.generator();
        ensure!(
            generator.mul_uint(order) == curve.infinity(),
            "Generator order mismatch"
        );

        Ok(curve)
    }

    /// Construct a curve without verifying that the generator has the claimed order.
    ///
    /// Use this for known curves with hardcoded parameters (NIST P-256, etc.)
    /// to avoid an expensive scalar multiplication at construction time.
    pub fn new_unchecked(modulus: U, a: U, b: U, x: U, y: U, order: U, cofactor: U) -> Result<Self> {
        ensure!(a < modulus, "a not in field");
        ensure!(b < modulus, "b not in field");
        ensure!(x < modulus, "x not in field");
        ensure!(y < modulus, "y not in field");
        let base_field = ModRing::from_modulus(modulus);
        let scalar_field = ModRing::from_modulus(order);
        let a = base_field.from(a);
        let b = base_field.from(b);
        let x = base_field.from(x);
        let y = base_field.from(y);

        // Ensure non-singular
        let c4 = base_field.from_u64(4);
        let c27 = base_field.from_u64(27);
        ensure!(
            c4 * a.pow(3) + c27 * b.pow(2) != base_field.zero(),
            "Singular curve"
        );

        // Ensure not anomalous
        ensure!(modulus != order, "Anomalous curve");

        // Ensure generator is on curve
        ensure!(y.pow(2) == x.pow(3) + a * x + b, "Generator not on curve");

        Ok(Self {
            base_field,
            scalar_field,
            a_monty: a.as_montgomery(),
            b_monty: b.as_montgomery(),
            cofactor,
            generator_monty: (x.as_montgomery(), y.as_montgomery()),
        })
    }

    pub const fn base_field(&self) -> &ModRing<U> {
        &self.base_field
    }

    pub const fn scalar_field(&self) -> &ModRing<U> {
        &self.scalar_field
    }

    pub fn a(&self) -> ModRingElementRef<'_, U> {
        self.base_field.from_montgomery(self.a_monty)
    }

    pub fn b(&self) -> ModRingElementRef<'_, U> {
        self.base_field.from_montgomery(self.b_monty)
    }

    pub const fn cofactor(&self) -> U {
        self.cofactor
    }

    pub fn generator(&self) -> EllipticCurvePoint<'_, U> {
        EllipticCurvePoint {
            curve:       self,
            coordinates: Coordinates::Affine(
                self.base_field.from_montgomery(self.generator_monty.0),
                self.base_field.from_montgomery(self.generator_monty.1),
            ),
        }
    }

    /// Point at infinity
    pub const fn infinity(&self) -> EllipticCurvePoint<'_, U> {
        EllipticCurvePoint {
            curve:       self,
            coordinates: Coordinates::Infinity,
        }
    }

    pub fn from_affine<'a>(
        &'a self,
        x: ModRingElementRef<'a, U>,
        y: ModRingElementRef<'a, U>,
    ) -> Result<EllipticCurvePoint<'a, U>> {
        self.ensure_valid(x, y)?;
        Ok(EllipticCurvePoint {
            curve:       self,
            coordinates: Coordinates::Affine(x, y),
        })
    }

    /// Returns a point with x-coordinate `x` if it exists.
    /// If a solution `p` exists, the other solution is `-p`.
    pub fn from_x<'a>(&'a self, x: ModRingElementRef<'a, U>) -> Option<EllipticCurvePoint<'a, U>> {
        assert_eq!(x.ring(), &self.base_field);
        let y2 = x.pow(3) + self.a() * x + self.b();
        let y = y2.sqrt()?;
        Some(EllipticCurvePoint {
            curve:       self,
            coordinates: Coordinates::Affine(x, y),
        })
    }

    pub fn from_montgomery(
        &self,
        coordinates: Option<(U, U)>,
    ) -> Result<EllipticCurvePoint<'_, U>> {
        match coordinates {
            Some((x, y)) => self.from_affine(
                self.base_field.from_montgomery(x),
                self.base_field.from_montgomery(y),
            ),
            None => Ok(self.infinity()),
        }
    }

    fn ensure_valid<'a>(
        &'a self,
        x: ModRingElementRef<'a, U>,
        y: ModRingElementRef<'a, U>,
    ) -> Result<()> {
        ensure!(x.ring() == &self.base_field);
        ensure!(y.ring() == &self.base_field);

        // Check curve equation y^2 = x^3 + ax + b
        ensure!(
            y.pow(2) == x.pow(3) + self.a() * x + self.b(),
            "Point not on curve."
        );

        if self.cofactor() != U::from_u64(1) {
            let point = EllipticCurvePoint {
                curve:       self,
                coordinates: Coordinates::Affine(x, y),
            };
            ensure!(
                point.mul_uint(self.scalar_field().modulus()) == self.infinity(),
                "Point not in subgroup."
            );
        }
        Ok(())
    }
}

impl<'a, U: UintMont> EllipticCurvePoint<'a, U> {
    pub const fn curve(&self) -> &'a EllipticCurve<U> {
        self.curve
    }

    pub const fn as_monty(&self) -> Option<(U, U)> {
        match self.coordinates {
            Coordinates::Infinity => None,
            Coordinates::Affine(x, y) => Some((x.as_montgomery(), y.as_montgomery())),
        }
    }

    pub const fn coordinates(
        &self,
    ) -> Option<(ModRingElementRef<'a, U>, ModRingElementRef<'a, U>)> {
        match self.coordinates {
            Coordinates::Infinity => None,
            Coordinates::Affine(x, y) => Some((x, y)),
        }
    }

    pub const fn x(&self) -> Option<ModRingElementRef<'a, U>> {
        match self.coordinates {
            Coordinates::Infinity => None,
            Coordinates::Affine(x, _) => Some(x),
        }
    }

    pub const fn y(&self) -> Option<ModRingElementRef<'a, U>> {
        match self.coordinates {
            Coordinates::Infinity => None,
            Coordinates::Affine(_, y) => Some(y),
        }
    }

    /// Scalar multiplication using Jacobian projective coordinates.
    ///
    /// Instead of affine coords (x, y) with a field inversion per point op,
    /// Jacobian coords (X, Y, Z) where x=X/Z², y=Y/Z³ use only field
    /// multiplications. Single inversion at the end to convert back to affine.
    ///
    /// Variable-time (branches on scalar bits). Fine for signature verification
    /// and ZK guests where side-channel resistance is irrelevant.
    fn mul_uint<W: UintExp>(self, scalar: W) -> Self {
        let (px, py) = match self.coordinates {
            Coordinates::Infinity => return self.curve.infinity(),
            Coordinates::Affine(x, y) => (x, y),
        };

        let field = self.curve.base_field();
        let a = self.curve.a();
        let c2 = field.from_u64(2);
        let c3 = field.from_u64(3);
        let c4 = field.from_u64(4);
        let c8 = field.from_u64(8);

        // Jacobian doubling: (X1,Y1,Z1) -> (X3,Y3,Z3)
        // https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#doubling-dbl-2007-bl
        #[inline(always)]
        fn jac_double<'a, U: UintMont>(
            x1: ModRingElementRef<'a, U>, y1: ModRingElementRef<'a, U>, z1: ModRingElementRef<'a, U>,
            a: ModRingElementRef<'a, U>,
            c2: ModRingElementRef<'a, U>, c4: ModRingElementRef<'a, U>, c8: ModRingElementRef<'a, U>,
        ) -> (ModRingElementRef<'a, U>, ModRingElementRef<'a, U>, ModRingElementRef<'a, U>) {
            let xx = x1 * x1;
            let yy = y1 * y1;
            let yyyy = yy * yy;
            let zz = z1 * z1;
            let s = c2 * ((x1 + yy) * (x1 + yy) - xx - yyyy);
            let m = c2 * xx + xx + a * (zz * zz); // 3*XX + a*ZZ²
            let t = m * m - c2 * s;
            let x3 = t;
            let y3 = m * (s - t) - c8 * yyyy;
            let z3 = (y1 + z1) * (y1 + z1) - yy - zz;
            (x3, y3, z3)
        }

        // Jacobian addition: (X1,Y1,Z1) + (X2,Y2,Z2) -> (X3,Y3,Z3)
        // https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#addition-add-2007-bl
        // Returns (X3, Y3, Z3, is_infinity)
        #[inline(always)]
        fn jac_add<'a, U: UintMont>(
            x1: ModRingElementRef<'a, U>, y1: ModRingElementRef<'a, U>, z1: ModRingElementRef<'a, U>,
            x2: ModRingElementRef<'a, U>, y2: ModRingElementRef<'a, U>, z2: ModRingElementRef<'a, U>,
            a: ModRingElementRef<'a, U>,
            c2: ModRingElementRef<'a, U>, c4: ModRingElementRef<'a, U>, c8: ModRingElementRef<'a, U>,
        ) -> (ModRingElementRef<'a, U>, ModRingElementRef<'a, U>, ModRingElementRef<'a, U>, bool) {
            let z1z1 = z1 * z1;
            let z2z2 = z2 * z2;
            let u1 = x1 * z2z2;
            let u2 = x2 * z1z1;
            let s1 = y1 * z2 * z2z2;
            let s2 = y2 * z1 * z1z1;
            let h = u2 - u1;
            let r = c2 * (s2 - s1);

            if h.to_uint() == U::from_u64(0) {
                if r.to_uint() == U::from_u64(0) {
                    // Points are equal — double instead
                    let (x3, y3, z3) = jac_double(x1, y1, z1, a, c2, c4, c8);
                    return (x3, y3, z3, false);
                } else {
                    // Points are inverses — result is infinity
                    let zero = z1 - z1; // get a zero element with the right lifetime
                    return (zero, zero, zero, true);
                }
            }

            let i = c4 * h * h;
            let j = h * i;
            let v = u1 * i;
            let x3 = r * r - j - c2 * v;
            let y3 = r * (v - x3) - c2 * s1 * j;
            let z3 = ((z1 + z2) * (z1 + z2) - z1z1 - z2z2) * h;
            (x3, y3, z3, false)
        }

        // ── Scalar multiply using Jacobian double-and-add ───────────────
        // Base point in Jacobian: (x, y, 1)
        let mut bx = px;
        let mut by = py;
        let mut bz = field.one();

        // Result starts at infinity
        let mut rx = field.zero();
        let mut ry = field.one();
        let mut rz = field.zero();
        let mut r_inf = true;

        for i in 0..scalar.bit_len() {
            if bool::from(scalar.bit_ct(i)) {
                if r_inf {
                    rx = bx;
                    ry = by;
                    rz = bz;
                    r_inf = false;
                } else {
                    let (nx, ny, nz, is_inf) = jac_add(rx, ry, rz, bx, by, bz, a, c2, c4, c8);
                    if is_inf {
                        r_inf = true;
                    } else {
                        rx = nx;
                        ry = ny;
                        rz = nz;
                    }
                }
            }
            // Double the base
            let (nx, ny, nz) = jac_double(bx, by, bz, a, c2, c4, c8);
            bx = nx;
            by = ny;
            bz = nz;
        }

        if r_inf {
            return self.curve.infinity();
        }

        // Convert Jacobian → Affine: x = X/Z², y = Y/Z³
        let z_inv = rz.inv().expect("Z should be nonzero for non-infinity point");
        let z_inv2 = z_inv * z_inv;
        let z_inv3 = z_inv2 * z_inv;
        let ax = rx * z_inv2;
        let ay = ry * z_inv3;

        EllipticCurvePoint {
            curve: self.curve,
            coordinates: Coordinates::Affine(ax, ay),
        }
    }
}

macro_rules! forward_fmt {
    ($($trait:path),+) => {
        $(
            impl<'a, U: UintMont + $trait> $trait for EllipticCurvePoint<'a, U> {
                fn fmt(&self, f: &mut Formatter) -> fmt::Result {
                    match self.coordinates {
                        Coordinates::Infinity => write!(f, "Infinity"),
                        Coordinates::Affine(x, y) => {
                            write!(f, "(")?;
                            <ModRingElementRef<'_, U> as $trait>::fmt(&x, f)?;
                            write!(f, ", ")?;
                            <ModRingElementRef<'_, U> as $trait>::fmt(&y, f)?;
                            write!(f, ")")
                        }
                    }
                }
            }
        )+
    };
}

forward_fmt!(
    fmt::Debug,
    fmt::Display,
    fmt::Binary,
    fmt::Octal,
    fmt::LowerHex,
    fmt::UpperHex
);

impl<U: UintMont> Add for EllipticCurvePoint<'_, U> {
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        assert_eq!(self.curve, other.curve);
        // TODO: Use constant time inversions
        match (self.coordinates, other.coordinates) {
            (Coordinates::Infinity, _) => other,
            (_, Coordinates::Infinity) => self,
            (Coordinates::Affine(x1, y1), Coordinates::Affine(x2, y2)) => {
                // https://hyperelliptic.org/EFD/g1p/auto-shortw.html
                if x1 == x2 {
                    if y1 == y2 {
                        // Point doubling
                        let lambda = (self.curve.base_field.from_u64(3) * x1.pow(2)
                            + self.curve.a())
                            / (self.curve.base_field.from_u64(2) * y1);
                        let lambda = lambda.unwrap();
                        let x3 = lambda.pow(2) - self.curve.base_field.from_u64(2) * x1;
                        let y3 = lambda * (x1 - x3) - y1;
                        EllipticCurvePoint {
                            curve:       self.curve,
                            coordinates: Coordinates::Affine(x3, y3),
                        }
                    } else {
                        // Point at infinity
                        self.curve.infinity()
                    }
                } else {
                    let lambda = (y2 - y1) / (x2 - x1);
                    let lambda = lambda.unwrap();
                    let x3 = lambda.pow(2) - x1 - x2;
                    let y3 = lambda * (x1 - x3) - y1;
                    self.curve.from_affine(x3, y3).unwrap()
                }
            }
        }
    }
}

impl<U: UintMont> AddAssign for EllipticCurvePoint<'_, U> {
    fn add_assign(&mut self, other: Self) {
        *self = *self + other;
    }
}

impl<U: UintMont> Neg for EllipticCurvePoint<'_, U> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        match self.coordinates {
            Coordinates::Infinity => self,
            Coordinates::Affine(x, y) => EllipticCurvePoint {
                curve:       self.curve,
                coordinates: Coordinates::Affine(x, -y),
            },
        }
    }
}

impl<U: UintMont> Sub for EllipticCurvePoint<'_, U> {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, other: Self) -> Self::Output {
        self + other.neg()
    }
}

impl<U: UintMont> SubAssign for EllipticCurvePoint<'_, U> {
    fn sub_assign(&mut self, other: Self) {
        *self = *self - other;
    }
}

impl<'a, U: UintMont> Mul<ModRingElementRef<'a, U>> for EllipticCurvePoint<'a, U> {
    type Output = Self;

    fn mul(self, scalar: ModRingElementRef<'a, U>) -> Self::Output {
        assert_eq!(scalar.ring(), self.curve.scalar_field());
        self.mul_uint(scalar.to_uint())
    }
}

impl<'a, U: UintMont> MulAssign<ModRingElementRef<'a, U>> for EllipticCurvePoint<'a, U> {
    fn mul_assign(&mut self, scalar: ModRingElementRef<'a, U>) {
        *self = *self * scalar;
    }
}

impl<'a, U: UintMont> Div<ModRingElementRef<'a, U>> for EllipticCurvePoint<'a, U> {
    type Output = Option<Self>;

    fn div(self, scalar: ModRingElementRef<'a, U>) -> Self::Output {
        scalar.inv().map(|inv| self * inv)
    }
}

impl<'a, U: UintMont> DivAssign<ModRingElementRef<'a, U>> for EllipticCurvePoint<'a, U> {
    fn div_assign(&mut self, scalar: ModRingElementRef<'a, U>) {
        *self = self.div(scalar).expect("Element is not invertible");
    }
}

/// Conditionally select an Elliptic Curve Point
///
/// Note: Points must have identical representation (Infinity / Affine) for
/// constant-time.
///
/// # Panics
///
/// Panics if the points are not on the same curve
impl<'a, U: UintMont> ConditionallySelectable for EllipticCurvePoint<'a, U> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        assert_eq!(a.curve, b.curve);
        use Coordinates::*;
        let coordinates = match (&a.coordinates, &b.coordinates) {
            (Infinity, Infinity) => Infinity,
            (Affine(ax, ay), Affine(bx, by)) => Affine(
                ModRingElementRef::<'a, U>::conditional_select(ax, bx, choice),
                ModRingElementRef::<'a, U>::conditional_select(ay, by, choice),
            ),
            (a, b) => {
                if bool::from(choice) {
                    *b
                } else {
                    *a
                }
            }
        };
        Self {
            curve: a.curve,
            coordinates,
        }
    }
}

/// Constant time coordinate equality check.
///
/// Warning: Only constant time in coordinates, not in Infinity / Affine cases
/// distinction.
///
/// # Panics
///
/// Panics if the points are not on the same curve
impl<U: UintMont> ConstantTimeEq for EllipticCurvePoint<'_, U> {
    fn ct_eq(&self, other: &Self) -> Choice {
        use Coordinates::*;
        assert_eq!(self.curve, other.curve);
        match (&self.coordinates, &other.coordinates) {
            (Infinity, Infinity) => Choice::from(1),
            (Affine(ax, ay), Affine(bx, by)) => ax.ct_eq(bx) & ay.ct_eq(by),
            _ => Choice::from(0),
        }
    }
}

impl<'a, U: 'a + UintMont> CryptoGroup<'a> for EllipticCurve<U> {
    type BaseElement = EllipticCurvePoint<'a, U>;
    type ScalarElement = ModRingElementRef<'a, U>;

    fn generator(&'a self) -> Self::BaseElement {
        self.generator()
    }

    fn random_scalar(&'a self, rng: &mut dyn super::CryptoCoreRng) -> Self::ScalarElement {
        self.scalar_field().random(rng)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        named::{
            brainpool_p160r1, brainpool_p512r1, secp192r1, secp224r1, secp256r1, secp384r1,
            secp521r1,
        },
        test_dh, test_schnorr,
    };

    #[test]
    fn test_secp192r1() {
        let group = secp192r1();
        test_dh(&group);
        test_schnorr(&group);
    }

    #[test]
    fn test_secp224r1() {
        let group = secp224r1();
        test_dh(&group);
        test_schnorr(&group);
    }

    #[test]
    fn test_secp256r1() {
        let group = secp256r1();
        test_dh(&group);
        test_schnorr(&group);
    }

    #[test]
    fn test_secp384r1() {
        let group = secp384r1();
        test_dh(&group);
        test_schnorr(&group);
    }

    #[test]
    fn test_secp521r1() {
        let group = secp521r1();
        test_dh(&group);
        test_schnorr(&group);
    }

    #[test]
    fn test_brainpool_p160r1() {
        let group = brainpool_p160r1();
        test_dh(&group);
        test_schnorr(&group);
    }

    #[test]
    fn test_brainpool_brainpool_p512r1() {
        let group = brainpool_p512r1();
        test_dh(&group);
        test_schnorr(&group);
    }
}
