use {
    num_traits::{PrimInt, Unsigned},
    subtle::{Choice, ConstantTimeEq},
};

/// Trait for Uint backends that can be used for exponentiation.
pub trait UintExp {
    /// Returns an upper bound for the highest bit set.
    /// Ideally this should not depend on the value.
    fn bit_len(&self) -> usize;

    /// Is the `indext`th bit set in the binary expansion of `self`.
    fn bit_ct(&self, index: usize) -> Choice;
}

// Implementation that should work for most unsigned integers.
impl<T> UintExp for T
where
    T: PrimInt + Unsigned + ConstantTimeEq,
{
    fn bit_len(&self) -> usize {
        // With constant-time: always return the full type width so pow_ct
        // iterates the same number of rounds regardless of exponent value.
        // Without constant-time: return only the significant bits so pow_vt
        // skips leading-zero iterations.
        #[cfg(feature = "constant-time")]
        return T::zero().count_zeros() as usize;
        #[cfg(not(feature = "constant-time"))]
        return (T::zero().count_zeros() - self.leading_zeros()) as usize;
    }

    fn bit_ct(&self, index: usize) -> Choice {
        let bit = T::one() << index;
        (*self & bit).ct_eq(&bit)
    }
}
