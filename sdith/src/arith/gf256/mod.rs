//! # Galois Field 256 and extension fields
//!
//! The field is an implementation of Rijndael's finite field with 256 elements.
//! Includes Trait for field arithmetic operations and implementations for the field and extension fields.

use crate::subroutines::prg::PRG;

pub mod gf256_arith;
pub mod gf256_ext;
pub mod gf256_matrices;
pub mod gf256_poly;
pub mod gf256_vector;

/// Trait for field arithmetic operations
pub trait FieldArith
where
    Self: Sized + Clone + Copy + PartialEq,
{
    /// A field element with value 1.
    fn field_mul_identity() -> Self;

    /// A field element with value 0.
    fn field_add_identity() -> Self {
        Self::field_sub(&Self::field_mul_identity(), Self::field_mul_identity())
    }

    /// Sample a random field element from the [`PRG`]
    fn field_sample(prg: &mut PRG) -> Self;

    /// Field addition operation
    fn field_add(&self, rhs: Self) -> Self;

    /// Field subtraction operation
    fn field_sub(&self, rhs: Self) -> Self;

    /// Field negation operation
    fn field_neg(&self) -> Self;

    /// Field multiplication operation
    fn field_mul(&self, rhs: Self) -> Self;

    /// Field multiplicative inverse
    fn field_mul_inverse(&self) -> Self;

    /// Field division operation
    ///
    /// Division is implemented as multiplication by the multiplicative inverse.
    fn field_div(&self, rhs: Self) -> Self
    where
        Self: Sized,
    {
        if rhs == Self::field_add_identity() {
            panic!("Division by zero");
        }
        self.field_mul(rhs.field_mul_inverse())
    }

    /// Field exponentiation operation
    ///
    /// Exponentiation is implemented in naive form as repeated multiplication.
    fn field_pow(&self, exp: u8) -> Self {
        let mut acc = Self::field_mul_identity();
        for _ in 0..exp {
            acc = Self::field_mul(&acc, *self);
        }
        acc
    }

    /// Evaluate a polynomial at the point `self` using Horner's method.
    ///
    /// The polynomial is represented as a slice of field elements with the coefficients in increasing order.
    /// e.g. `poly[0] + poly[1]*x + poly[2]*x^2 + ... + poly[n]*x^n`
    fn field_eval_polynomial(&self, poly: &[Self]) -> Self {
        assert!(poly.len() > 0 && poly.len() < u32::MAX as usize);
        let degree = poly.len() - 1;
        let mut acc = poly[degree].clone();
        for i in (0..degree).rev() {
            acc = Self::field_mul(&acc, *self);
            acc = Self::field_add(&acc, poly[i]);
        }
        return acc;
    }

    /// Field addition operation with assignment
    fn field_add_mut(&mut self, rhs: Self) {
        *self = self.field_add(rhs);
    }

    /// Field subtraction operation with assignment
    fn field_sub_mut(&mut self, rhs: Self) {
        *self = self.field_sub(rhs);
    }

    /// Field multiplication operation with assignment
    fn field_mul_mut(&mut self, rhs: Self) {
        *self = self.field_mul(rhs);
    }
}

/// A test for the definition and properties required in the finite fields
#[cfg(test)]
pub(super) fn test_field_definitions<T>(a: T, b: T, c: T)
where
    T: FieldArith + std::fmt::Debug,
{
    // Commutativity of addition and multiplication:
    assert_eq!(a.field_add(b), b.field_add(a));
    assert_eq!(a.field_mul(b), b.field_mul(a));

    // Associativity of addition and multiplication:
    assert_eq!(a.field_add(b.field_add(c)), a.field_add(b).field_add(c));
    assert_eq!(a.field_mul(b.field_mul(c)), a.field_mul(b).field_mul(c));

    // Identity of addition and multiplication:
    assert_eq!(a.field_add(T::field_add_identity()), a);
    assert_eq!(a.field_mul(T::field_mul_identity()), a);

    // Inverse of addition and multiplication:
    assert_eq!(a.field_sub(a), T::field_add_identity());
    // assert_eq!(a.field_mul(b).field_div(b), a); // Division not implemented

    // Distributivity of multiplication over addition:
    assert_eq!(
        a.field_mul(b.field_add(c)),
        a.field_mul(b).field_add(a.field_mul(c))
    );

    // Negation
    assert_eq!(b.field_add(a.field_neg()), b.field_sub(a));
}
