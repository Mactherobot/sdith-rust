use crate::subroutines::prg::PRG;

pub mod gf256_arith;
pub mod gf256_ext;
pub mod gf256_matrices;
pub mod gf256_poly;
pub mod gf256_vector;

/// TODO: Write documentation in the trait.
pub trait FieldArith
where
    Self: Sized + Clone + Copy + PartialEq,
{
    fn field_one() -> Self;
    fn field_zero() -> Self {
        Self::field_sub(&Self::field_one(), Self::field_one())
    }
    fn field_add(&self, rhs: Self) -> Self;
    fn field_sub(&self, rhs: Self) -> Self;
    fn field_neg(&self) -> Self;
    fn field_mul(&self, rhs: Self) -> Self;
    fn field_mul_inverse(&self) -> Self;
    fn field_div(&self, rhs: Self) -> Self
    where
        Self: Sized,
    {
        if rhs == Self::field_zero() {
            panic!("Division by zero");
        }
        self.field_mul(rhs.field_mul_inverse())
    }

    fn field_pow(&self, exp: u8) -> Self {
        let mut acc = Self::field_one();
        for _ in 0..exp {
            acc = Self::field_mul(&acc, *self);
        }
        acc
    }

    /// Evaluate a polynomial at the point `self` using Horner's method.
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

    fn field_add_mut(&mut self, rhs: Self) {
        *self = self.field_add(rhs);
    }

    fn field_sub_mut(&mut self, rhs: Self) {
        *self = self.field_sub(rhs);
    }

    fn field_mul_mut(&mut self, rhs: Self) {
        *self = self.field_mul(rhs);
    }

    fn field_sample(prg: &mut PRG) -> Self;
}

/// A thorough test for properties in the extended fields
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
    assert_eq!(a.field_add(T::field_zero()), a);
    assert_eq!(a.field_mul(T::field_one()), a);

    // Inverse of addition and multiplication:
    assert_eq!(a.field_sub(a), T::field_zero());
    // assert_eq!(a.field_mul(b).field_div(b), a); // Division not implemented

    // Distributivity of multiplication over addition:
    assert_eq!(
        a.field_mul(b.field_add(c)),
        a.field_mul(b).field_add(a.field_mul(c))
    );

    // Negation
    assert_eq!(b.field_add(a.field_neg()), b.field_sub(a));
}
