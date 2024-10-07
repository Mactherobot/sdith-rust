use crate::subroutines::prg::prg::PRG;

pub(crate) mod gf256_arith;
pub(crate) mod gf256_ext;
pub(crate) mod gf256_poly;
pub(crate) mod gf256_vector;

/// TODO: Replace calls to gf256_* methods to use the FieldArith trait.
pub(crate) trait FieldArith
where
    Self: Sized + Clone + Copy + PartialEq,
{
    fn field_one() -> Self;
    fn field_zero() -> Self {
        Self::field_sub(&Self::field_one(), Self::field_one())
    }
    fn field_add(&self, rhs: Self) -> Self;
    fn field_sub(&self, rhs: Self) -> Self;
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
