use crate::subroutines::prg::prg::PRG;

mod addition_tests;
pub(crate) mod gf256_arith;
pub(crate) mod gf256_ext;
pub(crate) mod gf256_poly;
pub(crate) mod gf256_vector;
mod multiplication_tests;

pub(crate) trait FieldArith
where
    Self: Sized,
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
        self.field_mul(rhs.field_mul_inverse())
    }

    fn field_pow(&self, exp: u8) -> Self;
    fn field_eval_polynomial(&self, poly: &[Self]) -> Self;

    fn field_add_mut(&mut self, rhs: Self) {
        *self = self.field_add(rhs);
    }

    fn field_sub_mut(&mut self, rhs: Self) {
        *self = self.field_sub(rhs);
    }

    fn field_mul_mut(&mut self, rhs: Self) {
        *self = self.field_mul(rhs);
    }
}
