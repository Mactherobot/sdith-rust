use super::FieldArith;

struct GF251(u8);

impl FieldArith for GF251(u8) {
    fn field_mul_identity() -> Self {
        todo!()
    }

    fn field_sample(prg: &mut crate::subroutines::prg::PRG) -> Self {
        todo!()
    }

    fn field_add(&self, rhs: Self) -> Self {
        self.0 ^ rhs.0
    }

    fn field_sub(&self, rhs: Self) -> Self {
        todo!()
    }

    fn field_neg(&self) -> Self {
        todo!()
    }

    fn field_mul(&self, rhs: Self) -> Self {
        todo!()
    }

    fn field_mul_inverse(&self) -> Self {
        todo!()
    }
}