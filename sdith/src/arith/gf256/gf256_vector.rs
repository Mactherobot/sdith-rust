// ----------------------- Vector operations -----------------------

use super::{
    gf256_arith::{gf256_add, gf256_mul},
    FieldArith,
};

/// vz'[] = vz[] + vx[]
pub(crate) fn gf256_add_vector(vz: &mut [u8], vx: &[u8]) {
    assert!(vx.len() >= vz.len());
    let bytes = vz.len();
    for i in 0..bytes {
        vz[i] = gf256_add(vz[i], vx[i]);
    }
}
/// vz'[] = vz[] + (vx[], 00000...)
pub(crate) fn gf256_add_vector_with_padding(vz: &mut [u8], vx: &[u8]) {
    assert!(vz.len() >= vx.len());
    let bytes = vx.len();
    for i in 0..bytes {
        vz[i] = gf256_add(vz[i], vx[i]);
    }
}

/// vx'[] = vx[] * scalar
pub(crate) fn gf256_mul_vector_by_scalar(vx: &mut [u8], scalar: u8) {
    let bytes = vx.len();
    for i in 0..bytes {
        vx[i] = gf256_mul(vx[i], scalar);
    }
}

/// vz'[] = vz[] + (vx[] * scalar)
pub(crate) fn gf256_add_vector_mul_scalar(vz: &mut [u8], vx: &[u8], scalar: u8) {
    let bytes = vz.len();
    for i in 0..bytes {
        vz[i] = gf256_add(vz[i], gf256_mul(vx[i], scalar));
    }
}

/// vz'[] = vz[] * scalar + vx[]
pub(crate) fn gf256_add_vector_add_scalar(vz: &mut [u8], vx: &[u8], scalar: u8) {
    let bytes = vz.len();
    for i in 0..bytes {
        vz[i] = vx[i].field_add(vz[i].field_mul(scalar));
    }
}

#[cfg(test)]
mod tests_vector_ops {
    use super::*;

    #[test]
    fn test_gf256_add_vector() {
        let mut vz = [0x01, 0x02, 0x03, 0x04];
        let vx = [0x05, 0x06, 0x07, 0x08];
        let expected = [0x04, 0x04, 0x04, 0x0C];

        gf256_add_vector(&mut vz, &vx);
        assert_eq!(vz, expected);
    }

    #[test]
    fn test_gf256_mul_vector_by_scalar() {
        let mut vz = [0x01, 0x02, 0x03, 0x04];
        let y = 0x05;
        let expected = [0x05, 0x0A, 0x0F, 0x14];

        gf256_mul_vector_by_scalar(&mut vz, y);
        assert_eq!(vz, expected);
    }

    #[test]
    fn test_gf256_add_vector_mul_scalar() {
        let mut vz = [0x01, 0x02, 0x03, 0x04];
        let vx = [0x05, 0x06, 0x07, 0x08];
        let y = 0x02;
        let binding = vz
            .iter()
            .enumerate()
            .map(|(i, z)| gf256_add(*z, gf256_mul(vx[i], y)))
            .collect::<Vec<u8>>();
        let expected = binding.as_slice();

        gf256_add_vector_mul_scalar(&mut vz, &vx, y);
        assert_eq!(vz, expected);
    }

    #[test]
    fn test_gf256_add_vector_with_padding() {
        let mut vz = [0x01, 0x02, 0x03, 0x04];
        let vx = [0x05, 0x06];
        let expected = [0x04, 0x04, 0x03, 0x04];

        gf256_add_vector_with_padding(&mut vz, &vx);
        assert_eq!(vz, expected);
    }
}
