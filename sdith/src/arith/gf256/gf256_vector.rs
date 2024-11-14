// ----------------------- Vector operations -----------------------

use std::simd::u8x32;

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

/// vz'[] = vz[] * scalar + vx[]
pub(crate) fn gf256_add_vector_add_scalar_chunked_simd(vz: &mut [u8], vx: &[u8], scalar: u8) {
    assert!(
        vz.len() == vx.len(),
        "Length of the two vectors must be the same"
    );
    let chunk_size = 32;

    // Then go through the chunks using SIMD
    // using the gf256_add_vector_add_scalar_simd_32 function
    let vz_chunks = vz.chunks_mut(chunk_size);
    let mut vx_chunks = vx.chunks(chunk_size);
    let scalar_chunk = u8x32::splat(scalar);

    for vz_chunk in vz_chunks {
        let vx_chunk = vx_chunks.next().unwrap();
        if vz_chunk.len() < chunk_size {
            for i in 0..vz_chunk.len() {
                vz_chunk[i] = vx_chunk[i].field_add(vz_chunk[i].field_mul(scalar));
            }

            break;
        }
        let mut vz_chunk_simd = u8x32::from_slice(vz_chunk);
        let vx_chunk = u8x32::from_slice(vx_chunk);
        println!("{:?}", vz_chunk_simd);
        gf256_add_vector_add_scalar_simd_32(&mut vz_chunk_simd, vx_chunk, scalar_chunk);
        vz_chunk.copy_from_slice(vz_chunk_simd.as_array());
    }
}

/// vz'[] = vz[] * scalar + vx[]
pub(crate) fn gf256_add_vector_add_scalar_simd_32(vz: &mut u8x32, vx: u8x32, scalar: u8x32) {
    *vz = (*vz * scalar) ^ vx;
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

    #[test]
    fn test_gf256_add_vector_add_scalar() {
        let mut vz = [0x03; 195];
        let mut vz_expected = [0x03; 195];
        for i in 0..195 {
            let value = 0x03 + i as u8;
            vz[i] = value;
            vz_expected[i] = value;
        }
        let vx = [0x05; 195];
        let y = 0x02;
        gf256_add_vector_add_scalar(&mut vz_expected, &vx, y);
        gf256_add_vector_add_scalar_chunked_simd(&mut vz, &vx, y);
        assert_eq!(vz, vz_expected);
        let mut vz = [0x03; 128];
        let mut vz_expected = [0x03; 128];
        let vx = [0x05; 128];
        let y = 0x02;
        gf256_add_vector_add_scalar(&mut vz_expected, &vx, y);
        gf256_add_vector_add_scalar_chunked_simd(&mut vz, &vx, y);
        assert_eq!(vz, vz_expected);
    }

    #[test]
    fn test_gf256_add_vector_add_scalar_simd_32() {
        let mut vz = u8x32::splat(0x03);
        let vx = u8x32::splat(0x05);
        let y = u8x32::splat(0x02);
        let expected = u8x32::splat(0x03);

        gf256_add_vector_add_scalar_simd_32(&mut vz, vx, y);
        assert_eq!(vz, expected);
    }
}
