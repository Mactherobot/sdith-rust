// ----------------------- Vector operations -----------------------

#[cfg(feature = "simd")]
use std::simd::{num::SimdUint, u8x32};

use super::{gf256_arith::gf256_add, FieldArith};

#[cfg(not(feature = "simd"))]
/// vz'[] = vz[] + vx[]
pub(crate) fn gf256_add_vector(vz: &mut [u8], vx: &[u8]) {
    assert!(vx.len() >= vz.len());
    let bytes = vz.len();
    for i in 0..bytes {
        vz[i] = gf256_add(vz[i], vx[i]);
    }
}

#[cfg(not(feature = "simd"))]
/// vx'[] = vx[] * scalar
pub(crate) fn gf256_mul_vector_by_scalar(vx: &mut [u8], scalar: u8) {
    let bytes = vx.len();
    for i in 0..bytes {
        vx[i] = super::gf256_arith::gf256_mul(vx[i], scalar);
    }
}

#[cfg(not(feature = "simd"))]
/// vz'[] = vz[] * scalar + vx[]
pub(crate) fn gf256_add_vector_add_scalar(vz: &mut [u8], vx: &[u8], scalar: u8) {
    let bytes = vz.len();
    for i in 0..bytes {
        vz[i] = vx[i].field_add(vz[i].field_mul(scalar));
    }
}

#[cfg(feature = "simd")]
/// vz'[] = vz[] + vx[]
pub(crate) fn gf256_add_vector(vz: &mut [u8], vx: &[u8]) {
    let chunk_size = 32;

    // Then go through the chunks using SIMD
    // using the gf256_add_vector_add_scalar_simd_32 function
    let vz_chunks = vz.chunks_mut(chunk_size);
    let mut vx_chunks = vx.chunks(chunk_size);

    for vz_chunk in vz_chunks {
        let vx_chunk = vx_chunks.next().unwrap();
        if vz_chunk.len() < chunk_size {
            for i in 0..vz_chunk.len() {
                vz_chunk[i] = vx_chunk[i].field_add(vz_chunk[i]);
            }

            break;
        }
        let mut vz_chunk_simd = u8x32::from_slice(vz_chunk);
        let vx_chunk = u8x32::from_slice(vx_chunk);
        // Perform the addition
        vz_chunk_simd ^= vx_chunk;
        vz_chunk.copy_from_slice(vz_chunk_simd.as_array());
    }
}

#[cfg(feature = "simd")]
/// vz'[] = vz[] * scalar + vx[]
pub(crate) fn gf256_mul_vector_by_scalar(vz: &mut [u8], scalar: u8) {
    let chunk_size = 32;

    // Then go through the chunks using SIMD
    // using the gf256_add_vector_add_scalar_simd_32 function
    let vz_chunks = vz.chunks_mut(chunk_size);
    let scalar_chunk = u8x32::splat(scalar);
    let one = u8x32::splat(1);
    let modulus = u8x32::splat(super::gf256_arith::MODULUS);

    for vz_chunk in vz_chunks {
        if vz_chunk.len() < chunk_size {
            for i in 0..vz_chunk.len() {
                vz_chunk[i] = vz_chunk[i].field_mul(scalar);
            }

            break;
        }
        let mut vz_chunk_simd = u8x32::from_slice(vz_chunk);
        {
            let vz: &mut u8x32 = &mut vz_chunk_simd;

            // Perform the multiplication
            let mut r = (scalar_chunk >> 7).wrapping_neg() & *vz;
            r = ((scalar_chunk >> 6 & one).wrapping_neg() & *vz)
                ^ ((r >> 7).wrapping_neg() & modulus)
                ^ (r + r);
            r = ((scalar_chunk >> 5 & one).wrapping_neg() & *vz)
                ^ ((r >> 7).wrapping_neg() & modulus)
                ^ (r + r);
            r = ((scalar_chunk >> 4 & one).wrapping_neg() & *vz)
                ^ ((r >> 7).wrapping_neg() & modulus)
                ^ (r + r);
            r = ((scalar_chunk >> 3 & one).wrapping_neg() & *vz)
                ^ ((r >> 7).wrapping_neg() & modulus)
                ^ (r + r);
            r = ((scalar_chunk >> 2 & one).wrapping_neg() & *vz)
                ^ ((r >> 7).wrapping_neg() & modulus)
                ^ (r + r);
            r = ((scalar_chunk >> 1 & one).wrapping_neg() & *vz)
                ^ ((r >> 7).wrapping_neg() & modulus)
                ^ (r + r);
            r = ((scalar_chunk & one).wrapping_neg() & *vz)
                ^ ((r >> 7).wrapping_neg() & modulus)
                ^ (r + r);

            // Perform the addition
            *vz = r;
        };
        vz_chunk.copy_from_slice(vz_chunk_simd.as_array());
    }
}
#[cfg(feature = "simd")]
/// vz'[] = vz[] * scalar + vx[]
pub(crate) fn gf256_add_vector_add_scalar(vz: &mut [u8], vx: &[u8], scalar: u8) {
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
    let one = u8x32::splat(1);
    let modulus = u8x32::splat(super::gf256_arith::MODULUS);

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
        {
            let vz: &mut u8x32 = &mut vz_chunk_simd;

            // Perform the multiplication
            let mut r = (scalar_chunk >> 7).wrapping_neg() & *vz;
            r = ((scalar_chunk >> 6 & one).wrapping_neg() & *vz)
                ^ ((r >> 7).wrapping_neg() & modulus)
                ^ (r + r);
            r = ((scalar_chunk >> 5 & one).wrapping_neg() & *vz)
                ^ ((r >> 7).wrapping_neg() & modulus)
                ^ (r + r);
            r = ((scalar_chunk >> 4 & one).wrapping_neg() & *vz)
                ^ ((r >> 7).wrapping_neg() & modulus)
                ^ (r + r);
            r = ((scalar_chunk >> 3 & one).wrapping_neg() & *vz)
                ^ ((r >> 7).wrapping_neg() & modulus)
                ^ (r + r);
            r = ((scalar_chunk >> 2 & one).wrapping_neg() & *vz)
                ^ ((r >> 7).wrapping_neg() & modulus)
                ^ (r + r);
            r = ((scalar_chunk >> 1 & one).wrapping_neg() & *vz)
                ^ ((r >> 7).wrapping_neg() & modulus)
                ^ (r + r);
            r = ((scalar_chunk & one).wrapping_neg() & *vz)
                ^ ((r >> 7).wrapping_neg() & modulus)
                ^ (r + r);

            // Perform the addition
            *vz = r ^ vx_chunk;
        };
        vz_chunk.copy_from_slice(vz_chunk_simd.as_array());
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
    fn test_gf256_add_vector_add_scalar() {
        let mut vz = [
            124, 219, 230, 229, 212, 149, 74, 252, 76, 136, 197, 12, 15, 249, 224, 215, 204, 20,
            13, 16, 99, 218, 131, 5, 19, 134, 77, 96, 135, 39, 86, 31, 41, 38, 158, 227, 65, 234,
            245, 1, 216, 230, 14, 52, 165, 128, 51, 130, 198, 142, 15, 214, 60, 237, 137, 251, 156,
            212, 186, 10, 127, 229, 188, 9, 63, 154, 213, 224, 189, 161, 163, 150, 128, 194, 61, 0,
            28, 98, 71, 229, 197, 101, 37, 94, 197, 148, 39, 114, 208, 102, 181, 163, 249, 115,
            235, 10, 249, 12, 88, 136, 218, 85, 255, 139, 96, 168, 187, 77, 197, 145, 196, 2, 254,
            131, 109, 224, 175, 142, 169, 60, 157, 108, 92, 80, 125, 171, 157, 140, 165, 92, 194,
            224, 68, 39, 151, 39, 65, 199, 198, 124, 54, 3, 240, 130, 109, 205, 106, 229, 11, 246,
            44, 152, 68, 81, 38, 77, 68, 86, 212, 158, 66, 202, 251, 16, 86, 1, 32, 98, 232, 130,
            168, 212, 44, 11, 138, 211, 44, 18, 220, 115, 166, 88, 185, 209, 169, 58, 22, 70, 18,
            45, 73, 40, 225, 54, 62, 208, 210, 31, 109, 206, 171, 239, 200, 153, 4, 118, 220, 77,
            190, 229, 159, 33, 108, 241, 113, 78, 149, 128, 91, 235, 49, 65, 149, 118, 168, 110,
            125, 95, 126, 71, 115, 215, 17, 227, 186, 132, 174, 39, 103, 38, 68, 169, 58, 68, 114,
            103, 212, 133, 216, 103, 70, 184, 219, 0, 226, 200, 146, 152, 161, 3, 69, 55, 153, 83,
            190, 255, 249, 112, 104, 171, 140, 114, 142, 133, 66, 151, 223, 190, 48, 102, 1, 163,
            165, 92, 105, 39, 159, 28, 114, 109, 18, 201, 175, 61, 11, 177, 183, 42, 129, 39, 133,
            99, 161, 71, 148, 120, 255, 133, 70, 27, 184, 79, 23, 80, 61, 115, 198, 106, 52, 172,
            8, 230, 15, 164, 85, 208, 63, 237, 251, 201, 225, 92, 64, 214, 99, 43, 78, 121, 86, 98,
            244, 216, 5, 99, 42, 184, 227, 154, 252, 250, 91, 56, 254, 255, 223, 119, 191, 110, 61,
            252, 150, 3, 246, 188, 44, 173, 183, 120, 54, 95, 241, 113, 202, 79, 76, 211, 249, 162,
            172, 15, 93, 194, 22, 248,
        ];
        let vx = [
            243, 32, 200, 245, 75, 79, 26, 154, 226, 149, 5, 120, 9, 219, 239, 25, 197, 38, 127,
            76, 89, 211, 165, 196, 60, 119, 229, 98, 119, 68, 83, 107, 151, 133, 74, 93, 178, 65,
            149, 9, 86, 169, 220, 250, 29, 3, 14, 171, 202, 46, 187, 189, 126, 152, 207, 40, 3,
            138, 193, 59, 128, 86, 75, 129, 219, 109, 89, 124, 191, 146, 40, 195, 242, 193, 170,
            125, 135, 102, 164, 138, 172, 60, 223, 31, 216, 167, 187, 209, 31, 37, 35, 71, 219,
            221, 113, 105, 30, 162, 217, 68, 115, 205, 29, 89, 85, 254, 17, 87, 75, 70, 97, 95,
            139, 126, 55, 168, 71, 154, 174, 12, 172, 74, 217, 74, 109, 50, 13, 20, 167, 137, 133,
            35, 31, 43, 143, 194, 49, 135, 52, 181, 235, 146, 48, 79, 203, 73, 104, 84, 135, 158,
            247, 4, 5, 225, 240, 60, 85, 87, 21, 7, 137, 255, 154, 161, 28, 45, 222, 119, 101, 227,
            192, 181, 254, 58, 240, 31, 175, 206, 206, 248, 37, 93, 204, 1, 205, 5, 17, 121, 252,
            55, 12, 176, 104, 39, 180, 187, 29, 170, 91, 48, 49, 40, 47, 60, 46, 16, 194, 160, 73,
            5, 138, 242, 65, 156, 9, 115, 105, 79, 123, 60, 71, 62, 169, 18, 195, 117, 41, 2, 148,
            247, 100, 71, 20, 172, 225, 111, 160, 105, 212, 197, 195, 88, 151, 106, 191, 21, 80,
            164, 106, 113, 93, 172, 197, 2, 205, 216, 64, 95, 5, 254, 189, 127, 89, 34, 29, 115,
            147, 117, 236, 78, 254, 148, 14, 154, 26, 114, 191, 119, 67, 200, 136, 139, 6, 154,
            103, 194, 8, 3, 44, 216, 232, 138, 207, 199, 211, 98, 181, 113, 46, 147, 167, 142, 161,
            232, 87, 234, 99, 119, 149, 133, 118, 255, 82, 160, 184, 80, 205, 29, 35, 227, 96, 43,
            186, 82, 144, 32, 95, 237, 83, 66, 177, 14, 176, 111, 21, 166, 44, 18, 190, 134, 144,
            176, 34, 251, 213, 214, 64, 139, 62, 43, 176, 99, 43, 41, 46, 90, 131, 192, 56, 88, 45,
            255, 125, 40, 27, 42, 116, 151, 1, 87, 81, 108, 221, 103, 214, 141, 213, 232, 61, 93,
            248, 117, 75, 40,
        ];
        let y = 128;

        gf256_add_vector_add_scalar(&mut vz, &vx, y);
        assert_eq!(
            vz,
            [
                151, 216, 153, 63, 114, 187, 32, 100, 245, 99, 100, 34, 200, 147, 147, 187, 72,
                200, 165, 148, 36, 171, 164, 114, 127, 192, 114, 132, 64, 66, 235, 114, 208, 3, 73,
                186, 127, 74, 135, 137, 53, 248, 157, 191, 154, 153, 230, 42, 48, 245, 122, 159,
                87, 62, 185, 123, 27, 179, 95, 76, 127, 156, 248, 109, 105, 88, 224, 0, 140, 35,
                130, 172, 104, 13, 3, 125, 5, 155, 68, 64, 205, 108, 194, 203, 185, 211, 189, 244,
                16, 238, 124, 237, 147, 120, 250, 30, 86, 248, 32, 178, 11, 238, 120, 52, 179, 163,
                15, 192, 42, 132, 128, 68, 110, 127, 11, 212, 183, 65, 115, 37, 52, 246, 22, 223,
                137, 244, 149, 212, 32, 70, 73, 95, 100, 45, 96, 196, 252, 253, 206, 209, 181, 9,
                148, 206, 247, 68, 249, 158, 112, 23, 6, 42, 126, 244, 118, 171, 46, 239, 44, 4,
                223, 95, 201, 121, 164, 173, 117, 138, 117, 98, 157, 140, 15, 205, 29, 139, 94, 13,
                155, 93, 57, 164, 201, 142, 16, 1, 228, 25, 63, 70, 173, 119, 148, 121, 134, 180,
                9, 179, 103, 166, 247, 149, 148, 146, 24, 3, 151, 55, 225, 207, 9, 217, 253, 184,
                183, 127, 157, 213, 25, 183, 180, 243, 93, 1, 158, 210, 205, 86, 235, 23, 193, 229,
                76, 75, 127, 195, 208, 111, 159, 67, 184, 133, 147, 17, 154, 94, 105, 136, 9, 58,
                61, 41, 61, 2, 170, 99, 25, 113, 180, 101, 70, 161, 247, 44, 181, 22, 219, 75, 102,
                136, 62, 177, 213, 182, 76, 157, 113, 223, 48, 3, 8, 33, 129, 85, 109, 196, 139,
                129, 9, 228, 43, 177, 63, 110, 36, 11, 241, 173, 52, 149, 139, 243, 16, 8, 35, 184,
                6, 91, 245, 170, 243, 115, 39, 53, 17, 245, 55, 140, 102, 136, 12, 122, 123, 85,
                179, 47, 237, 75, 0, 121, 77, 193, 253, 77, 104, 250, 32, 192, 6, 123, 2, 211, 148,
                134, 9, 83, 167, 190, 192, 248, 210, 124, 206, 76, 224, 201, 171, 103, 145, 166,
                66, 100, 244, 155, 234, 193, 48, 197, 95, 3, 117, 210, 125, 235, 193, 25, 157, 194,
                86, 156, 183, 185, 190, 224
            ]
        )
    }
}
