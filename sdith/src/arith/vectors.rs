fn copy_from_vec_ptrs(src: &[u8], dst: &mut [u8]) {
    for i in 0..src.len() {
        dst[i] = src[i].clone();
    }
}

/// Copies and splits a vector of pointers into two arrays. The "Parse" function
pub(crate) fn vector_copy_into_2<const A: usize, const B: usize>(
    v: &[u8],
    out1: &mut [u8; A],
    out2: &mut [u8; B],
) {
    assert!(A + B == v.len());
    let mut offset = 0;
    copy_from_vec_ptrs(&v[offset..offset + A], out1);
    offset += A;
    copy_from_vec_ptrs(&v[offset..offset + B], out2);
}

/// Concatenates a list of vectors into a single vector. The "Parse" function
pub(crate) fn parse<const N: usize>(arrays: Vec<&[u8]>) -> [u8; N] {
    let mut result = Vec::new();
    assert!(arrays.iter().map(|a| a.len()).sum::<usize>() == N);
    for array in arrays {
        result.extend_from_slice(array);
    }
    result.try_into().expect("Failed to parse vector")
}

/// Splits a vector into a list of vectors. The "Serialize" function
pub(crate) fn serialize<const N: usize>(array: &Vec<u8>, n_sizes: Vec<usize>) -> [Vec<u8>; N] {
    assert!(n_sizes.iter().sum::<usize>() == array.len());
    let mut result = Vec::with_capacity(N);
    let mut offset = 0;
    for size in n_sizes.iter() {
        result.push(array[offset..offset + size].to_vec());
        offset += size;
    }
    result.try_into().expect("Failed to serialize vector")
}

/// Concatenates a list of vectors into a single vector. The "Serialize" function
pub(crate) fn concat_vectors<const O: usize>(vectors: &[&[u8]]) -> [u8; O] {
    assert!(vectors.iter().map(|v| v.len()).sum::<usize>() == O);
    let mut result = Vec::with_capacity(O);
    for v in vectors {
        result.extend_from_slice(v);
    }
    result
        .as_slice()
        .try_into()
        .expect("Failed to concatenate vectors")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vector_copy_into_2() {
        let mut v: Vec<u8> = vec![1, 2, 3, 4, 5, 6];
        let mut out1 = [0; 2];
        let mut out2 = [0; 4];
        vector_copy_into_2(&v, &mut out1, &mut out2);
        assert_eq!(out1, [1, 2]);
        assert_eq!(out2, [3, 4, 5, 6]);

        v[0] = 10;
        assert_eq!(out1, [1, 2]);
    }

    #[test]
    fn test_vector_concat() {
        let v1 = [1, 2, 3];
        let v2 = [4, 5, 6];
        let v3 = [7, 8, 9];

        let result = concat_vectors(&[&v1, &v2, &v3]);
        assert_eq!(result, [1, 2, 3, 4, 5, 6, 7, 8, 9]);
    }

    #[test]
    fn test_parse() {
        let v1 = [1, 2, 3];
        let v2 = [4, 5, 6];
        let v3 = [7, 8, 9, 10];

        let result = parse::<10>(vec![&v1, &v2, &v3]);
        assert_eq!(result, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    }

    #[test]
    fn test_serialize() {
        let v = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
        let result = serialize::<3>(&v, vec![3, 4, 2]);

        assert_eq!(result.len(), 3);
        assert_eq!(result[0], [1, 2, 3]);
        assert_eq!(result[1], [4, 5, 6, 7]);
        assert_eq!(result[2], [8, 9]);
    }
}
