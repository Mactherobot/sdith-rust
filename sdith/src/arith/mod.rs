pub(crate) mod gf256;
pub(crate) mod matrices;

/// Calculate hamming weight of the given vector, which is the number of non-zero elements.
pub(crate) fn hamming_weight_vector(x: &[u8]) -> u64 {
    x.iter().fold(0, |a, b| a + (*b != 0) as u64)
}

/// Concatenate two arrays. Should be stable without experimental features.
/// https://users.rust-lang.org/t/concatenating-arrays/89538/3
pub(crate) fn concat_arrays_stable<T, const A: usize, const B: usize, const C: usize>(
    a: [T; A],
    b: [T; B],
) -> [T; C]
where
    T: Default,
{
    assert_eq!(A + B, C);
    let mut ary: [T; C] = std::array::from_fn(|_| Default::default());
    for (idx, val) in a.into_iter().chain(b.into_iter()).enumerate() {
        ary[idx] = val;
    }
    ary
}

pub(crate) fn split_array_stable<const A: usize, const B: usize, const C: usize>(
    a: [u8; A],
) -> [[u8; B]; C] {
    assert_eq!(A % B, 0);
    let mut split_array: [[u8; B]; C] = [[0; B]; C];
    for (i, val) in a.chunks(B).enumerate() {
        split_array[i] = val.try_into().expect("Invalid chunk size");
    }
    split_array
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_concat_arrays_stable() {
        let a = [1, 2, 3];
        let b = [4, 5, 6];
        let c = concat_arrays_stable(a, b);
        assert_eq!(c, [1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn test_split_array_stable() {
        let a = [1, 2, 3, 4, 5, 6];
        let b = split_array_stable(a);
        assert_eq!(b, [[1, 2, 3], [4, 5, 6]]);
    }
}
