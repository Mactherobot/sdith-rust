#[cfg(test)]
mod xof_tests {
    use crate::{constants::types::Hash, subroutines::prg::xof::xof_init_base};
    use tiny_keccak::Xof;

    #[test]
    fn test_xof_correct_reference_impl() {
        let h2: Hash = [
            253, 110, 109, 150, 126, 122, 237, 98, 46, 235, 26, 232, 204, 57, 25, 230, 165, 176,
            207, 174, 32, 137, 6, 253, 110, 92, 165, 196, 229, 37, 219, 3,
        ];
        let mut xof = xof_init_base(&h2);

        let correct = [224, 181];
        let mut out = [0u8; 2];
        xof.squeeze(&mut out);
        assert_eq!(out, correct);
    }

    #[test]
    fn test_vector() {
        // From https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/shakebytetestvectors.zip
        let msg = hex::decode("1b3b6e").unwrap();
        let output = hex::decode("d7335497e4cd3666885edbb0824d7a75").unwrap();
        println!("{:?}", msg);
        let mut xof = xof_init_base(&msg);
        let mut out = vec![0u8; output.len()];
        xof.squeeze(&mut out);

        println!("{:?}", out);
        assert_eq!(out, output);
    }
}
