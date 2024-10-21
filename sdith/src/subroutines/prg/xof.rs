/// Extendable output function. The pseudorandomness in SD-in-the-Head is generated through
/// an extendable output hash function (XOF). Such a function takes an arbitrary-long input bit-
/// string x ∈ {0, 1}∗ and produces an arbitrary-long output bit-string y ∈ {0, 1}∗ whose length is
/// tailored to the requirements of the application. Formally, a XOF is equipped with two routines:
/// XOF.Init(x) initializes the XOF state with the input x ∈ {0, 1}∗ . Once initialized, the XOF
/// can be queried with the routine XOF.GetByte() to generate the next byte of the output y
/// associated to x. The concrete instance of the XOF we use in the SD-in-the-Head scheme is given
/// in Section 4.5. In our context, we use the XOF as a secure pseudorandom generator (PRG)
/// which tolerates input seeds of variable lengths.
use tiny_keccak::{Hasher, Shake};

use crate::constants::params::{PARAM_SALT_SIZE, PARAM_SEED_SIZE};

fn get_hasher() -> Shake {
    Shake::v128()
}

pub(crate) fn xof_init(
    seed: &[u8; PARAM_SEED_SIZE],
    salt: Option<&[u8; PARAM_SALT_SIZE]>,
) -> Shake {
    let mut xof = get_hasher();
    if let Some(salt) = salt {
        xof.update(salt);
    }
    xof.update(seed);
    xof
}

pub(crate) fn xof_init_base(x: &[u8]) -> Shake {
    let mut xof = get_hasher();
    xof.update(x);
    xof
}

#[cfg(test)]
mod xof_tests {
    use tiny_keccak::Xof;

    use crate::constants::types::Hash;

    use super::*;
    #[test]
    fn test_xof_correct_reference_impl() {
        let h2: Hash = [
            253, 110, 109, 150, 126, 122, 237, 98, 46, 235, 26, 232, 204, 57, 25, 230, 165, 176,
            207, 174, 32, 137, 6, 253, 110, 92, 165, 196, 229, 37, 219, 3,
        ];
        let mut xof = xof_init_base(&h2);

        let correct = [119u8, 105];
        let mut out = [0u8; 2];
        xof.squeeze(&mut out);
        assert_eq!(out, correct);
    }
}
