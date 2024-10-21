/// Extendable output function. The pseudorandomness in SD-in-the-Head is generated through
/// an extendable output hash function (XOF). Such a function takes an arbitrary-long input bit-
/// string x ∈ {0, 1}∗ and produces an arbitrary-long output bit-string y ∈ {0, 1}∗ whose length is
/// tailored to the requirements of the application. Formally, a XOF is equipped with two routines:
/// XOF.Init(x) initializes the XOF state with the input x ∈ {0, 1}∗ . Once initialized, the XOF
/// can be queried with the routine XOF.GetByte() to generate the next byte of the output y
/// associated to x. The concrete instance of the XOF we use in the SD-in-the-Head scheme is given
/// in Section 4.5. In our context, we use the XOF as a secure pseudorandom generator (PRG)
/// which tolerates input seeds of variable lengths.
use tiny_keccak::{Hasher, IntoXof, KangarooTwelve, KangarooTwelveXof, Shake};

use crate::constants::params::{PARAM_DIGEST_SIZE, PARAM_SALT_SIZE, PARAM_SEED_SIZE};

pub(crate) fn xof_init(
    seed: &[u8; PARAM_SEED_SIZE],
    salt: Option<&[u8; PARAM_SALT_SIZE]>,
) -> KangarooTwelveXof {
    let mut hasher = KangarooTwelve::new([31u8]);

    if let Some(salt) = salt {
        hasher.update(salt);
    }
    hasher.update(seed);

    hasher.into_xof()
}

pub(crate) fn xof_init_base(x: &[u8]) -> KangarooTwelveXof {
    let mut hasher = KangarooTwelve::new([31u8]);

    hasher.update(x);
    hasher.into_xof()
}
