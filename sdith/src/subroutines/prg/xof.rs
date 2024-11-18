/// Extendable output function. The pseudorandomness in SD-in-the-Head is generated through
/// an extendable output hash function (XOF). Such a function takes an arbitrary-long input bit-
/// string x ∈ {0, 1}∗ and produces an arbitrary-long output bit-string y ∈ {0, 1}∗ whose length is
/// tailored to the requirements of the application. Formally, a XOF is equipped with two routines:
/// XOF.Init(x) initializes the XOF state with the input x ∈ {0, 1}∗ . Once initialized, the XOF
/// can be queried with the routine XOF.GetByte() to generate the next byte of the output y
/// associated to x. The concrete instance of the XOF we use in the SD-in-the-Head scheme is given
/// in Section 4.5. In our context, we use the XOF as a secure pseudorandom generator (PRG)
/// which tolerates input seeds of variable lengths.

#[cfg(not(feature = "xof_blake3"))]
use crate::constants::params::{XOFPrimitive, XOF_PRIMITIVE};
#[cfg(not(feature = "xof_blake3"))]
use tiny_keccak::{Hasher, Shake, Xof};

use crate::constants::params::{PARAM_SALT_SIZE, PARAM_SEED_SIZE};

pub(crate) trait SDitHXOFTrait<T> {
    fn get_xof() -> T;
    fn init_base(x: &[u8]) -> Self;
    fn init(seed: &[u8; PARAM_SEED_SIZE], salt: Option<&[u8; PARAM_SALT_SIZE]>) -> Self;
    fn squeeze(&mut self, output: &mut [u8]);
}

pub(crate) struct SDitHXOF<T> {
    xof: T,
}

#[cfg(not(feature = "xof_blake3"))]
impl SDitHXOFTrait<Shake> for SDitHXOF<Shake> {
    fn get_xof() -> Shake {
        match XOF_PRIMITIVE {
            XOFPrimitive::SHAKE128 => Shake::v128(),
            XOFPrimitive::SHAKE256 => Shake::v256(),
        }
    }

    fn init_base(x: &[u8]) -> Self {
        let mut xof = Self::get_xof();
        xof.update(x);
        SDitHXOF { xof }
    }

    fn init(seed: &[u8; PARAM_SEED_SIZE], salt: Option<&[u8; PARAM_SALT_SIZE]>) -> Self {
        let mut xof = match XOF_PRIMITIVE {
            XOFPrimitive::SHAKE128 => Shake::v128(),
            XOFPrimitive::SHAKE256 => Shake::v256(),
        };
        if let Some(salt) = salt {
            xof.update(salt);
        }
        xof.update(seed);
        SDitHXOF { xof }
    }

    fn squeeze(&mut self, output: &mut [u8]) {
        self.xof.squeeze(output);
    }
}

#[cfg(feature = "xof_blake3")]
impl SDitHXOFTrait<blake3::OutputReader> for SDitHXOF<blake3::OutputReader> {
    fn get_xof() -> blake3::OutputReader {
        blake3::Hasher::new().finalize_xof()
    }

    fn init_base(x: &[u8]) -> Self {
        let mut xof = blake3::Hasher::new();
        xof.update(x);
        SDitHXOF {
            xof: xof.finalize_xof(),
        }
    }

    fn init(seed: &[u8; PARAM_SEED_SIZE], salt: Option<&[u8; PARAM_SALT_SIZE]>) -> Self {
        let mut xof = blake3::Hasher::new();
        if let Some(salt) = salt {
            xof.update(salt);
        }
        xof.update(seed);
        SDitHXOF {
            xof: xof.finalize_xof(),
        }
    }

    fn squeeze(&mut self, output: &mut [u8]) {
        self.xof.fill(output);
    }
}
