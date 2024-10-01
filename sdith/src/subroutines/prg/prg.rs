use std::fmt::Error;

use tiny_keccak::{Shake, Xof};

use crate::{
    arith::gf256::gf256_ext::FPoint,
    constants::params::{PARAM_SALT_SIZE, PARAM_SEED_SIZE},
};

use super::xof::{xof_init, xof_init_base};

pub struct PRG {
    xof: Shake,
}

impl PRG {
    /// Initialize the PRG with a seed and optional salt
    pub fn init(seed: &[u8; PARAM_SEED_SIZE], salt: Option<&[u8; PARAM_SALT_SIZE]>) -> Self {
        PRG {
            xof: xof_init(seed, salt),
        }
    }

    /// Initialize the PRG with a base value e.g for h1 in the spec `PRG::init_base(HASH_PREFIX_CHALLENGE_1)`
    pub fn init_base(x: &[u8]) -> Self {
        PRG {
            xof: xof_init_base(x),
        }
    }

    pub fn sample_field_fq_non_zero(&mut self, output: &mut [u8]) {
        for i in 0..output.len() {
            self.sample_field_fq_elements(&mut output[i..i + 1]);
            if output[i] == 0 {
                output[i] += 1;
            }
        }
    }

    pub fn sample_field_fq_non_zero_set(&mut self, output: &mut [u8]) -> Result<(), Error> {
        if output.len() >= 256 {
            return Err(Error);
        };

        let mut i = 0;
        while i < output.len() {
            self.sample_field_fq_non_zero(&mut output[i..i + 1]);
            let is_redundant = (0..i).any(|j| output[j] == output[i]);
            if is_redundant {
                continue;
            }
            i += 1;
        }

        return Ok(());
    }

    /// Sample a random value in the field F_q = F_256
    /// The byte B_i is returned as the sampled field element. XOF is called to generate n bytes
    pub fn sample_field_fq_elements_vec(&mut self, n: usize) -> Vec<u8> {
        let mut f = vec![0u8; n];
        self.xof.squeeze(&mut f);

        f
    }

    /// Sample a random value in the field F_q = F_256
    /// The byte B_i is returned as the sampled field element. XOF is called to generate n bytes
    pub fn sample_field_fq_elements(&mut self, out: &mut [u8]) {
        self.xof.squeeze(out);
    }

    /// Sample a random value in the field F_q^η
    pub fn sample_field_fpoint_elements(&mut self, out: &mut [FPoint]) {
        for i in 0..out.len() {
            self.xof.squeeze(&mut out[i]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prg() {
        let seed = &[0u8; PARAM_SEED_SIZE];
        let mut prg = PRG::init(seed, None);

        let mut output = [0u8; 32];
        prg.sample_field_fq_elements(&mut output);
        assert_ne!(output, [0u8; 32]);
    }

    #[test]
    fn test_prg_sample_field_elements_gf256_vec() {
        let seed = &[0u8; PARAM_SEED_SIZE];
        let mut prg = PRG::init(seed, None);

        let f = prg.sample_field_fq_elements_vec(32);
        assert_ne!(f, vec![0u8; 32]);
    }

    #[test]
    fn test_prg_sample_non_zero() {
        let seed = &[0u8; PARAM_SEED_SIZE];
        let mut prg = PRG::init(seed, None);

        let mut f = [0u8; 256];
        prg.sample_field_fq_non_zero(&mut f);

        assert_ne!(f, [0u8; 256]);
        for i in f.iter() {
            assert_ne!(*i, 0);
        }
    }

    #[test]
    fn test_prg_sample_non_zero_set() {
        let seed = &[0u8; PARAM_SEED_SIZE];
        let mut prg = PRG::init(seed, None);

        let mut f = [0u8; 100];
        prg.sample_field_fq_non_zero_set(&mut f);
        for (i, fi) in f.iter().enumerate() {
            assert_ne!(*fi, 0);
            let is_redundant = (0..i).any(|j| f[j] == *fi);
            assert!(!is_redundant);
        }

        let mut f = [0u8; 256];
        assert!(prg.sample_field_fq_non_zero_set(&mut f).is_err());
    }
}
