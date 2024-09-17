use tiny_keccak::{Shake, Xof};

use crate::constants::params::{PARAM_SALT_SIZE, PARAM_SEED_SIZE};

use super::xof::xof_init;

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

    /// Sample a random value from the PRG
    pub fn sample(&mut self, output: &mut [u8]) {
        self.xof.squeeze(output);
    }

    /// Sample a random value in the field F_q = F_256
    /// The byte B_i is returned as the sampled field element. XOF is called to generate n bytes
    pub fn sample_field_elements_gf256(&mut self, n: usize) -> Vec<u8> {
        let mut f = vec![0u8; n];
        for i in 0..n {
            self.xof.squeeze(&mut f[i..i + 1]);
        }

        f
    }

    /// Sample a random value in the field F_q = F_251.
    /// See bottom of page 24 in spec
    pub fn sample_field_elements_gf251(&mut self, n: usize) -> Vec<u8> {
        let mut f = vec![0u8; n];
        let mut i = 1;
        while i <= n {
            let mut buf = [0u8; 1];
            self.xof.squeeze(&mut buf);
            if buf[0] < 251 {
                f[i - 1] = buf[0];
                i += 1;
            }
        }

        f
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
        prg.sample(&mut output);
        assert_ne!(output, [0u8; 32]);
    }

    #[test]
    fn test_prg_sample_field_elements_gf256() {
        let seed = &[0u8; PARAM_SEED_SIZE];
        let mut prg = PRG::init(seed, None);

        let f = prg.sample_field_elements_gf256(32);
        assert_ne!(f, vec![0u8; 32]);
    }

    #[test]
    fn test_prg_sample_field_elements_gf251() {
        let seed = &[0u8; PARAM_SEED_SIZE];
        let mut prg = PRG::init(seed, None);

        let f = prg.sample_field_elements_gf251(32);
        assert_ne!(f, vec![0u8; 32]);
        for i in f.iter() {
            println!("{}", i);
            assert!(*i < 251);
        }
    }
}
