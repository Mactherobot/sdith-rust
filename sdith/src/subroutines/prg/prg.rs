use tiny_keccak::{Shake, Xof};

use crate::{
    arith::{gf256::gf256_ext::FPoint, vectors::parse},
    constants::params::{PARAM_ETA, PARAM_SALT_SIZE, PARAM_SEED_SIZE},
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

    /// Sample a random value from the PRG
    pub fn sample(&mut self, output: &mut [u8]) {
        self.xof.squeeze(output);
    }

    pub fn sample_non_zero<const SIZE: usize>(&mut self) -> [u8; SIZE] {
        let mut result = [0_u8; SIZE];
        for i in 0..SIZE {
            self.sample(&mut result[i..i + 1]);
            if result[i] == 0 {
                result[i] += 1;
            }
        }
        result
    }

    /// Sample a random value in the field F_q = F_256
    /// The byte B_i is returned as the sampled field element. XOF is called to generate n bytes
    pub fn sample_field_elements_gf256_vec(&mut self, n: usize) -> Vec<u8> {
        let mut f = vec![0u8; n];
        self.xof.squeeze(&mut f);

        f
    }

    /// Sample a random value in the field F_q = F_256
    /// The byte B_i is returned as the sampled field element. XOF is called to generate n bytes
    pub fn sample_field_elements_gf256<const N: usize>(&mut self) -> [u8; N] {
        let mut f = [0u8; N];
        self.xof.squeeze(&mut f);

        f
    }

    /// Sample a random value in the field F_q^η
    pub fn sample_field_f_point_elements<const N: usize>(&mut self) -> [FPoint; N] {
        let mut f = [FPoint::default(); N];
        for i in 0..N {
            self.xof.squeeze(&mut f[i]);
        }
        f
    }

    /// Sample a random value in the field F_q = F_251.
    /// See bottom of page 24 in spec
    fn sample_field_elements_gf251(&mut self, n: usize) -> Vec<u8> {
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
    fn test_prg_sample_field_elements_gf256_vec() {
        let seed = &[0u8; PARAM_SEED_SIZE];
        let mut prg = PRG::init(seed, None);

        let f = prg.sample_field_elements_gf256_vec(32);
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

    #[test]
    fn test_prg_sample_non_zero() {
        let seed = &[0u8; PARAM_SEED_SIZE];
        let mut prg = PRG::init(seed, None);

        let f = prg.sample_non_zero::<256>();
        assert_ne!(f, [0u8; 256]);
        for i in f.iter() {
            assert_ne!(*i, 0);
        }
    }
}
