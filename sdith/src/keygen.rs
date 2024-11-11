use crate::{
    constants::{
        params::{PARAM_M_SUB_K, PARAM_SEED_SIZE},
        types::Seed,
    },
    subroutines::marshalling::Marshalling,
    witness::{generate_instance_with_solution, Solution, SOLUTION_PLAIN_SIZE},
};

#[derive(Debug, Clone, Copy)]
pub struct PublicKey {
    pub(crate) seed_h: Seed,
    pub(crate) y: [u8; PARAM_M_SUB_K],
}

impl Marshalling for PublicKey {
    fn serialise(&self) -> Vec<u8> {
        let mut serialised = Vec::new();
        serialised.extend_from_slice(&self.seed_h);
        serialised.extend_from_slice(&self.y);

        serialised
    }

    fn parse(serialised: &Vec<u8>) -> Result<Self, String> {
        if serialised.len() != PARAM_SEED_SIZE + PARAM_M_SUB_K {
            return Err(format!(
                "Invalid public key length. Got {}, expected {}",
                serialised.len(),
                PARAM_SEED_SIZE + PARAM_M_SUB_K
            ));
        }
        let seed_h: Seed = serialised[..PARAM_SEED_SIZE].try_into().unwrap();
        let y = serialised[PARAM_SEED_SIZE..].try_into().unwrap();
        Ok(PublicKey { seed_h, y })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SecretKey {
    pub(crate) seed_h: Seed,
    pub(crate) y: [u8; PARAM_M_SUB_K],
    /// Solution to the instance (s_a, Q', )
    pub(crate) solution: Solution,
}

impl Marshalling for SecretKey {
    fn serialise(&self) -> Vec<u8> {
        let mut serialised = Vec::new();
        serialised.extend_from_slice(&self.seed_h);
        serialised.extend_from_slice(&self.y);
        serialised.extend_from_slice(&self.solution.serialise());
        serialised
    }

    fn parse(serialised: &Vec<u8>) -> Result<Self, String> {
        if serialised.len() != PARAM_SEED_SIZE + PARAM_M_SUB_K + SOLUTION_PLAIN_SIZE {
            return Err(format!(
                "Invalid secret key length. Got {}, expected {}",
                serialised.len(),
                PARAM_SEED_SIZE + PARAM_M_SUB_K + SOLUTION_PLAIN_SIZE
            ));
        }
        let seed_h: Seed = serialised[..PARAM_SEED_SIZE].try_into().unwrap();
        let y = serialised[PARAM_SEED_SIZE..PARAM_SEED_SIZE + PARAM_M_SUB_K]
            .try_into()
            .unwrap();
        let solution = Solution::parse(
            serialised[PARAM_SEED_SIZE + PARAM_M_SUB_K
                ..PARAM_SEED_SIZE + PARAM_M_SUB_K + SOLUTION_PLAIN_SIZE]
                .try_into()
                .unwrap(),
        );

        Ok(SecretKey {
            seed_h,
            y,
            solution,
        })
    }
}

pub fn keygen(seed_root: Seed) -> (Box<PublicKey>, Box<SecretKey>) {
    let (instance, solution) = generate_instance_with_solution(seed_root);
    let pk = Box::new(PublicKey {
        seed_h: instance.seed_h,
        y: instance.y,
    });
    let sk = Box::new(SecretKey {
        seed_h: instance.seed_h,
        y: instance.y,
        solution,
    });

    (pk, sk)
}
