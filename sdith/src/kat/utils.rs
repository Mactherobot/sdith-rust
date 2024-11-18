use crate::{
  constants::{
      params::{PARAM_M_SUB_K, PARAM_SEED_SIZE},
      types::Seed,
  },
  keygen::{PublicKey, SecretKey},
  witness::{Solution, SOLUTION_PLAIN_SIZE},
};

impl PublicKey {
  pub(super) fn parse_from_hex(hex: &str) -> Self {
      let bytes = hex::decode(hex).unwrap();
      assert_eq!(
          bytes.len(), PARAM_SEED_SIZE + PARAM_M_SUB_K,
          "Invalid public key length. Got {}, expected {}",
          bytes.len(),
          PARAM_SEED_SIZE + PARAM_M_SUB_K
      );
      let seed_h: Seed = bytes[..PARAM_SEED_SIZE].try_into().unwrap();
      let y = bytes[PARAM_SEED_SIZE..].try_into().unwrap();
      PublicKey { seed_h, y }
  }

  pub(super) fn to_hex(&self) -> String {
      let mut bytes = Vec::new();
      bytes.extend_from_slice(&self.seed_h);
      bytes.extend_from_slice(&self.y);
      hex::encode(bytes)
  }
}

impl SecretKey {
  pub(super) fn parse_from_hex(hex: &str) -> Self {
      let bytes = hex::decode(hex).unwrap();

      assert!(
          bytes.len() == SOLUTION_PLAIN_SIZE + PARAM_SEED_SIZE + PARAM_M_SUB_K,
          "Invalid secret key length. Got {}, expected {}",
          bytes.len(),
          SOLUTION_PLAIN_SIZE + PARAM_SEED_SIZE + PARAM_M_SUB_K
      );

      let seed_h: Seed = bytes[..PARAM_SEED_SIZE].try_into().unwrap();
      let y = bytes[PARAM_SEED_SIZE..PARAM_SEED_SIZE + PARAM_M_SUB_K]
          .try_into()
          .unwrap();
      let solution_plain = bytes[PARAM_SEED_SIZE + PARAM_M_SUB_K..].try_into().expect(
          format!(
              "Invalid secret key length. Got {}, expected {}",
              bytes.len(),
              SOLUTION_PLAIN_SIZE
          )
          .as_str(),
      );
      SecretKey {
          seed_h,
          y,
          solution: Solution::parse(solution_plain),
      }
  }

  pub(super) fn to_hex(&self) -> String {
      let mut bytes = Vec::new();
      bytes.extend_from_slice(&self.seed_h);
      bytes.extend_from_slice(&self.y);
      bytes.extend_from_slice(&self.solution.serialise());
      hex::encode(bytes)
  }
}
