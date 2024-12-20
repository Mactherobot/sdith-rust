//! # Broadcast
//!
//! Contains the structs used for the broadcast values
//! The broadcast values are created by the MPC party computation, and are sent to the
//! verifier in the signature. Where they are used in veryfying the signature. By running an
//! inverse party computation on the broadcast values.
//!
//! Also contains the functions for serialising and deserialising the broadcast values

use crate::{
    constants::params::{PARAM_ETA, PARAM_SPLITTING_FACTOR, PARAM_T},
    subroutines::arith::gf256::gf256_ext::FPoint,
    utils::marshalling::Marshalling,
};

type BroadcastValue = [[FPoint; PARAM_T]; PARAM_SPLITTING_FACTOR];

/// Struct for holding the broadcast values
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Broadcast {
    /// Broadcast value alpha
    pub alpha: BroadcastValue,

    /// Broadcast value beta
    pub beta: BroadcastValue,
}

const BROADCAST_VALUE_PLAIN_SIZE: usize = PARAM_ETA * PARAM_T * PARAM_SPLITTING_FACTOR;

/// Size of the plain value of the broadcast values
pub const BROADCAST_PLAIN_SIZE: usize = PARAM_ETA * PARAM_T * PARAM_SPLITTING_FACTOR * 2;

impl Marshalling<[u8; BROADCAST_PLAIN_SIZE]> for Broadcast {
    /// Serialise the broadcast values into a byte array
    fn serialise(&self) -> [u8; BROADCAST_PLAIN_SIZE] {
        let mut result = [0u8; BROADCAST_PLAIN_SIZE];

        for (n, v) in [self.alpha, self.beta].iter().enumerate() {
            serialise_broadcast_value(result.as_mut_slice(), v, n);
        }

        result
    }

    /// Parse the broadcast values from a byte array
    fn parse(broadcast_plain: &[u8; BROADCAST_PLAIN_SIZE]) -> Result<Self, String> {
        let alpha: BroadcastValue = deserialise_broadcast_value(
            broadcast_plain[..BROADCAST_VALUE_PLAIN_SIZE]
                .try_into()
                .unwrap(),
        );
        let beta: BroadcastValue = deserialise_broadcast_value(
            broadcast_plain[BROADCAST_VALUE_PLAIN_SIZE..]
                .try_into()
                .unwrap(),
        );

        Ok(Self { alpha, beta })
    }
}

fn serialise_broadcast_value(out: &mut [u8], broadcast_value: &BroadcastValue, n_offset: usize) {
    let ab_offset = n_offset * BROADCAST_VALUE_PLAIN_SIZE;
    let flattened = broadcast_value.as_flattened().as_flattened();
    out[ab_offset..ab_offset + flattened.len()].copy_from_slice(flattened);
}

fn deserialise_broadcast_value(
    broadcast_value_plain: [u8; BROADCAST_VALUE_PLAIN_SIZE],
) -> BroadcastValue {
    let mut broadcast_value = BroadcastValue::default();

    (0..PARAM_SPLITTING_FACTOR).for_each(|d| {
        for j in 0..PARAM_T {
            let offset = d * PARAM_T * PARAM_ETA + j * PARAM_ETA;

            let point: FPoint = broadcast_value_plain[offset..(offset + PARAM_ETA)]
                .try_into()
                .unwrap();
            broadcast_value[d][j] = point
        }
    });
    broadcast_value
}

impl std::fmt::Debug for Broadcast {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Broadcast {{ alpha: {:?}, beta: {:?} }}",
            &self.alpha[0][0], &self.beta[0][0]
        )
    }
}

#[derive(Debug, Default, PartialEq, Eq, Clone)]
/// Broadcast share struct
pub struct BroadcastShare {
    /// Broadcast value alpha
    pub alpha: BroadcastValue,

    /// Broadcast value beta
    pub beta: BroadcastValue,

    /// Broadcast value v
    pub v: [FPoint; PARAM_T],
}

/// Size of the plain value for a and b of the broadcast share
pub const BROADCAST_SHARE_PLAIN_SIZE_AB: usize = PARAM_ETA * PARAM_T * PARAM_SPLITTING_FACTOR * 2;
const BROADCAST_SHARE_PLAIN_SIZE_V: usize = PARAM_ETA * PARAM_T;

/// Size of the complete plain value of the broadcast share
pub const BROADCAST_SHARE_PLAIN_SIZE: usize =
    BROADCAST_SHARE_PLAIN_SIZE_AB + BROADCAST_SHARE_PLAIN_SIZE_V;

impl Marshalling<[u8; BROADCAST_SHARE_PLAIN_SIZE]> for BroadcastShare {
    /// Serialise the broadcast share into a byte array
    fn serialise(&self) -> [u8; BROADCAST_SHARE_PLAIN_SIZE] {
        let mut result = [0u8; BROADCAST_SHARE_PLAIN_SIZE];

        for (n, v) in [self.alpha, self.beta].iter().enumerate() {
            serialise_broadcast_value(&mut result, v, n);
        }

        let mut offset = BROADCAST_SHARE_PLAIN_SIZE_AB;
        self.v.iter().for_each(|vj| {
            result[offset..(offset + PARAM_ETA)].copy_from_slice(vj);
            offset += PARAM_ETA;
        });

        result
    }

    /// Parse the broadcast share from a byte array
    fn parse(broadcast_share_plain: &[u8; BROADCAST_SHARE_PLAIN_SIZE]) -> Result<Self, String> {
        let alpha: BroadcastValue = deserialise_broadcast_value(
            broadcast_share_plain[..BROADCAST_VALUE_PLAIN_SIZE]
                .try_into()
                .unwrap(),
        );
        let beta: BroadcastValue = deserialise_broadcast_value(
            broadcast_share_plain[BROADCAST_VALUE_PLAIN_SIZE..BROADCAST_VALUE_PLAIN_SIZE * 2]
                .try_into()
                .unwrap(),
        );

        let mut v = [FPoint::default(); PARAM_T];

        let mut offset = BROADCAST_SHARE_PLAIN_SIZE_AB;
        v.iter_mut().for_each(|vj| {
            let point = &broadcast_share_plain[offset..(offset + PARAM_ETA)];
            vj.copy_from_slice(point);
            offset += PARAM_ETA;
        });

        Ok(Self { alpha, beta, v })
    }
}

#[cfg(test)]
mod broadcast_tests {
    use super::*;
    use crate::subroutines::prg::PRG;

    #[test]
    fn test_serialise_deserialise_broadcast_value() {
        let mut prg = PRG::init_base(&[1, 2, 3]);
        let mut alpha = [[FPoint::default(); PARAM_T]; PARAM_SPLITTING_FACTOR];
        let mut beta = [[FPoint::default(); PARAM_T]; PARAM_SPLITTING_FACTOR];
        for d in 0..PARAM_SPLITTING_FACTOR {
            prg.sample_field_fpoint_elements(&mut alpha[d]);
            prg.sample_field_fpoint_elements(&mut beta[d]);
        }

        let mut serialised = [0u8; BROADCAST_VALUE_PLAIN_SIZE * 2];
        serialise_broadcast_value(&mut serialised, &alpha, 0);
        assert!(serialised[BROADCAST_VALUE_PLAIN_SIZE..]
            .iter()
            .all(|&x| x == 0));

        let mut serialised = [0u8; BROADCAST_VALUE_PLAIN_SIZE * 2];
        serialise_broadcast_value(&mut serialised, &beta, 1);

        assert!(serialised[..BROADCAST_VALUE_PLAIN_SIZE]
            .iter()
            .all(|&x| x == 0));

        serialise_broadcast_value(&mut serialised, &alpha, 0);

        let deserialised_alpha = deserialise_broadcast_value(
            serialised[..BROADCAST_VALUE_PLAIN_SIZE].try_into().unwrap(),
        );

        assert_eq!(alpha, deserialised_alpha);

        let deserialised_beta = deserialise_broadcast_value(
            serialised[BROADCAST_VALUE_PLAIN_SIZE..].try_into().unwrap(),
        );

        assert_eq!(beta, deserialised_beta);
    }

    #[test]
    fn test_serialise_deserialise_broadcast() {
        let mut broadcast = Broadcast {
            alpha: [[FPoint::default(); PARAM_T]; PARAM_SPLITTING_FACTOR],
            beta: [[FPoint::default(); PARAM_T]; PARAM_SPLITTING_FACTOR],
        };

        let mut prg = PRG::init_base(&[1, 2, 3]);
        for d in 0..PARAM_SPLITTING_FACTOR {
            prg.sample_field_fpoint_elements(&mut broadcast.alpha[d]);
            prg.sample_field_fpoint_elements(&mut broadcast.beta[d]);
        }

        assert!(broadcast.alpha[0][0] != FPoint::default());

        let serialised = broadcast.serialise();

        assert_eq!(serialised.len(), BROADCAST_PLAIN_SIZE);
        assert_ne!(serialised, [0u8; BROADCAST_PLAIN_SIZE]);

        let deserialised = Broadcast::parse(&serialised).unwrap();

        assert_eq!(broadcast.alpha, deserialised.alpha);
        assert_eq!(broadcast.beta, deserialised.beta);
    }

    fn gen_random_broadcast_share(prg: &mut PRG) -> BroadcastShare {
        let mut broadcast_share = BroadcastShare::default();

        for d in 0..PARAM_SPLITTING_FACTOR {
            prg.sample_field_fpoint_elements(&mut broadcast_share.alpha[d]);
            prg.sample_field_fpoint_elements(&mut broadcast_share.beta[d]);
        }
        prg.sample_field_fpoint_elements(&mut broadcast_share.v);

        broadcast_share
    }

    #[test]
    fn test_marhalling_broadcast_share() {
        let bs1 = gen_random_broadcast_share(&mut PRG::init_base(&[1]));
        let bs2 = gen_random_broadcast_share(&mut PRG::init_base(&[2]));

        crate::utils::marshalling::_test_marhalling(bs1, bs2);
    }

    fn gen_random_broadcast(prg: &mut PRG) -> Broadcast {
        let mut broadcast = Broadcast::default();

        for d in 0..PARAM_SPLITTING_FACTOR {
            prg.sample_field_fpoint_elements(&mut broadcast.alpha[d]);
            prg.sample_field_fpoint_elements(&mut broadcast.beta[d]);
        }

        broadcast
    }

    #[test]
    fn test_marhalling_broadcast() {
        let bc1 = gen_random_broadcast(&mut PRG::init_base(&[1]));
        let bc2 = gen_random_broadcast(&mut PRG::init_base(&[2]));

        crate::utils::marshalling::_test_marhalling(bc1, bc2);
    }
}
