use crate::{
    arith::gf256::gf256_ext::FPoint,
    constants::params::{PARAM_ETA, PARAM_SPLITTING_FACTOR, PARAM_T},
};

type BroadcastValue = [[FPoint; PARAM_T]; PARAM_SPLITTING_FACTOR];

#[derive(Clone)]
pub(crate) struct Broadcast {
    pub(crate) alpha: BroadcastValue,
    pub(crate) beta: BroadcastValue,
}

const BROADCAST_VALUE_PLAIN_SIZE: usize = PARAM_ETA * PARAM_T * PARAM_SPLITTING_FACTOR;

pub(crate) const BROADCAST_PLAIN_SIZE: usize = PARAM_ETA * PARAM_T * PARAM_SPLITTING_FACTOR * 2;
const BROADCAST_V_PLAIN_SIZE: usize = PARAM_ETA * PARAM_T;

impl Broadcast {
    pub(crate) fn default() -> Self {
        let alpha = [[FPoint::default(); PARAM_T]; PARAM_SPLITTING_FACTOR];
        let beta = [[FPoint::default(); PARAM_T]; PARAM_SPLITTING_FACTOR];
        Self { alpha, beta }
    }

    pub(crate) fn serialise(&self) -> [u8; BROADCAST_PLAIN_SIZE] {
        let mut result = [0u8; BROADCAST_PLAIN_SIZE];

        for (n, v) in [self.alpha, self.beta].iter().enumerate() {
            serialise_broadcast_value(result.as_mut_slice(), v, n);
        }

        result
    }

    pub(crate) fn parse(broadcast_plain: [u8; BROADCAST_PLAIN_SIZE]) -> Self {
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

        Self { alpha, beta }
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

    for d in 0..PARAM_SPLITTING_FACTOR {
        for j in 0..PARAM_T {
            let offset = d * PARAM_T * PARAM_ETA + j * PARAM_ETA;

            let point: FPoint = broadcast_value_plain[offset..(offset + PARAM_ETA)]
                .try_into()
                .unwrap();
            broadcast_value[d][j] = point
        }
    }
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

#[derive(Debug)]
pub(crate) struct BroadcastShare {
    pub(crate) alpha: BroadcastValue,
    pub(crate) beta: BroadcastValue,
    pub(crate) v: [FPoint; PARAM_T],
}

pub(crate) const BROADCAST_SHARE_PLAIN_SIZE_AB: usize =
    PARAM_ETA * PARAM_T * PARAM_SPLITTING_FACTOR * 2;
const BROADCAST_SHARE_PLAIN_SIZE_V: usize = PARAM_ETA * PARAM_T;
pub(crate) const BROADCAST_SHARE_PLAIN_SIZE: usize =
    BROADCAST_SHARE_PLAIN_SIZE_AB + BROADCAST_SHARE_PLAIN_SIZE_V;

impl BroadcastShare {
    pub(crate) fn serialise(&self) -> [u8; BROADCAST_SHARE_PLAIN_SIZE] {
        let mut result = [0u8; BROADCAST_SHARE_PLAIN_SIZE];

        for (n, v) in [self.alpha, self.beta].iter().enumerate() {
            serialise_broadcast_value(&mut result, v, n);
        }

        let mut offset = BROADCAST_SHARE_PLAIN_SIZE_AB;
        for j in 0..PARAM_T {
            let point = self.v[j];
            result[offset..(offset + PARAM_ETA)].copy_from_slice(&point);
            offset += PARAM_ETA;
        }

        result
    }

    pub(crate) fn parse(broadcast_share_plain: [u8; BROADCAST_SHARE_PLAIN_SIZE]) -> Self {
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
        for j in 0..PARAM_T {
            let point = &broadcast_share_plain[offset..(offset + PARAM_ETA)];
            v[j].copy_from_slice(point);
            offset += PARAM_ETA;
        }

        Self { alpha, beta, v }
    }

    pub(crate) fn default() -> BroadcastShare {
        return BroadcastShare {
            alpha: [[FPoint::default(); PARAM_T]; PARAM_SPLITTING_FACTOR],

            beta: [[FPoint::default(); PARAM_T]; PARAM_SPLITTING_FACTOR],
            v: [FPoint::default(); PARAM_T],
        };
    }
}

#[cfg(test)]
mod broadcast_tests {
    use super::*;
    use crate::subroutines::prg::prg::PRG;

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

        let deserialised = Broadcast::parse(serialised);

        assert_eq!(broadcast.alpha, deserialised.alpha);
        assert_eq!(broadcast.beta, deserialised.beta);
    }

    #[test]
    fn test_serialise_deserialise_broadcast_share() {
        let mut broadcast_share = BroadcastShare {
            alpha: [[FPoint::default(); PARAM_T]; PARAM_SPLITTING_FACTOR],
            beta: [[FPoint::default(); PARAM_T]; PARAM_SPLITTING_FACTOR],
            v: [FPoint::default(); PARAM_T],
        };

        let mut prg = PRG::init_base(&[1, 2, 3]);
        for d in 0..PARAM_SPLITTING_FACTOR {
            prg.sample_field_fpoint_elements(&mut broadcast_share.alpha[d]);
            prg.sample_field_fpoint_elements(&mut broadcast_share.beta[d]);
        }
        prg.sample_field_fpoint_elements(&mut broadcast_share.v);

        let serialised = broadcast_share.serialise();
        let deserialised = BroadcastShare::parse(serialised);

        assert_eq!(broadcast_share.alpha, deserialised.alpha);
        assert_eq!(broadcast_share.beta, deserialised.beta);
        assert_eq!(broadcast_share.v, deserialised.v);
    }
}
