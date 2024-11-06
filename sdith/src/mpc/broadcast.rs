use crate::{
    arith::{
        arrays::{Array2D, Array2DTrait},
        gf256::gf256_ext::FPoint,
    },
    constants::params::{PARAM_ETA, PARAM_SPLITTING_FACTOR, PARAM_T},
};

#[derive(Clone)]
pub(crate) struct Broadcast {
    pub(crate) alpha: Array2D<FPoint>,
    pub(crate) beta: Array2D<FPoint>,
}

const BROADCAST_VALUE_PLAIN_SIZE: usize = PARAM_ETA * PARAM_T * PARAM_SPLITTING_FACTOR;

pub(crate) const BROADCAST_PLAIN_SIZE: usize = PARAM_ETA * PARAM_T * PARAM_SPLITTING_FACTOR * 2;

impl Broadcast {
    pub(crate) fn default() -> Self {
        let alpha = Array2D::new(PARAM_T, PARAM_SPLITTING_FACTOR);
        let beta = Array2D::new(PARAM_T, PARAM_SPLITTING_FACTOR);
        Self { alpha, beta }
    }

    pub(crate) fn serialise(&self) -> Vec<u8> {
        let mut result = vec![0u8; BROADCAST_PLAIN_SIZE];

        for (n, v) in [&self.alpha, &self.beta].iter().enumerate() {
            serialise_broadcast_value(result.as_mut_slice(), v, n);
        }

        result
    }

    pub(crate) fn parse(broadcast_plain: Vec<u8>) -> Self {
        let alpha: Array2D<FPoint> = deserialise_broadcast_value(
            broadcast_plain[..BROADCAST_VALUE_PLAIN_SIZE]
                .try_into()
                .unwrap(),
        );
        let beta: Array2D<FPoint> = deserialise_broadcast_value(
            broadcast_plain[BROADCAST_VALUE_PLAIN_SIZE..]
                .try_into()
                .unwrap(),
        );

        Self { alpha, beta }
    }
}

fn serialise_broadcast_value(out: &mut [u8], broadcast_value: &Array2D<FPoint>, n_offset: usize) {
    for d in 0..PARAM_SPLITTING_FACTOR {
        for j in 0..PARAM_T {
            let ab_offset = n_offset * BROADCAST_VALUE_PLAIN_SIZE;
            let offset = ab_offset + d * PARAM_T + j * PARAM_ETA;

            let point = broadcast_value.get(d, j);
            out[offset..(offset + PARAM_ETA)].copy_from_slice(&point);
        }
    }
}

fn deserialise_broadcast_value(broadcast_value_plain: Vec<u8>) -> Array2D<FPoint> {
    let mut broadcast_value = Array2D::new(PARAM_T, PARAM_SPLITTING_FACTOR);

    for d in 0..PARAM_SPLITTING_FACTOR {
        for j in 0..PARAM_T {
            let offset = d * PARAM_T + j * PARAM_ETA;

            let point: FPoint = broadcast_value_plain[offset..(offset + PARAM_ETA)]
                .try_into()
                .unwrap();
            broadcast_value.set(d, j, point);
        }
    }
    broadcast_value
}

impl std::fmt::Debug for Broadcast {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Broadcast {{ alpha: {:?}, beta: {:?} }}",
            &self.alpha.get(0, 0),
            &self.beta.get(0, 0)
        )
    }
}

#[derive(Debug)]
pub(crate) struct BroadcastShare {
    pub(crate) alpha: Array2D<FPoint>, 
    // TODO: Is this performant? I'e we have arrays in vec. 
    // Do we want special array that spreads out the points. Essentially a Array3D with PARAM_ETA as cols
    pub(crate) beta: Array2D<FPoint>,
    pub(crate) v: Vec<FPoint>,
}

pub(crate) const BROADCAST_SHARE_PLAIN_SIZE_AB: usize =
    PARAM_ETA * PARAM_T * PARAM_SPLITTING_FACTOR * 2;
const BROADCAST_SHARE_PLAIN_SIZE_V: usize = PARAM_ETA * PARAM_T;
pub(crate) const BROADCAST_SHARE_PLAIN_SIZE: usize =
    BROADCAST_SHARE_PLAIN_SIZE_AB + BROADCAST_SHARE_PLAIN_SIZE_V;

impl BroadcastShare {
    pub(crate) fn serialise(&self) -> Vec<u8> {
        let mut result = vec![0u8; BROADCAST_SHARE_PLAIN_SIZE];

        for (n, v) in [&self.alpha, &self.beta].iter().enumerate() {
            serialise_broadcast_value(result.as_mut_slice(), v, n);
        }

        let mut offset = BROADCAST_SHARE_PLAIN_SIZE_AB;
        for j in 0..PARAM_T {
            let point = self.v[j];
            result[offset..(offset + PARAM_ETA)].copy_from_slice(&point);
            offset += PARAM_ETA;
        }

        result
    }

    pub(crate) fn parse(broadcast_share_plain: Vec<u8>) -> Self {
        let alpha: Array2D<FPoint> = deserialise_broadcast_value(
            broadcast_share_plain[..BROADCAST_VALUE_PLAIN_SIZE]
                .try_into()
                .unwrap(),
        );
        let beta: Array2D<FPoint> = deserialise_broadcast_value(
            broadcast_share_plain[BROADCAST_VALUE_PLAIN_SIZE..BROADCAST_VALUE_PLAIN_SIZE * 2]
                .try_into()
                .unwrap(),
        );

        let mut v = vec![FPoint::default(); PARAM_T];

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
            alpha: Array2D::new(PARAM_T, PARAM_SPLITTING_FACTOR),
            beta: Array2D::new(PARAM_T, PARAM_SPLITTING_FACTOR),
            v: vec![FPoint::default(); PARAM_T],
        };
    }
}

#[cfg(test)]
mod broadcast_tests {
    use super::*;
    use crate::subroutines::prg::prg::PRG;

    #[test]
    fn test_serialise_deserialise_broadcast() {
        let mut broadcast = Broadcast::default();

        let mut prg = PRG::init_base(&[1, 2, 3]);
        for d in 0..PARAM_SPLITTING_FACTOR {
            prg.sample_field_fpoint_elements(&mut broadcast.alpha.get_row_mut(d));
            prg.sample_field_fpoint_elements(&mut broadcast.beta.get_row_mut(d));
        }

        assert!(broadcast.alpha.get(0, 0) != FPoint::default());

        let serialised = broadcast.serialise();

        assert_eq!(serialised.len(), BROADCAST_PLAIN_SIZE);
        assert_ne!(serialised, [0u8; BROADCAST_PLAIN_SIZE]);

        let deserialised = Broadcast::parse(serialised);

        assert_eq!(broadcast.alpha, deserialised.alpha);
        assert_eq!(broadcast.beta, deserialised.beta);
    }

    #[test]
    fn test_serialise_deserialise_broadcast_share() {
        let mut broadcast_share = BroadcastShare::default();

        let mut prg = PRG::init_base(&[1, 2, 3]);
        for d in 0..PARAM_SPLITTING_FACTOR {
            prg.sample_field_fpoint_elements(&mut broadcast_share.alpha.get_row_mut(d));
            prg.sample_field_fpoint_elements(&mut broadcast_share.beta.get_row_mut(d));
        }
        prg.sample_field_fpoint_elements(&mut broadcast_share.v);

        let serialised = broadcast_share.serialise();
        let deserialised = BroadcastShare::parse(serialised);

        assert_eq!(broadcast_share.alpha, deserialised.alpha);
        assert_eq!(broadcast_share.beta, deserialised.beta);
        assert_eq!(broadcast_share.v, deserialised.v);
    }
}
