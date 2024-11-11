#[cfg(test)]
mod tests {
    use crate::{arith::gf256::gf256_ext::FPoint, constants::{params::PARAM_CHUNK_M, precomputed::PRECOMPUTED_F_POLY}, mpc::{challenge::get_powers, mpc::MPC}};

    #[test]
    fn test_mpc_polynomial_evaluation_vs_spec() {
        let spec_points = [
            [101, 240, 130, 70],
            [188, 62, 92, 104],
            [217, 118, 89, 108],
            [217, 191, 97, 2],
            [230, 184, 239, 173],
            [233, 129, 202, 172],
            [56, 189, 15, 1],
        ];

        let spec_points_exp2 = [
            [149, 81, 148, 191],
            [18, 212, 171, 135],
            [58, 133, 140, 151],
            [42, 32, 70, 4],
            [185, 29, 47, 167],
            [26, 94, 114, 166],
            [49, 190, 117, 1],
        ];
        let spec_f_evals = [
            [188, 71, 118, 91],
            [17, 165, 132, 51],
            [133, 81, 123, 176],
            [74, 131, 161, 189],
            [179, 195, 88, 253],
            [89, 33, 109, 134],
            [12, 207, 24, 210],
        ];

        let mut f_evals = [FPoint::default(); 7];

        for i in 0..7 {
            let mut powers_of_r = [FPoint::default(); PARAM_CHUNK_M + 1];
            get_powers(spec_points[i], &mut powers_of_r);

            assert_eq!(spec_points[i], powers_of_r[1]);
            assert_eq!(spec_points_exp2[i], powers_of_r[2]);

            f_evals[i] = MPC::polynomial_evaluation(&PRECOMPUTED_F_POLY, &powers_of_r);
        }

        for i in 0..7 {
            assert_eq!(f_evals[i], spec_f_evals[i]);
        }
    }
}
