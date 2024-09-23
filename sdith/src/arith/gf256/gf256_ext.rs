// Field extension `F_q^2 = F_q[X] / (X^2 + X + 32)`

use super::gf256_arith::{gf256_add, gf256_mul};

/// Addition: Field extension `F_q^2 = F_q[X] / (X^2 + X + 32)`
fn gf256_ext16_add(a: [u8; 2], b: [u8; 2]) -> [u8; 2] {
    [gf256_add(a[0], b[0]), gf256_add(a[1], b[1])]
}

/// Multiplication: Field extension `F_q^2 = F_q[X] / (X^2 + X + 32)`
fn gf256_ext16_mul(a: [u8; 2], b: [u8; 2]) -> [u8; 2] {
    let [a0, a1] = a;
    let [b0, b1] = b;
    let leading = gf256_mul(a1, b1);
    let cnst = gf256_mul(a0, b0);
    let sum_a = gf256_add(a0, a1);
    let sum_b = gf256_add(b0, b1);

    let c0 = gf256_add(cnst, gf256_mul(leading, 0x20));
    let c1 = gf256_add(gf256_mul(sum_a, sum_b), cnst);
    [c0, c1]
}

fn gf256_ext16_mul32(a: [u8; 2]) -> [u8; 2] {
    let [a0, a1] = a;
    let c0 = gf256_mul(gf256_mul(a1, 0x20), 0x20);
    let c1 = gf256_mul(gf256_add(a0, a1), 0x20);
    [c0, c1]
}

#[cfg(test)]
mod ext16_tests {
    #[test]
    fn test_add() {
        todo!()
    }

    #[test]
    fn test_mul() {
        todo!()
    }
}

// Field extension `F_q^4 = F_q[Z] / (Z^2 + Z + 32(X))` where (X) = 256

/// Addition: Field extension `F_q^4 = F_q[Z] / (Z^2 + Z + 32(X))` where (X) = 256
pub(crate) fn gf256_ext32_add(a: [u8; 4], b: [u8; 4]) -> [u8; 4] {
    let [a0, a1, a2, a3] = a;
    let [b0, b1, b2, b3] = b;
    let [r0, r1] = gf256_ext16_add([a0, a1], [b0, b1]);
    let [r2, r3] = gf256_ext16_add([a2, a3], [b2, b3]);

    [r0, r1, r2, r3]
}

/// Multiplication: Field extension `F_q^4 = F_q[Z] / (Z^2 + Z + 32(X))` where (X) = 256
pub(crate) fn gf256_ext32_mul(a: [u8; 4], b: [u8; 4]) -> [u8; 4] {
    let [a0, a1, a2, a3] = a;
    let [b0, b1, b2, b3] = b;

    let leading = gf256_ext16_mul([a2, a3], [b2, b3]);
    let cnst = gf256_ext16_mul([a0, a1], [b0, b1]);
    let sum_a = gf256_ext16_add([a0, a1], [a2, a3]);
    let sum_b = gf256_ext16_add([b0, b1], [b2, b3]);

    let [r0, r1] = gf256_ext16_add(gf256_ext16_mul32(leading), cnst);
    let [r2, r3] = gf256_ext16_add(gf256_ext16_mul(sum_a, sum_b), cnst);

    [r0, r1, r2, r3]
}

/// Sample a value from the extended field `F_q^4 = F_q[Z] / (Z^2 + Z + 32(X))` where (X) = 256
pub(crate) fn gf256_ext32_sample() -> [u8; 4] {
    [
        rand::random::<u8>(),
        rand::random::<u8>(),
        rand::random::<u8>(),
        rand::random::<u8>(),
    ]
}

#[cfg(test)]
mod ext32_tests {
    #[test]
    fn test_add() {
        todo!()
    }

    #[test]
    fn test_mul() {
        todo!()
    }

    #[test]
    fn test_sample() {
        todo!()
    }
}
