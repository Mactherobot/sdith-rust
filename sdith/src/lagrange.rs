// Imagine you have a set of data points. These points represent the values of a function at specific points. Your goal is to find a polynomial that passes exactly through all these points. Lagrange interpolation is a method to construct such a polynomial.

use std::iter;

/// Given a set of points, this function returns the Lagrange basis polynomials on `x_value`
///
/// Returns the result of the interpolation at the given x value.
pub(crate) fn lagrange_interpolation(
    // The points (x,y) to interpolate.
    points: &Vec<(f64, f64)>,
    x_value: &f64,
    weights: Option<Vec<f64>>,
) -> f64 {
    assert!(
        x_value > &points.first().expect("Must not be empty.").0
            && x_value < &points.last().expect("Must not be empty.").0
    );

    let x_points: Vec<f64> = points.iter().map(|(x, _)| *x).collect();
    let weights: Vec<f64> = weights.unwrap_or(_newton_calculate_weights(&x_points));
    let numerator = _newton_calculate_numerator(&x_points, x_value);

    let mut result = 0.0;
    for (j, (x_j, y_j)) in points.iter().enumerate() {
        result += weights[j] * y_j / (x_value - x_j);
    }

    return result * numerator;
}

/// Calculate the weights for the newton method for lagrange interpolation. Runs in O(n^2).
/// Based on https://math.umd.edu/~petersd/666/BarycentricLagrange1.pdf
fn _newton_calculate_weights(x_points: &Vec<f64>, // x points to interpolate.
) -> Vec<f64> {
    // w^(0) = [1]
    let n = x_points.len();
    let mut w: Vec<f64> = iter::repeat(0.0).take(n).collect();

    for j in 0..n {
        w[j] = 1.0;
        for k in 0..j {
            w[k] = w[k] / (x_points[k] - x_points[j]);
            w[j] = w[j] / (x_points[j] - x_points[k]);
        }
    }

    return w;
}

/// Calculate `l(x) = (x-x_0)(x-x_1)...(x-x_n)` for the newton method for lagrange interpolation.
fn _newton_calculate_numerator(x_points: &Vec<f64>, x: &f64) -> f64 {
    let n = x_points.len();
    let mut numerator: f64 = 1.0;

    for j in 0..n {
        numerator *= x - x_points[j];
    }

    numerator
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interpolate_sin() {
        let table = vec![(0.0, 0.0), (30.0, 0.5), (60.0, 0.86603), (90.0, 1.0)];
        let res = lagrange_interpolation(&table, &51.0, None);
        assert!((res - 0.7771).abs() <= 1e-3);
    }
}
