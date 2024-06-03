use blstrs::{Scalar, G1Projective};
use ff::Field;
use group::Group;
use crate::util::random_scalars;

pub fn eval_poly_at(p: &[Scalar], x: Scalar) -> Scalar {
    let mut result = Scalar::zero();
    for coeff in p.iter().rev() {
        result = result * x + coeff;
    }
    result
}

pub fn eval_poly_at_1_n(p: &[Scalar], n: usize) -> Vec<Scalar> {
    let mut result = Vec::with_capacity(n);
    for i in 1..=n {
        result.push(eval_poly_at(p, Scalar::from(i as u64)));
    }
    result
}

pub fn low_degree_test(coms: &[G1Projective], degree: usize) -> bool {
    let n = coms.len();
    let new_dgree = n-degree-2;
    let rng= &mut rand::thread_rng();
    let z_poly = random_scalars(new_dgree+1,rng);
    let z_evals = eval_poly_at_1_n(&z_poly, n);
    let mut lambda = vec![Scalar::one(); n];
    for i in 0..n {
        for j in 0..n {
            if i != j {
                lambda[i] *= Scalar::from((i as u64) + 1) - Scalar::from((j as u64) + 1);
            }
        }
        lambda[i] = lambda[i].invert().unwrap();
    }
    let mut product = G1Projective::identity();
    for i in 0..n {
        product += coms[i] * (z_evals[i] * lambda[i]);
    }
    product.is_identity().into()
}

pub fn lagrange_coefficients(xs: &[Scalar])->Vec<Scalar>{
    let n = xs.len();
    let mut lambda = vec![Scalar::one(); n];
    for i in 0..n {
        for j in 0..n {
            if i != j {
                lambda[i] *= xs[j]*((xs[j] - xs[i]).invert().unwrap());
            }
        }
    }
    lambda
}

pub fn recon(share: &[Scalar], xs: &[Scalar])->Scalar{
    let n = xs.len();
    let lambda = lagrange_coefficients(xs);
    let mut result = Scalar::zero();
    for i in 0..n {
        result += share[i]*lambda[i];
    }
    result
}

pub fn recon_u64(share: &[Scalar], xs: &[u64])->Scalar{
    let new_xs: Vec<Scalar> = xs.iter().map(|x| Scalar::from(*x)).collect();
    recon(share, &new_xs)
}

pub fn recon_com(coms: &[G1Projective], xs: &[Scalar])->G1Projective{
    let n = xs.len();
    let lambda = lagrange_coefficients(xs);
    let mut result = G1Projective::identity();
    for i in 0..n {
        result += coms[i]*lambda[i];
    }
    result
}

pub fn recon_com_u64(coms: &[G1Projective], xs: &[u64])->G1Projective{
    let new_xs: Vec<Scalar> = xs.iter().map(|x| Scalar::from(*x)).collect();
    recon_com(coms, &new_xs)
}


pub fn gcd(a: u64, b: u64) -> u64 {
    if b == 0 {
        a
    } else {
        gcd(b, a % b)
    }
}

//计算出拉格朗日基多项式的分母（的倍数）
pub fn get_denominator(xs: &[u64]) -> u64 {

    let mut result = 1;
    for i in 0..xs.len() {
        let mut temp =1;
        for j in i+1..xs.len() {
            if i!=j{
                temp*=xs[j]-xs[i];
            }
        }
        result *= temp/gcd(result,temp);
    }
    result
}
#[cfg(test)]
mod tests {
    use super::*;
    use blstrs::{G1Projective, Scalar};
    use rand::thread_rng;
    use group::Group; // Import the Group trait for G1Projective
    use crate::util::random_scalars;

    #[test]
    fn test_low_degree_test() {
        let mut rng = thread_rng();

        // Degree of the polynomial
        let degree = 5;

        // Generate a random polynomial of degree `degree`
        let poly = random_scalars(degree + 1, &mut rng);

        // Evaluate the polynomial at points 1, 2, ..., n
        let n = 8;
        let evals = eval_poly_at_1_n(&poly, n);

        // Commitments: Just use the scalar evaluations as dummy commitments for testing
        let coms: Vec<G1Projective> = evals.iter().map(|e| G1Projective::generator() * e).collect();

        // Perform the low degree test
        let result = low_degree_test(&coms, degree);

        // For the purpose of this test, we expect `true` because the polynomial degree is within the allowed range
        assert!(result);
    }

    #[test]
    fn test_low_degree_test_fail() {
        let mut rng = thread_rng();

        // Degree of the polynomial
        let degree = 5;

        // Generate a random polynomial of degree `degree + 1` to ensure it fails the test
        let poly = random_scalars(degree + 2, &mut rng);

        // Evaluate the polynomial at points 1, 2, ..., n
        let n = 8;
        let evals = eval_poly_at_1_n(&poly, n);

        // Commitments: Just use the scalar evaluations as dummy commitments for testing
        let coms: Vec<G1Projective> = evals.iter().map(|e| G1Projective::generator() * e).collect();

        // Perform the low degree test
        let result = low_degree_test(&coms, degree);

        // For the purpose of this test, we expect `false` because the polynomial degree exceeds the allowed range
        assert!(!result);
    }

    #[test]
    fn test_recon() {
        let mut rng = thread_rng();

        // Degree of the polynomial
        let degree = 3;

        // Generate a random polynomial of degree `degree`
        let poly = random_scalars(degree + 1, &mut rng);

        // Evaluate the polynomial at points 1, 2, ..., n
        let n = 8;
        let evals = eval_poly_at_1_n(&poly, n);

        let xs: Vec<Scalar> = (1..=(degree+1)).map(|i| Scalar::from(i as u64)).collect();
        // Perform the reconstruction
        let recon_value = recon(&evals[0..(degree+1)], &xs);

        // The expected value is the evaluation of the polynomial at x = 0 (constant term of the polynomial)
        let expected_value = poly[0];
        // Verify that the reconstructed value matches the expected value
        assert_eq!(recon_value, expected_value);
    }

    #[test]
    fn test_recon_com() {
        let mut rng = thread_rng();

        // Degree of the polynomial
        let degree = 5;

        let f_poly = random_scalars(degree + 1, &mut rng);
        let r_poly = random_scalars(degree + 1, &mut rng);

        // Evaluate the polynomial at points 1, 2, ..., n
        let n = 8;
        let f_evals = eval_poly_at_1_n(&f_poly, n);
        let r_evals = eval_poly_at_1_n(&r_poly, n);

        let g= G1Projective::generator();
        let h = G1Projective::hash_to_curve(b"seed", b"dst", b"aug");

        //com i = g^{f_i} h^{r_i}
        let coms: Vec<G1Projective> = f_evals.iter().zip(r_evals.iter()).map(|(f, r)| g * f + h * r).collect();
        let expected_com0 = g * f_poly[0] + h * r_poly[0];

        let xs: Vec<Scalar> = (1..=degree+1).map(|i| Scalar::from(i as u64)).collect();
        // Perform the reconstruction
        let recon_com = recon_com(&coms[0..degree+1], &xs);

        // Verify that the reconstructed value matches the expected value
        assert_eq!(recon_com, expected_com0);
        
    }
}
