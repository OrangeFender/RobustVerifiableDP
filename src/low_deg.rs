use blstrs::{Scalar, G1Projective};
use group::Group;
use rand::thread_rng;
use std::ops::Mul;


use crate::{evaluation_domain::BatchEvaluationDomain, lagrange::all_lagrange_denominators, util::random_scalars, fft::fft_assign};



pub fn low_deg_test(coms: &Vec<G1Projective>, t: usize, n: usize) -> bool {
    // If the degree is n-1, then the check is trivially true
    if t == n {
        return true; 
    }

    let mut rng = thread_rng();
    let batch_dom = BatchEvaluationDomain::new(n);   
    let vf = get_dual_code_word(t - 1, &batch_dom, n, &mut rng);   
    let ip = G1Projective::multi_exp(&coms, vf.as_ref());
    
    ip.eq(&G1Projective::identity())
}

pub fn get_dual_code_word<R: rand_core::RngCore + rand_core::CryptoRng>(
    deg: usize,
    batch_dom: &BatchEvaluationDomain,
    n: usize,
    mut rng: &mut R,
) -> Vec<Scalar> {
    // The degree-(t-1) polynomial p(X) that shares our secret
    // So, deg = t-1 => t = deg + 1
    // The "dual" polynomial f(X) of degree n - t - 1 = n - (deg + 1) - 1 = n - deg - 2
    let mut f = random_scalars(n - deg - 2, &mut rng);

    // Compute f(\omega^i) for all i's
    let dom = batch_dom.get_subdomain(n);
    fft_assign(&mut f, &dom);
    f.truncate(n);

    // Compute v_i = 1 / \prod_{j \ne i, j \in [0, n-1]} (\omega^i - \omega^j), for all i's
    let v = all_lagrange_denominators(&batch_dom, n);

    // Compute v_i * f(\omega^i), for all i's
    let vf = f
        .iter()
        .zip(v.iter())
        .map(|(v, f)| v.mul(f))
        .collect::<Vec<Scalar>>();

    vf
}