use blstrs::{G1Projective, Scalar};
use crate::commitment::Commit;
use crate::public_parameters::PublicParameters;
use crate::util;
use crate::fft::fft;

pub struct Client{
    x_int: usize,
    x_scalar: Scalar,
    r_poly: Vec<Scalar>,//commitment blinding factor's polynomial coefficients
    f_poly: Vec<Scalar>,//polynomial coefficients
    f_eval: Vec<Scalar>,//
    r_eval: Vec<Scalar>,//
    coms_f_i: Vec<G1Projective>,//
}

impl Client{
    pub fn new(x_int: usize,pp:PublicParameters) -> Self {
        let x_scalar = Scalar::from(x_int as u64);
        let mut r_poly = Vec::new();
        let mut f_poly = Vec::new();
        
        let t = pp.get_threshold();
        let mut rng = rand::thread_rng();

        for _ in 0..t {
            //random generation of r_blinding and f_poly
            r_poly.push(util::random_scalar(&mut rng));
            f_poly.push(util::random_scalar(&mut rng));
        }

        f_poly[0] = x_scalar;

        let mut f_evals = fft(&f_poly, pp.get_dom());
        f_evals.truncate(pp.get_prover_num());

        let mut r_evals = fft(&r_poly, pp.get_dom());
        r_evals.truncate(pp.get_prover_num());

        let mut coms_f_i = Vec::new();

        for i in 0..pp.get_prover_num() {
            coms_f_i.push(pp.get_commit_base().commit(f_evals[i], r_evals[i]));
        }

        Self {
            x_int,
            x_scalar,
            r_poly,
            f_poly,
            f_eval: f_evals,
            r_eval: r_evals,
            coms_f_i,
        }
    }

}