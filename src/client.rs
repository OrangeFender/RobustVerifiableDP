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
    coms_f_x: Vec<G1Projective>,//
}

impl Client{
    pub fn new(x_int: usize,pp:PublicParameters) -> Self {
        let x_scalar = Scalar::from(x_int as u64);

        
        let t = pp.get_threshold();
        let mut rng = rand::thread_rng();

        // let mut r_poly = Vec::new();
        // let mut f_poly = Vec::new();
        // for _ in 0..t {
        //     //random generation of r_blinding and f_poly
        //     r_poly.push(util::random_scalar(&mut rng));
        //     f_poly.push(util::random_scalar(&mut rng));
        // }

        let r_poly = util::random_scalars(t, &mut rng);
        let mut f_poly = util::random_scalars(t, &mut rng);

        f_poly[0] = x_scalar;

        let mut f_evals = fft(&f_poly, pp.get_dom());
        f_evals.truncate(pp.get_prover_num());

        let mut r_evals = fft(&r_poly, pp.get_dom());
        r_evals.truncate(pp.get_prover_num());

        let mut coms_f_x = Vec::new();

        for i in 0..pp.get_prover_num() {
            coms_f_x.push(pp.get_commit_base().commit(f_evals[i], r_evals[i]));
        }

        Self {
            x_int,
            x_scalar,
            r_poly,
            f_poly,
            f_eval: f_evals,
            r_eval: r_evals,
            coms_f_x,
        }
    }

    pub fn get_coms_f_x(&self) -> Vec<G1Projective> {
        self.coms_f_x.clone()
    }

    pub fn send_ith_share(&self, i: usize) -> (Scalar, Scalar) {
        (self.f_eval[i], self.r_eval[i])
    }

}