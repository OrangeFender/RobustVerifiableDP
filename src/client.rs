use blstrs::{G1Projective, Scalar};
use rand_core::le;
use crate::public_parameters::PublicParameters;
use crate::util;

pub struct Client{
    x_int: usize,
    x_scalar: Scalar,
    r_blinding: Vec<Scalar>,
    f_poly: Vec<Scalar>,
}

impl Client{
    pub fn new(x_int: usize,pp:PublicParameters) -> Self {
        let x_scalar = Scalar::from(x_int as u64);
        let mut r_blinding = Vec::new();
        let mut f_poly = Vec::new();
        
        let length = pp.get_prover_num();
        let mut rng = rand::thread_rng();

        for _ in 0..length {
            r_blinding.push(util::random_scalar(&mut rng));
            f_poly.push(util::random_scalar(&mut rng));
        }

        Self {
            x_int,
            x_scalar,
            r_blinding,
            f_poly,
        }
    }

    
}