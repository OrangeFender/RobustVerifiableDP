use blstrs::{G1Projective, Scalar};
use rand::Rng;
use rand_core::le;
use crate::public_parameters::PublicParameters;
use crate::util;
pub struct Prover {
    bit_vector: Vec<Scalar>, 
    s_blinding: Vec<Scalar>,
}

impl Prover {
    pub fn new(pp:&PublicParameters) -> Self {
        // Generate a random bit vector of length `n_b'`
        let length = pp.get_n_b();
        let mut rng = rand::thread_rng();
        let bit_vector = (0..length).map(|_| util::random_bit_scalar(&mut rng)).collect();
        
        let s_blinding = (0..length).map(|_| util::random_scalar(&mut rng)).collect();
        
        
        Self {
            bit_vector,
            s_blinding,
        }

    }
}