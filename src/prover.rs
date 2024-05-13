use blstrs::{G1Projective, Scalar};
use rand::Rng;
use crate::public_parameters::PublicParameters;
use crate::util;
pub struct Prover {
    bit_vector: Vec<Scalar>, 
}

impl Prover {
    pub fn new(pp:&PublicParameters) -> Self {
        // Generate a random bit vector of length `n_b'`
        let length = pp.get_n_b();
        let mut rng = rand::thread_rng();
        let bit_vector = (0..length).map(|_| util::random_bit_scalar(&mut rng)).collect();
        Self {
            bit_vector,
        }

    }
}