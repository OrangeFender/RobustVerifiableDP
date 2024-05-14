use blstrs::{G1Projective, Scalar};
use rand::Rng;
use rand_core::le;
use crate::commitment::Commit;
use crate::public_parameters::PublicParameters;
use crate::util;
pub struct Prover {
    bit_vector: Vec<Scalar>, 
    s_blinding: Vec<Scalar>,
    coms_v_k: Vec<G1Projective>,
}

impl Prover {
    pub fn new(pp:&PublicParameters) -> Self {
        // Generate a random bit vector of length `n_b'`
        let length = pp.get_n_b();
        let mut rng = rand::thread_rng();
        let bit_vector: Vec<Scalar> = (0..length).map(|_| util::random_bit_scalar(&mut rng)).collect();
        
        let s_blinding: Vec<Scalar> = (0..length).map(|_| util::random_scalar(&mut rng)).collect();
        
        let mut coms_v_k = Vec::new();
        for i in 0..length {
            //let scalars = [bit_vector[i], s_blinding[i]];
            coms_v_k.push(pp.commit_base.commit(bit_vector[i], s_blinding[i]));
        }

        Self {
            bit_vector,
            s_blinding,
            coms_v_k,
        }

    }
    
    pub fn get_coms_v_k(&self) -> Vec<G1Projective> {
        self.coms_v_k.clone()
    }
}