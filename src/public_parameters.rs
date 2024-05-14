use crate::{DST_ROBUST_DP_PUBLIC_PARAMS_GENERATION};

use group::Group;



pub struct PublicParameters {
    n_b: usize,
    g: G1Projective,
    h: G1Projective,
}

impl PublicParameters {
    pub fn new(n_b: usize, seed: &[u8]) -> Self {
        let g = G1Projective::generator();
        let h = G1Projective::hash_to_curve(seed, DST_ROBUST_DP_PUBLIC_PARAMS_GENERATION.as_slice(), b"h");
        
        Self {
            n_b,
            g,
            h,
        }
    }

    pub fn get_n_b(&self) -> usize {
        self.n_b
    }

    pub fn get_points(&self) -> Vec<&G1Projective> {
        vec![&self.g, &self.h]
    }
}