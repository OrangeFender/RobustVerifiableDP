use blstrs::{G1Projective, Scalar};
use group::Group;
use crate::DST_ROBUST_DP_PUBLIC_PARAMS_GENERATION;


#[derive(Clone)]
pub struct CommitBase{
    pub bases: [G1Projective; 2],
}

impl CommitBase{
    pub fn new(seed: &[u8]) -> Self {
        let g = G1Projective::generator();
        let h = G1Projective::hash_to_curve(seed, DST_ROBUST_DP_PUBLIC_PARAMS_GENERATION.as_slice(), b"h");
        Self {
            bases: [g, h],
        }
    }

    pub fn get_g(&self) -> G1Projective {
        self.bases[0]
    }

    pub fn get_h(&self) -> G1Projective {
        self.bases[1]
    }
}

pub trait Commit{
    fn commit(&self, message:Scalar, blinding:Scalar) -> G1Projective;
    fn vrfy(&self, message:Scalar, blinding:Scalar, com:G1Projective) -> bool;
}

impl Commit for CommitBase{
    fn commit(&self, message:Scalar, blinding:Scalar) -> G1Projective {
        G1Projective::multi_exp(&self.bases, &[message, blinding])
    }
    fn vrfy(&self, message:Scalar, blinding:Scalar, com:G1Projective) -> bool {
        let com_prime = G1Projective::multi_exp(&self.bases, &[message, blinding]);
        com == com_prime
    }
}
