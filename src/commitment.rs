use blstrs::{G1Projective, Scalar};
use group::Group;
use crate::DST_ROBUST_DP_PUBLIC_PARAMS_GENERATION;

pub struct CommitBase{
    bases: [G1Projective; 2],
}

impl CommitBase{
    pub fn new(seed: &[u8]) -> Self {
        let g = G1Projective::generator();
        let h = G1Projective::hash_to_curve(seed, DST_ROBUST_DP_PUBLIC_PARAMS_GENERATION.as_slice(), b"h");
        Self {
            bases: [g, h],
        }
    }
}

pub trait Commit{
    fn commit(&self, message:Scalar, blinding:Scalar) -> G1Projective;
}

impl Commit for CommitBase{
    fn commit(&self, message:Scalar, blinding:Scalar) -> G1Projective {
        G1Projective::multi_exp(&self.bases, &[message, blinding])
    }
}