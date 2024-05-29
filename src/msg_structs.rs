use blstrs::{G1Projective, Scalar};

use crate::sigma_or::ProofStruct;



pub struct coms_and_share{
    pub coms:Vec<G1Projective>,
    pub share:Scalar,
    pub pi:Scalar,
    pub proof:ProofStruct,
}