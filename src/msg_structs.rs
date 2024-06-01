use blstrs::{G1Projective, Scalar};

use crate::sigma_or::ProofStruct;


use serde::Serialize;

#[derive(Serialize)]
pub struct ComsAndShare{
    pub coms:Vec<G1Projective>,
    pub share:Scalar,
    pub pi:Scalar,
    pub proof:ProofStruct,
}

