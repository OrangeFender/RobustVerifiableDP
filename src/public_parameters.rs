use crate::commitment::CommitBase;
use crate::evaluation_domain::{BatchEvaluationDomain, EvaluationDomain};
use blstrs::G1Projective;

#[derive(Clone)]
pub struct PublicParameters {
    n_b: usize,
    prover_num: usize,
    threshold: usize,
    commit_base: CommitBase,

}

impl PublicParameters {
    pub fn new(n_b: usize,prover_num: usize, threshold: usize , seed: &[u8]) -> Self {
        let dom = batch_dom.get_subdomain(prover_num);
        Self {
            n_b,
            prover_num,
            threshold,
            commit_base: CommitBase::new(seed),
        }
    }

    pub fn get_n_b(&self) -> usize {
        self.n_b
    }

    pub fn get_prover_num(&self) -> usize {
        self.prover_num
    }
    
    pub fn get_threshold(&self) -> usize {
        self.threshold
    }

    pub fn get_batch_dom(&self) -> &BatchEvaluationDomain {
        &self.batch_dom
    }

    pub fn get_dom(&self) -> &EvaluationDomain {
        &self.dom
    }

    pub fn get_commit_base(&self) -> &CommitBase {
        &self.commit_base
    }

    pub fn get_g(&self) -> G1Projective {
        self.commit_base.bases[0]
    }

    pub fn get_h(&self) -> G1Projective {
        self.commit_base.bases[1]
    }
}
