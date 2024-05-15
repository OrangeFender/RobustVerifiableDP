use crate::commitment::CommitBase;




pub struct PublicParameters {
    n_b: usize,
    prover_num: usize,
    threshold: usize,
    pub commit_base: CommitBase,
}

impl PublicParameters {
    pub fn new(n_b: usize,prover_num: usize, threshold: usize , seed: &[u8]) -> Self {
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
}