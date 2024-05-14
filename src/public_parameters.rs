use crate::commitment::CommitBase;




pub struct PublicParameters {
    n_b: usize,
    pub commit_base: CommitBase,
}

impl PublicParameters {
    pub fn new(n_b: usize, seed: &[u8]) -> Self {
        
        Self {
            n_b,
            commit_base: CommitBase::new(seed),
        }
    }

    pub fn get_n_b(&self) -> usize {
        self.n_b
    }

    
}