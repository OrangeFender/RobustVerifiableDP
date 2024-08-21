use crate::commitment::CommitBase;
use blstrs::G1Projective;

#[derive(Clone)]
pub struct PublicParameters {
    commit_base: CommitBase,

}

impl PublicParameters {
    pub fn new(seed: &[u8]) -> Self {
        Self {
            commit_base: CommitBase::new(seed),
        }
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
