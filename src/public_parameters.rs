use crate::commitment::CommitBase;
use curve25519_dalek::ristretto::RistrettoPoint;

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

    pub fn get_g(&self) -> RistrettoPoint {
        self.commit_base.get_g()
    }

    pub fn get_h(&self) -> RistrettoPoint {
        self.commit_base.get_h()
    }
}
