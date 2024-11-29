use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use sha3::{Digest, Sha3_512};


#[derive(Clone)]
pub struct CommitBase{
    pub g: RistrettoPoint,
    pub h: RistrettoPoint,
}

impl CommitBase{
    pub fn new(seed: &[u8]) -> Self {
        let mut hasher = Sha3_512::new();
        hasher.update(seed);
        let h = RistrettoPoint::from_hash(hasher);
        let g = RISTRETTO_BASEPOINT_POINT;

        Self {
            g,
            h,
        }
    }

    pub fn get_g(&self) -> RistrettoPoint {
        self.g
    }

    pub fn get_h(&self) -> RistrettoPoint {
        self.h
    }
}

pub trait Commit{
    fn commit(&self, message:Scalar, blinding:Scalar) -> RistrettoPoint;
    fn vrfy(&self, message:Scalar, blinding:Scalar, com:RistrettoPoint) -> bool;
}

impl Commit for CommitBase{
    fn commit(&self, message:Scalar, blinding:Scalar) -> RistrettoPoint {
        let gm = &message * &self.g;
        let hr = &blinding * &self.h;
    
        let ans = gm + hr;
        return ans
    }
    fn vrfy(&self, message:Scalar, blinding:Scalar, com:RistrettoPoint) -> bool {
        let gm = &message * &self.g;
        let hr = &blinding * &self.h;
        let com_prime = gm + hr;
        com == com_prime
    }
}
