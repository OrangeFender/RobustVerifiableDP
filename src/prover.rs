// ============================================================
use aptos_bitvec::BitVec;
use aptos_crypto::{Uniform, Signature};
use aptos_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature};
use aptos_crypto::multi_ed25519::{MultiEd25519PublicKey, MultiEd25519Signature};
use aptos_crypto::test_utils::{TEST_SEED, KeyPair};
// ============================================================
use blstrs::{G1Projective, Scalar};
use rand::Rng;
use rand_core::le;

use crate::commitment::Commit;
use crate::public_parameters::PublicParameters;
use crate::util;
pub struct Prover {
    bit_vector: Vec<Scalar>, 
    s_blinding: Vec<Scalar>,
    coms_v_k: Vec<G1Projective>,
    // ============================================================
    pub(crate) sig_key: Ed25519PrivateKey,
    // ============================================================
    shares_coms: Vec<Vec<G1Projective>>,
}

impl Prover {
    pub fn new(pp:&PublicParameters, sig_key:Ed25519PrivateKey) -> Self {
        // Generate a random bit vector of length `n_b'`
        let length = pp.get_n_b();
        let mut rng = rand::thread_rng();
        //let bit_vector: Vec<Scalar> = (0..length).map(|_| util::random_bit_scalar(&mut rng)).collect();
        let bit_vector = util::random_scalars(length, &mut rng);
        //let s_blinding: Vec<Scalar> = (0..length).map(|_| util::random_scalar(&mut rng)).collect();
        let s_blinding = util::random_scalars(length, &mut rng);

        let mut coms_v_k = Vec::new();
        for i in 0..length {
            //let scalars = [bit_vector[i], s_blinding[i]];
            coms_v_k.push(pp.get_commit_base().commit(bit_vector[i], s_blinding[i]));
        }

        let shares_coms = Vec::new();

        Self {
            bit_vector,
            s_blinding,
            coms_v_k,
            shares_coms,
            sig_key,
        }

    }
    
    pub fn get_coms_v_k(&self) -> Vec<G1Projective> {
        self.coms_v_k.clone()
    }

    pub fn input_shares_coms(coms_f_x) -> Self {

    }
}