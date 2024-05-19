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
use crate::sig::{sign_verified_deal};
use crate::low_deg::low_deg_test;
pub struct Prover {
    index: usize,
    bit_vector: Vec<Scalar>, //随机比特向量
    s_blinding: Vec<Scalar>,
    s_blinding_xor: Vec<Scalar>,
    coms_v_k: Vec<G1Projective>,
    coms_v_k_xor: Vec<G1Projective>,
    // ============================================================
    pub(crate) sig_key: Ed25519PrivateKey,
    pub(crate) vrfy_key: Ed25519PublicKey,
    // ============================================================
    // shares_coms: Vec<G1Projective>,
    share_f_i_k: Vec<Scalar>,//长度是Client的数量
    share_r_i_k: Vec<Scalar>,//长度是Client的数量
    valid_shares: Vec<bool>,//长度是Client的数量
}

impl Prover {
    pub fn new(index:usize, pp:&PublicParameters, sig_key:Ed25519PrivateKey, vrfy_key:Ed25519PublicKey) -> Self {
        // Generate a random bit vector of length `n_b'`
        let length = pp.get_n_b();
        let mut rng = rand::thread_rng();
        //let bit_vector: Vec<Scalar> = (0..length).map(|_| util::random_bit_scalar(&mut rng)).collect();
        //let bit_vector = util::random_scalars(length, &mut rng);
        let mut bit_vector = Vec::new();
        for _ in 0..length {
            bit_vector.push(util::random_bit_scalar(&mut rng));
        }


        //let s_blinding: Vec<Scalar> = (0..length).map(|_| util::random_scalar(&mut rng)).collect();
        let s_blinding = util::random_scalars(length, &mut rng);

        let mut coms_v_k = Vec::new();
        for i in 0..length {
            //let scalars = [bit_vector[i], s_blinding[i]];
            coms_v_k.push(pp.get_commit_base().commit(bit_vector[i], s_blinding[i]));
        }

        // let shares_coms = Vec::new();
        let share_f_i_k = Vec::new();
        let share_r_i_k = Vec::new();
        let valid_shares = Vec::new();
        Self {
            index,
            bit_vector,
            s_blinding,
            s_blinding_xor: Vec::new(),
            coms_v_k,
            coms_v_k_xor: Vec::new(),
            // shares_coms,
            sig_key,
            vrfy_key,
            share_f_i_k,
            share_r_i_k,
            valid_shares,
        }

    }
    
    pub fn get_coms_v_k(&self) -> Vec<G1Projective> {
        self.coms_v_k.clone()
    }

    // pub fn input_shares_coms(coms_f_x) -> Self {
    // }

    fn double_check(ind:usize, coms: &Vec<G1Projective>, pp:&PublicParameters, f_i_k: Scalar, r_i_k: Scalar) -> bool {
        let commit_valid = pp.get_commit_base().vrfy(f_i_k, r_i_k, coms[ind].clone());
        let deg_valid = low_deg_test(&coms, pp.get_threshold(), pp.get_prover_num());
        commit_valid && deg_valid
    }



    pub fn verify_share_and_sig(&self, coms: &Vec<G1Projective>, pp:&PublicParameters, f_i_k: Scalar, r_i_k: Scalar) -> Option<Ed25519Signature> {
        let result = Self::double_check(self.index, coms, pp, f_i_k, r_i_k);
        if result {
            Some(sign_verified_deal(&self.sig_key, &coms))
        } else {
            None
        }
    }


}