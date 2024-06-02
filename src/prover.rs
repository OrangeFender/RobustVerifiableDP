// ============================================================
use aptos_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature};
use blstrs::{G1Projective, Scalar};
use ff::Field;

use crate::commitment::Commit;
use crate::public_parameters::PublicParameters;
use crate::{msg_structs, sigma_or, util};
use crate::sig::sign_verified_deal;
use crate::low_deg::low_deg_test;
use crate::recon::reconstruct_com;

pub struct Prover {
    index: usize,
    bit_vector: Vec<Scalar>, //随机比特向量
    bit_vector_xor: Vec<Scalar>, //随机比特向量的异或
    s_blinding: Vec<Scalar>,
    s_blinding_xor: Vec<Scalar>,
    coms_v_k: Vec<G1Projective>,
    //coms_v_k_xor: Vec<G1Projective>,
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
            bit_vector_xor: Vec::new(),
            s_blinding_xor: Vec::new(),
            coms_v_k,
            //coms_v_k_xor: Vec::new(),
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

    pub fn input_shares(&mut self,f:Scalar, r:Scalar) {
        //assert!(pp.get_commit_base().vrfy(f, r, com));
        self.share_f_i_k.push(f);
        self.share_r_i_k.push(r);
    }

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

    pub fn triple_check(&self, coms: &Vec<G1Projective>, pp:&PublicParameters, f_i_k: &Scalar, r_i_k: &Scalar, sigma_or_struct:&sigma_or::ProofStruct) -> bool {
        let commit_valid = pp.get_commit_base().vrfy(f_i_k.clone(), r_i_k.clone(), coms[self.index].clone());
        let deg_valid = low_deg_test(&coms, pp.get_threshold(), pp.get_prover_num());
        let reconcom=reconstruct_com(&coms, pp.get_threshold());
        let sigma_or_valid = sigma_or::sigma_or_verify( pp.get_commit_base(),&sigma_or_struct, reconcom);
        commit_valid && deg_valid && sigma_or_valid
    }


    pub fn verify_msg_and_sig(&self,msg:
        &msg_structs::ComsAndShare,pp:&PublicParameters)-> Option<Ed25519Signature>{
        let result = Self::triple_check(&self, &msg.coms, &pp, &msg.share, &msg.pi, &msg.proof);
        if result {
            Some(sign_verified_deal(&self.sig_key, &msg.coms))
        } else {
            None
        }
    }


    pub fn x_or(&mut self, pp:&PublicParameters, hash_bit_vec:&Vec<bool>) {
        for i in 0..pp.get_n_b() {
            if hash_bit_vec[i] {
                self.bit_vector_xor.push(Scalar::one()-self.bit_vector[i].clone());
                self.s_blinding_xor.push(Scalar::one()-self.s_blinding[i].clone());
            }
            else {
                self.bit_vector_xor.push(self.bit_vector[i].clone());
                self.s_blinding_xor.push(self.s_blinding[i].clone());
            }
        }
        //self.coms_v_k_xor = xor_commitments(&self.coms_v_k, hash_bit_vec, pp.get_g(), pp.get_h())
    }
    pub fn calc_output(&self, pp:&PublicParameters) -> (Scalar,Scalar) {
        let mut res=Scalar::zero();
        let mut proof = Scalar::zero();
        for i in 0..pp.get_n_b() {
            res=res+&self.bit_vector_xor[i].clone();
            proof=proof+&self.s_blinding_xor[i].clone();
        }
        for i in 0..self.share_f_i_k.len() {
            res=res+&self.share_f_i_k[i].clone();
            proof=proof+&self.share_r_i_k[i].clone();
        }
        (res,proof)
    }


}