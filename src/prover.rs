// ============================================================
use blstrs::{G1Projective, Scalar};
use ff::Field;
use ed25519_dalek::{Signature, Keypair, PublicKey, Signer, Verifier};
use crate::constants;
use crate::commitment::Commit;
use crate::msg_structs::ShareProof;
use crate::public_parameters::PublicParameters;
use crate::{msg_structs, sigma_or, util};
use crate::sign::sign_verified_deal;


pub struct Prover {
    index: usize,
    bit_vector: Vec<Scalar>, //随机比特向量
    bit_vector_xor: Vec<Scalar>, //随机比特向量的异或
    s_blinding: Vec<Scalar>,
    s_blinding_xor: Vec<Scalar>,
    coms_v_k: Vec<G1Projective>,
    // ============================================================
    pub(crate) sig_key: Keypair,
    // ============================================================
}

impl Prover {
    pub fn new(index:usize, bool_vector:Vec<bool>, s_blinding:Vec<Scalar>, pp:&PublicParameters, sig_key:Keypair) -> Self {
        // Generate a random bit vector of length `n_b'`
        let length = constants::BITS_NUM;
        let mut rng = rand::thread_rng();
        //let bit_vector: Vec<Scalar> = (0..length).map(|_| util::random_bit_scalar(&mut rng)).collect();
        //let bit_vector = util::random_scalars(length, &mut rng);
        let mut bit_vector = Vec::new();
        for i in 0..length {
            if bool_vector[i] {
                bit_vector.push(Scalar::one());
            } else {
                bit_vector.push(Scalar::zero());
            }
        }

        let mut coms_v_k = Vec::new();
        for i in 0..length {
            //let scalars = [bit_vector[i], s_blinding[i]];
            coms_v_k.push(pp.get_commit_base().commit(bit_vector[i], s_blinding[i]));
        }

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
        }

    }
    
    pub fn get_coms_v_k(&self) -> Vec<G1Projective> {
        self.coms_v_k.clone()
    }





    pub fn verify_msg_and_sig(&self,msg:
        &msg_structs::ShareProof,pp:&PublicParameters)-> Option<Signature>{
        let result = msg.verify(pp.get_commit_base());
        if result {
            Some(sign_verified_deal(&self.sig_key, &msg.coms))
        } else {
            None
        }
    }


    pub fn x_or(&mut self, pp:&PublicParameters, hash_bit_vec:&Vec<bool>) {
        for i in 0..constants::BITS_NUM {
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
     

}