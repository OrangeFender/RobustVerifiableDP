// ============================================================
use blstrs::{G1Projective, Scalar};
use ff::Field;
use ed25519_dalek::{Signature, Keypair};
use rand::Rng;
use crate::constants;
use crate::commitment::Commit;
use crate::public_parameters::PublicParameters;
use crate::msg_structs;
use crate::sign::sign_verified_deal;
use crate::datastore::ShareStore;
use crate::replicated::ReplicaShare;
use crate::hash::hash_bit_vec;
use crate::util::random_scalars;

pub struct Prover<'a, D:ShareStore> {
    index: usize,
    bit_vector: Vec<Scalar>, //随机比特向量
    s_blinding: Vec<Scalar>,
    coms_v_k: Vec<G1Projective>,
    sig_key: Keypair,
    share_store: &'a mut D, //the database of shares from clients
}

impl <'a, D:ShareStore> Prover<'a, D> {
    pub fn new(index:usize, pp:&PublicParameters, sig_key_bytes:[u8;64], share_store: &'a mut D) -> Self {
        let length = constants::BITS_NUM;
        let mut rng = rand::thread_rng();
        let mut bool_vector = Vec::new();
        let s_blinding = random_scalars(constants::BITS_NUM, &mut rng);
        for _ in 0..length {
            bool_vector.push(rng.gen::<bool>());
        }
        let length = constants::BITS_NUM;
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

        let sig_key=Keypair::from_bytes(sig_key_bytes.as_slice()).unwrap();


        Self {
            index,
            bit_vector,
            s_blinding,
            coms_v_k,
            sig_key,
            share_store,
        }

    }
    
    pub fn get_coms_v_k(&self) -> Vec<G1Projective> {
        self.coms_v_k.clone()
    }

    /// Handle a message from a client, including
    /// 1. Verifying the share is corresponding to the commitment
    /// 2. Verify the sigma-or proof
    /// 3. Sign the deal
    /// 4. Store the share

    pub fn handle_msg(&mut self, msg:&msg_structs::ShareProof,pp:&PublicParameters)-> Option<Signature>{
        let result = msg.verify(self.index, pp.get_commit_base());
        if result {
            self.share_store.put(msg.uid, msg.share.clone());
            Some(sign_verified_deal(&self.sig_key, &msg.coms))
        } else {
            None
        }
    }


    /// # Arguments
    /// * `uid_list` - The list of uids of clients
    /// * `get_share_from_verifier` - A function that returns the share of a client given its uid
    /// which is used to get the share from the verifier if the share is not in the share store
    pub fn response_verifier<F>(&self, uid_list: Vec<u64>, get_share_from_verifier: F) -> ReplicaShare
    where
        F: Fn(u64) -> ReplicaShare,
    {
        let mut share = ReplicaShare::new_zero(self.index);
        for uid in &uid_list {
            if let Some(s) = self.share_store.get(*uid) {
                share = share + s;
            } else {
                let s = get_share_from_verifier(*uid);
                share = share + s;
            }
        }
        let hash_val = hash_bit_vec(&uid_list, constants::BITS_NUM);

        let mut bit_vector_xor = self.bit_vector.clone();
        let mut s_blinding_xor = self.s_blinding.clone();

        for i in 0..constants::BITS_NUM {
            if hash_val[i] {
                bit_vector_xor[i] = Scalar::one() - bit_vector_xor[i];
                s_blinding_xor[i] = Scalar::one() - s_blinding_xor[i];
            }
        }

        let mut noise = Scalar::zero();
        let mut noise_proof =Scalar::zero();

        for i in 0..constants::BITS_NUM {
            noise += bit_vector_xor[i];
            noise_proof += s_blinding_xor[i];
        }

        share.add_noise(noise, noise_proof)
    }


}