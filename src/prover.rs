// ============================================================
use blstrs::{G1Projective, Scalar};
use ff::Field;
use ed25519_dalek::{Keypair, PublicKey, Signature};
use rand::Rng;
use crate::constants;
use crate::commitment::Commit;
use crate::public_parameters::PublicParameters;
use crate::sign::sign_verified_deal;
use crate::share_store::ShareStore;
use crate::replicated::ReplicaShare;
use crate::hash::hash_bit_vec;
use crate::util::random_scalars;
use crate::user_store::UserStore;


pub struct Prover<'a, D:ShareStore> {
    index: usize,
    bit_vector: Vec<Scalar>, //随机比特向量
    s_blinding: Vec<Scalar>,
    coms_v_k: Vec<G1Projective>,
    sig_key: Keypair,
    pks: Vec<PublicKey>,
    share_store: &'a mut D, //the database of shares from clients
}

impl <'a, D:ShareStore> Prover<'a, D> {
    pub fn new(index:usize, pp:&PublicParameters, sig_key_bytes:[u8;64],pks:&Vec<PublicKey>, share_store: &'a mut D) -> Self {
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
            pks:pks.clone(),
            share_store,
        }

    }
    
    pub fn get_coms_v_k(&self) -> Vec<G1Projective> {
        self.coms_v_k.clone()
    }
    
    pub fn handle_client<'b, B :UserStore>(&mut self,client:(u64, ReplicaShare), broad: &'b mut B,pp:&PublicParameters) -> bool {
        let (id, replica_share): (u64, ReplicaShare) = client;
        let (coms, proof) = broad.get_user_commitment_proof(id).unwrap();
        let recon=coms.get_sum();
        if !proof.verify(pp.get_commit_base(), recon) {
            return false;
        }
        if !replica_share.check_com(pp.get_commit_base(), coms.clone()){
            return false;
        }
        self.share_store.put(id, replica_share);
        broad.sig_to_user(id, sign_verified_deal(&self.sig_key, &coms).into(), self.index)
    }
    

    pub fn check_all_users_and_sum_share_and_add_noise<B:UserStore>(&self,pks:&Vec<PublicKey>, broad:&B, pp:&PublicParameters) -> ReplicaShare {
        let mut valid_user_ids=Vec::new();
        let mut sum_share = ReplicaShare::new_zero(self.index);
        let mut all_users = broad.iter_all_users().unwrap();
        while let Some(user) = all_users.next() {
            if user.check_whole(pks, pp) {
                valid_user_ids.push(user.id);
                match self.share_store.get(user.id) {
                    Some(share) => {
                        sum_share = sum_share + share;
                        
                    }
                    None => {
                        sum_share=sum_share+user.share[self.index].clone().unwrap();
                    }
                }
            }
        }
        let valid_user_ids=valid_user_ids.sort();
        let hash_val = hash_bit_vec(&valid_user_ids, constants::BITS_NUM);
        let mut bit_vector_xor = self.bit_vector.clone();
        let mut s_blinding_xor = self.s_blinding.clone();
        for i in 0..constants::BITS_NUM {
            if hash_val[i] {
                bit_vector_xor[i] = Scalar::one() - bit_vector_xor[i];
                s_blinding_xor[i] = Scalar::one() - s_blinding_xor[i];
            }
        }
        let mut noise = Scalar::zero();
        let mut noise_proof = Scalar::zero();
        for i in 0..constants::BITS_NUM {
            noise += bit_vector_xor[i];
            noise_proof += s_blinding_xor[i];
        }
        sum_share.add_noise(noise, noise_proof)

    }


    

}