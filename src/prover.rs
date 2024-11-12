// ============================================================
use blstrs::{G1Projective, Scalar};
use ff::Field;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::Rng;
use crate::{constants, util};
use crate::commitment::Commit;
use crate::public_parameters::PublicParameters;
use crate::sign::sign_verified_deal;
use crate::share_store::ShareStore;
use crate::replicated::ReplicaShare;
use crate::util::random_scalars;
use crate::user_store::UserStore;

pub struct Prover<'a, D:ShareStore> {
    pp: PublicParameters,
    index: usize,
    bit_vector: Vec<Vec<Scalar>>, //随机比特向量
    s_blinding: Vec<Vec<Scalar>>,
    coms_v_k: Vec<Vec<G1Projective>>,
    sig_key: SigningKey,
    pks: Vec<VerifyingKey>,
    share_store: &'a mut D, //the database of shares from clients
    
}

impl <'a, D:ShareStore> Prover<'a, D> {
    pub fn new(index:usize, pp:&PublicParameters, sig_key:SigningKey,pks:&Vec<VerifyingKey>, share_store: &'a mut D) -> Self {
        let mut rng = rand::thread_rng();
        let mut s_blinding=Vec::new();
        let mut bit_vector = Vec::new();


        for _ in 0..constants::SHARE_LEN {
            s_blinding.push(random_scalars(constants::BITS_NUM, &mut rng));
            bit_vector.push(Vec::new());
        }

        for i in 0..constants::SHARE_LEN {
            for _ in 0..constants::BITS_NUM {
                if rng.gen_bool(0.5) {
                    bit_vector[i].push(Scalar::one());
                } else {
                    bit_vector[i].push(Scalar::zero());
                }
            }
        }

        let mut coms_v_k = Vec::new();
        for i in 0..constants::SHARE_LEN {
            coms_v_k.push(Vec::new());
            for j in 0..constants::BITS_NUM {
                coms_v_k[i].push(pp.get_commit_base().commit(bit_vector[i][j], s_blinding[i][j]));
            }
        }


        Self {
            pp: pp.clone(),
            index,
            bit_vector,
            s_blinding,
            coms_v_k,
            sig_key,
            pks:pks.clone(),
            share_store,
        }

    }
    
    pub fn get_coms_v_k(&self) -> Vec<Vec<G1Projective>> {
        self.coms_v_k.clone()
    }
    
    pub fn handle_client<'b, B :UserStore>(&mut self,client:(u64, ReplicaShare), broad: &'b mut B) -> bool {
        let (id, replica_share): (u64, ReplicaShare) = client;
        let (coms, proof) = broad.get_user_commitment_proof(id).unwrap();
        let recon=coms.get_sum();
        if !proof.verify(self.pp.get_commit_base(), recon) {
            return false;
        }
        if !replica_share.check_com(self.pp.get_commit_base(), coms.clone()){
            return false;
        }
        self.share_store.put(id, replica_share);
        broad.sig_to_user(id, sign_verified_deal(&self.sig_key, &coms).into(), self.index)
    }
    



    pub fn check_all_users_and_sum_share<B:UserStore>(&self, broad:&B) -> ReplicaShare {
        let mut valid_user_ids=Vec::new();
        let mut sum_share = ReplicaShare::new_zero(self.index);
        let mut all_users = broad.iter_all_users().unwrap();
        while let Some(user) = all_users.next() {
            if user.check_whole(&self.pks, &self.pp) {
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
        sum_share

    }

    pub fn check_all_users<B:UserStore>(&mut self, broad:&B) -> Vec<u64> {
        let mut valid_user_ids=Vec::new();
        let mut all_users = broad.iter_all_users().unwrap();
        while let Some(user) = all_users.next() {
            let (res, share) = user.check_whole_lazy(&self.pks, &self.pp, self.index);
            if res {
                valid_user_ids.push(user.id);
            }
            if let Some(share) = share {
                self.share_store.put(user.id, share);
            }
        }
        valid_user_ids
    }

    pub fn sum_share<B:UserStore>(&self, broad:&B, valid_user_ids:&Vec<u64>) -> ReplicaShare {
        let mut sum_share = ReplicaShare::new_zero(self.index);
        for id in valid_user_ids {
            match self.share_store.get(*id) {
                Some(share) => {
                    sum_share = sum_share + share;
                }
                None => {
                    let user = broad.get_user(*id).unwrap();
                    sum_share = sum_share + user.share[self.index].clone().unwrap();
                }
            }
        }
        sum_share
    }

    pub fn add_noise_from_rand_bits(&self, pub_rand_bits:&Vec<Vec<bool>>,share:ReplicaShare) -> ReplicaShare {
        let mut bit_vector_xor = self.bit_vector.clone();
        let mut s_blinding_xor = self.s_blinding.clone();
        for i in 0..constants::SHARE_LEN {
            for j in 0..constants::BITS_NUM {
                if pub_rand_bits[i][j] {
                    bit_vector_xor[i][j] = Scalar::one() - bit_vector_xor[i][j];
                    s_blinding_xor[i][j] = Scalar::one() - s_blinding_xor[i][j];
                }
            }
        }

        let mut noise = Vec::new();
        let mut noise_proof = Vec::new();
        for _ in 0..constants::SHARE_LEN {
            noise.push(Scalar::zero());
            noise_proof.push(Scalar::zero());
        }
        for i in 0..constants::SHARE_LEN {
            for j in 0..constants::BITS_NUM {
                noise[i] += bit_vector_xor[i][j];
                noise_proof[i] += s_blinding_xor[i][j];
            }
        }
        share.add_noise(noise, noise_proof)
    }



}