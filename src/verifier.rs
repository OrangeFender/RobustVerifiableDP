use blstrs::G1Projective;
use group::Group;
use ed25519_dalek::PublicKey;
use crate::constants;
use crate::public_parameters::PublicParameters;
use crate::share_store::{ShareStore, CommitmentStore};
use crate::replicated::{ReplicaShare, ReplicaCommitment};
use crate::hash::hash_bit_vec;

pub struct VerifierBroad<'a, D:ShareStore, C:CommitmentStore> {
    coms_v_ks: Vec<Vec<G1Projective>>,
    sig_keys: Vec<PublicKey>,
    share_stores: Vec<&'a mut D>,
    commitment_store: &'a mut C,
}


/// TODO: the coms_v_ks should be verified by the verifier with the sigma_or_proof
impl <'a, D:ShareStore, C:CommitmentStore> VerifierBroad<'a, D, C> {
    pub fn new(coms_v_ks: Vec<Vec<G1Projective>>, sig_keys: Vec<PublicKey>, share_stores: Vec<&'a mut D>, commitment_store: &'a mut C) -> Self {
        for i in 0..constants::PROVER_NUM {
            assert_eq!(coms_v_ks[i].len(), constants::BITS_NUM);
        }
        assert_eq!(share_stores.len(),constants::PROVER_NUM);
        Self {
            coms_v_ks,
            sig_keys,
            share_stores,
            commitment_store,
        }
    }

    pub fn handle_trancript(&mut self, transcript:msg_structs::Transcript, pp:&PublicParameters) -> bool {
        let result = transcript.verify(pp.get_commit_base(),&self.sig_keys);
        if !result {
            return false;
        }
        else{
            let uid = transcript.uid;
            self.commitment_store.put(uid,transcript.coms.clone());
            for i in 0..constants::PROVER_NUM {
                let sig_or_share = &transcript.sigs_and_shares[i];
                match sig_or_share {
                    msg_structs::SigOrShare::Signature(_) => {
                        // Do nothing
                    },
                    msg_structs::SigOrShare::Share(share) => {
                        self.share_stores[i].put(uid,share.clone());
                    },
                }
            }
            return true;
        }
    }

    pub fn list_clients(&self)->Vec<u64>{
        self.commitment_store.get_all_uids()
    }

    pub fn aggregate_coms(&self)->ReplicaCommitment{
        self.commitment_store.sum()
    }

    /// this function verifies the share of prover
    pub fn handle_prover_share(&self,ind:usize,share:ReplicaShare, aggregated_com:ReplicaCommitment, uids: Vec<u64>, pp:&PublicParameters)->bool{
        let prover_id=share.get_ind();
        if ind!=prover_id{
            return false;
        }
        let hash_val = hash_bit_vec(&uids, constants::BITS_NUM);
        let mut coms_x_or = self.coms_v_ks[prover_id].clone();
        let g=pp.get_g();
        let h=pp.get_h();

        for i in 0..constants::BITS_NUM{
            if hash_val[i]{
                coms_x_or[i]=g+h-coms_x_or[i];
            }
            else{
                continue;
            }
        }
        let mut noise_commitment = G1Projective::identity();
        for i in 0..constants::BITS_NUM{
            noise_commitment+=coms_x_or[i];
        }

        if share.check_com_with_noise(pp.get_commit_base(),aggregated_com,noise_commitment){
            return true;
        }
        else{
            return false;
        }
    }

    pub fn get_share(&self, proverid:usize, uid:u64)->ReplicaShare{
        self.share_stores[proverid].get(uid).unwrap()
    }


}