use crate::constants;
use crate::replicated::{ReplicaShare, ReplicaCommitment};
use crate::sigma_or::ProofStruct;
use crate::sign::{MySignature,verify_sig};
use crate::public_parameters::PublicParameters;
use ed25519_dalek::VerifyingKey;
use serde::de;
use std::collections::HashMap;
use std::sync::RwLock;
use std::collections::HashSet;


#[derive(Clone)]
pub struct User{
    pub id: u64,
    pub commitment: ReplicaCommitment,
    pub sigma_proof: ProofStruct,
    pub signatures: [Option<MySignature>; constants::PROVER_NUM],
    pub share: [Option<ReplicaShare>; constants::PROVER_NUM]
}


impl User {
    pub fn check_signature(&self, pks: &Vec<VerifyingKey>) -> HashSet<usize> {
        let mut res = HashSet::new();
        for i in 0..constants::PROVER_NUM {
            if let Some(sig) = &self.signatures[i] {
                if verify_sig(&self.commitment, &pks[i], &sig.clone().into()) {
                    res.insert(i);
                }
            }
        }
        res
    }


    pub fn check_share(&self, pp: &PublicParameters) -> HashSet<usize> {
        let mut res = HashSet::new();
        for i in 0..constants::PROVER_NUM {
            if let Some(share) = &self.share[i] {
                if share.check_com(pp.get_commit_base(), self.commitment.clone()) {
                    res.insert(i);
                }
            }
        }
        res
    }

    pub fn check_whole(&self, pks: &Vec<VerifyingKey>,pp: &PublicParameters) -> bool {
        let reconcom = self.commitment.get_sum();
        if !self.sigma_proof.verify(pp.get_commit_base(), reconcom){
            return false;
        }
        let shares=self.check_share(pp);
        let sigs=self.check_signature(pks);
        //shares add sigs should be equal to 0..PROVER_NUM
        let union=shares.union(&sigs).cloned().collect::<HashSet<_>>();
        union.len()==constants::PROVER_NUM
    }

    pub fn check_whole_lazy(&self, pks: &Vec<VerifyingKey>, pp: &PublicParameters, proverid: usize) -> (bool,Option<ReplicaShare>) {
        let shares = self.check_share(pp);
        let sigs = self.check_signature(pks);
        // shares and sigs should cover all provers
        let union = shares.union(&sigs).cloned().collect::<HashSet<_>>();
        if union.len() < constants::PROVER_NUM {
            return (false, None);
        }

        if sigs.contains(&proverid) {
            return (true, None);
        }

        let reconcom = self.commitment.get_sum();
        if !self.sigma_proof.verify(pp.get_commit_base(), reconcom) {
            return (false, None);
        }

        (true, self.share[proverid].clone())
    }
}


pub trait UserStore {
    fn new_user(&mut self, id: u64, commitment: ReplicaCommitment, sigma_proof: ProofStruct) -> bool;

    fn get_user(&self, id: u64) -> Option<User>;

    fn get_user_commitment_proof(&self, id: u64) -> Option<(ReplicaCommitment, ProofStruct)>;

    fn sig_to_user(&mut self, id: u64, sig: MySignature, proverid: usize) -> bool;

    fn upload_share(&mut self, id: u64, share: ReplicaShare, proverid: usize) -> bool;

    fn iter_all_users(&self) -> Option<Box<dyn Iterator<Item = User>>>;

    fn check_all_users(&self, pks: &Vec<VerifyingKey>, pp: &PublicParameters) -> Vec<u64>;
}

pub struct MemoryUserStore {
    users: RwLock<HashMap<u64, User>>
}

impl MemoryUserStore {
    pub fn new() -> Self {
        MemoryUserStore {
            users: RwLock::new(HashMap::new()),
        }
    }
}

impl UserStore for MemoryUserStore {
    fn new_user(&mut self, id: u64, commitment: ReplicaCommitment, sigma_proof: ProofStruct) -> bool {
        let user = User {
            id,
            commitment,
            sigma_proof,
            signatures: core::array::from_fn(|_| None),
            share: core::array::from_fn(|_| None),
        };
        match self.users.write() {
            Ok(mut users) => {
                users.insert(id, user);
                true
            },
            Err(_) => false,
        }
    }

    fn get_user(&self, id: u64) -> Option<User> {
        self.users.read().ok()?.get(&id).cloned()
    }

    fn get_user_commitment_proof(&self, id: u64) -> Option<(ReplicaCommitment, ProofStruct)> {
        self.users.read().ok()?.get(&id).map(|user| (user.commitment.clone(), user.sigma_proof.clone()))
    }

    fn sig_to_user(&mut self, id: u64, sig: MySignature, proverid: usize) -> bool {
        if proverid >= constants::PROVER_NUM {
            return false;
        }
        match self.users.write() {
            Ok(mut users) => {
                if let Some(user) = users.get_mut(&id) {
                    user.signatures[proverid] = Some(sig);
                    true
                } else {
                    false
                }
            },
            Err(_) => false,
        }
    }

    fn upload_share(&mut self, id: u64, share: ReplicaShare, proverid: usize) -> bool {
        if proverid >= constants::PROVER_NUM {
            return false;
        }
        match self.users.write() {
            Ok(mut users) => {
                if let Some(user) = users.get_mut(&id) {
                    user.share[proverid] = Some(share);
                    true
                } else {
                    false
                }
            },
            Err(_) => false,
        }
    }

    fn iter_all_users(&self) -> Option<Box<dyn Iterator<Item = User>>> {
        match self.users.read() {
            Ok(users) => Some(Box::new(users.values().cloned().collect::<Vec<_>>().into_iter())),
            Err(_) => None,
        }
    }

    fn check_all_users(&self, pks: &Vec<VerifyingKey>, pp: &PublicParameters) -> Vec<u64> {
        let mut valid_user_ids = Vec::new();

        if let Some(users_iter) = self.iter_all_users() {
            for user in users_iter {
                if user.check_whole(pks, pp) {
                    valid_user_ids.push(user.id);
                }
            }
        }

        valid_user_ids.sort();
        valid_user_ids
    }
}