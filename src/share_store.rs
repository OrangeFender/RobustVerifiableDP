use std::collections::HashMap;
use std::sync::RwLock;
use crate::replicated::{ReplicaShare, ReplicaCommitment};

pub trait ShareStore {
    fn put(&mut self, uid: u64, share: ReplicaShare);
    fn get(&self, uid: u64) -> Option<ReplicaShare>;
    fn get_all(&self) -> Vec<(u64, ReplicaShare)>;
}
//TODO: 添加生命周期参数
pub struct MemoryShareStore {
    shares: RwLock<HashMap<u64, ReplicaShare>>,
}

impl Default for MemoryShareStore {
    fn default() -> Self {
        MemoryShareStore::new()
    }
}

impl MemoryShareStore {
    pub fn new() -> Self {
        MemoryShareStore {
            shares: RwLock::new(HashMap::new()),
        }
    }
}

impl ShareStore for MemoryShareStore {
    fn put(&mut self, uid: u64, share: ReplicaShare) {
        let mut shares = self.shares.write().unwrap();
        shares.insert(uid, share);
    }

    fn get(&self, uid: u64) -> Option<ReplicaShare> {
        let shares = self.shares.read().unwrap();
        shares.get(&uid).cloned()
    }

    fn get_all(&self) -> Vec<(u64, ReplicaShare)> {
        let shares = self.shares.read().unwrap();
        shares.iter().map(|(k, v)| (*k, v.clone())).collect()
    }
}

pub trait CommitmentStore {
    fn get_all_uids(&self) -> Vec<u64>;
    fn put(&mut self, uid: u64, com: ReplicaCommitment);
    fn sum(&self) -> ReplicaCommitment;
}

pub struct MemoryCommitmentStore {
    coms: RwLock<HashMap<u64, ReplicaCommitment>>,
}

impl MemoryCommitmentStore {
    pub fn new() -> Self {
        MemoryCommitmentStore {
            coms: RwLock::new(HashMap::new()),
        }
    }
}

impl CommitmentStore for MemoryCommitmentStore {
    fn get_all_uids(&self) -> Vec<u64> {
        let coms = self.coms.read().unwrap();
        coms.keys().cloned().collect()
    }

    fn put(&mut self, uid: u64, com: ReplicaCommitment) {
        let mut coms = self.coms.write().unwrap();
        coms.insert(uid, com);
    }

    fn sum(&self) -> ReplicaCommitment {
        let coms = self.coms.read().unwrap();
        let mut sum = ReplicaCommitment::new_zero();
        for com in coms.values() {
            sum = sum + com.clone();
        }
        sum
    }
}