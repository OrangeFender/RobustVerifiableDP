use std::collections::HashMap;
use std::sync::RwLock;
use crate::replicated::ReplicaShare;

pub trait ShareStore {
    fn put(&mut self, uid: u64, share: ReplicaShare);
    fn get(&self, uid: u64) -> Option<ReplicaShare>;
    fn get_all(&self) -> Vec<(u64, ReplicaShare)>;
}

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
