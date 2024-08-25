use crate::commitment::CommitBase;
use crate::replicated::{ReplicaShare, ReplicaCommitment};
use crate::sigma_or::ProofStruct;
use crate::constants;
use group::Group;
use blstrs::G1Projective;
use serde::{Serialize, Deserialize};
use ed25519_dalek::{Signature, Keypair, PublicKey, Signer, Verifier};
use crate::sign::{mySignature,verify_sig};

#[derive(Clone, Serialize, Deserialize)]
pub struct ShareProof{
    pub coms: ReplicaCommitment,
    pub share: ReplicaShare,
    pub proof:ProofStruct,
}

impl ShareProof {
    pub fn verify(&self,commit_base:&CommitBase) -> bool {
        if self.share.check_com(commit_base,self.coms.clone()) == false {
            return false;
        }
        let mut sum= self.coms.get_sum();
        self.proof.verify(&commit_base, sum)
    }
}

#[derive(Clone, Serialize, Deserialize)]

pub struct Transcript {
    pub id: u64,
    pub coms: ReplicaCommitment,
    pub sigs_and_shares: Vec<SigOrShare>,
    pub sigma_or_proof: ProofStruct,
}

#[derive(Clone, Serialize, Deserialize)]
pub enum SigOrShare {
    Signature(mySignature),
    Share(ReplicaShare),
}

impl Transcript {
    pub fn new(id:u64, coms:ReplicaCommitment, sigs_and_shares:Vec<SigOrShare>, sigma_or_proof: ProofStruct) -> Self {
        Self {
            id: id,
            coms,
            sigs_and_shares: sigs_and_shares,
            sigma_or_proof: sigma_or_proof,
        }
    }

    pub fn verify(&self, base: &CommitBase, pks: &Vec<PublicKey>) -> bool {
        let mut sum = self.coms.get_sum();
        if self.sigma_or_proof.verify(base, sum) == false {
            return false;
        }
        
        for i in 0..constants::PROVER_NUM {
            match &self.sigs_and_shares[i] {
                SigOrShare::Signature(sig) => {
                    if verify_sig(&self.coms, &pks[i], sig.clone().into()) == false {
                        return false;
                    }
                }
                SigOrShare::Share(share) => {
                    if !share.check_com(base, self.coms.clone()) {
                        return false;
                    }
                }
            }
        }



        true
    }
}

