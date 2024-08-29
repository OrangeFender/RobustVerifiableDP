use std::result;

use blstrs::{G1Projective, Scalar};
use ed25519_dalek::{Signature,PublicKey};
use crate::sign;
use crate::sign::mySignature;
use crate::commitment::Commit;
use crate::public_parameters::PublicParameters;
use crate::util;
use crate::sigma_or::{ProofStruct, create_proof_0, create_proof_1};
use crate::msg_structs::{ShareProof, Transcript, SigOrShare};
use crate::replicated::{ReplicaSecret, ReplicaCommitment};
use crate::constants;

pub struct Client{
    x:bool,
    id: u64,
    secret: ReplicaSecret,
    coms: ReplicaCommitment,
    sigma_proof: ProofStruct,

    pks: [PublicKey;constants::PROVER_NUM],
    signatures_and_id: Vec<(mySignature,usize)>
}

impl Client{
    pub fn new(id: u64, x: bool,pp:&PublicParameters,pks: [PublicKey;constants::PROVER_NUM]) -> Self {
        let x_scalar = Scalar::from(x as u64);
        let secret=ReplicaSecret::new(x_scalar.clone());
        let r_sum=secret.get_sum_r();
        let coms=secret.commit(pp.get_commit_base().clone());
        let proof;
        if x{
            proof = create_proof_1(&pp.get_commit_base(), x_scalar.clone(), r_sum.clone());
        }
        else{
            proof = create_proof_0(&pp.get_commit_base(), x_scalar.clone(), r_sum.clone());
        }

        Self {
            x,
            id,
            secret,
            coms: ReplicaCommitment::new(coms),
            sigma_proof: proof,
            pks,
            signatures_and_id:Vec::new()
        }
    }

    pub fn get_coms(&self) -> ReplicaCommitment {
        self.coms.clone()
    }


    pub fn verify_sig_and_add(&mut self, sig: Signature, proverid:usize) -> bool {
        if sign::verify_sig(&self.coms, &self.pks[proverid], sig){
            
            if self.signatures_and_id.iter().any(|(_, id)| *id == proverid) {
                self.signatures_and_id.iter_mut().for_each(|(s, id)| {
                    if *id == proverid {
                        *s = sig.into();
                        *id = proverid;
                    }
                });
            } else {
                self.signatures_and_id.push((sig.into(), proverid));
            }
            return true;
        }
        else {
            return false;
        }
    }

    pub fn gen_transcript(&self) -> Transcript{
        let mut sigs_and_shares = Vec::with_capacity(constants::PROVER_NUM);
        for i in 0..constants::PROVER_NUM {
            if let Some((sig, _)) = self.signatures_and_id.iter().find(|(_, id)| *id == i) {
                sigs_and_shares.push(SigOrShare::Signature(sig.clone()));
            } else {
                sigs_and_shares.push(SigOrShare::Share(self.secret.get_share(i)));
            }
            
        }

        Transcript::new(self.id, self.coms.clone(), sigs_and_shares, self.sigma_proof.clone())
    }


    
    pub fn create_prover_msg(&self,proverind:usize)->ShareProof{
        let coms=self.coms.clone();
        let share = self.secret.get_share(proverind);
        let proof = self.sigma_proof.clone();
        ShareProof{
            uid:self.id,
            coms,
            share,
            proof
        }
    }

}

