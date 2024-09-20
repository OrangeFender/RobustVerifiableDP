use blstrs::Scalar;
use ed25519_dalek::{Signature,PublicKey};
use crate::{communicator, sign};
use crate::sign::MySignature;
use crate::public_parameters::PublicParameters;
use crate::sigma_or::{ProofStruct, create_proof_0, create_proof_1};
use crate::replicated::{ReplicaSecret, ReplicaCommitment};
use crate::constants;
use crate::user_store::UserStore;
use crate::communicator::Communicator;

pub struct Client{
    id: u64,
    secret: ReplicaSecret,
    coms: ReplicaCommitment,
    sigma_proof: ProofStruct,
    pks: [PublicKey;constants::PROVER_NUM],
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
            id,
            secret,
            coms: ReplicaCommitment::new(coms),
            sigma_proof: proof,
            pks,
        }
    }

    pub fn get_coms(&self) -> ReplicaCommitment {
        self.coms.clone()
    }


    pub fn send_proof_coms<'a, D :UserStore>(&self, broad: &'a mut D) -> bool {
        broad.new_user(self.id, self.coms.clone(), self.sigma_proof.clone())
    }

    pub fn send_share<'a, C:Communicator>(&self, proverind:usize, communicator: &mut C) -> bool {
        let share=self.secret.get_share(proverind);
        let tuple=(self.id, share);
        communicator.send(&tuple).is_ok()
    }

    pub fn reveal_share<'a, D:UserStore>(&self, broad: &'a mut D) -> bool {
        match broad.get_user(self.id) {
            Some(user) => {
                let signed=user.check_signature(&self.pks.to_vec());
                for i in 0..constants::PROVER_NUM {
                    if !signed.contains(&i) {
                        broad.upload_share(self.id, self.secret.get_share(i), i);
                    }
                }
                return true;
            }
            None => {
                return false;
            }
        }
    }


}

