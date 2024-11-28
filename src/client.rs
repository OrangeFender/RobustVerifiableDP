use curve25519_dalek::Scalar;
use ed25519_dalek::VerifyingKey;
use crate::public_parameters::PublicParameters;
use crate::sigma_or::{ProofStruct, create_proof_0, create_proof_1};
use crate::replicated::{ReplicaSecret, ReplicaCommitment, ReplicaShare};
use crate::constants;
use crate::user_store::UserStore;

pub struct Client{
    id: u64,
    secret: ReplicaSecret,
    coms: ReplicaCommitment,
    sigma_proof: ProofStruct,
    pks: [VerifyingKey;constants::PROVER_NUM],
}

impl Client{
    pub fn new(id: u64, x: bool,pp:&PublicParameters,pks: [VerifyingKey;constants::PROVER_NUM]) -> Self {
        let x_scalar = Scalar::from(x as u64);
        let secret=ReplicaSecret::new(x_scalar.clone());
        let r_sum=secret.get_sum_r();
        let coms=secret.commit(pp.get_commit_base().clone());
        
        let proof;
        if x{
            proof = create_proof_1(&pp.get_commit_base(), r_sum.clone());
        }
        else{
            proof = create_proof_0(&pp.get_commit_base(), r_sum.clone());
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

    pub fn send_share(&self, proverind:usize) -> (u64, ReplicaShare) {
        let share=self.secret.get_share(proverind);
        (self.id, share)
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

