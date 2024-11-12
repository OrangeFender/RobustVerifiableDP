use blstrs::G1Projective;
use group::Group;
use ed25519_dalek::VerifyingKey;
use crate::{constants, util};
use crate::public_parameters::PublicParameters;
use crate::replicated::{ReplicaShare, ReplicaCommitment};
use crate::user_store::UserStore;
use blstrs::Scalar;

pub struct Verifier {
    coms_v_ks: Vec<Vec<Vec<G1Projective>>>,
    pks: Vec<VerifyingKey>,
}


impl Verifier {
    pub fn new(coms_v_ks: Vec<Vec<Vec<G1Projective>>>, pks: Vec<VerifyingKey>) -> Self {
        Self {
            coms_v_ks,
            pks,
        }
    }

    pub fn check_all_users_and_sum_coms<B:UserStore>(&self, broad: &B, pp: &PublicParameters) -> ReplicaCommitment {
        let mut valid_user_ids = Vec::new();
        let mut sum_com = ReplicaCommitment::new_zero();
        let mut all_users = broad.iter_all_users().unwrap();
        while let Some(user) = all_users.next() {
            if user.check_whole(&self.pks, pp) {
                valid_user_ids.push(user.id);
                sum_com = sum_com + user.commitment.clone();
            }
        }
        sum_com
    }



    /// this function verifies the share of prover
    pub fn handle_prover_share(&self,ind:usize,share:ReplicaShare, aggregated_com:ReplicaCommitment, public_rand_bits:&Vec<Vec<bool>>, pp:&PublicParameters)->bool{
        let prover_id=share.get_ind();
        
        if ind!=prover_id{
            return false;
        }

        let mut coms_x_or = self.coms_v_ks[ind].clone();
        let g = pp.get_g();
        let h = pp.get_h();
        for i in 0..constants::SHARE_LEN {
            for j in 0..constants::BITS_NUM {
                if public_rand_bits[i][j] {
                    coms_x_or[i][j] = g + h - coms_x_or[i][j];
                }
            }
        }

        let mut noise_commitments = Vec::new();
        for i in 0..constants::SHARE_LEN {
            let mut noise_commitment = G1Projective::identity();
            for j in 0..constants::BITS_NUM {
                noise_commitment += coms_x_or[i][j];
            }
            noise_commitments.push(noise_commitment);
        }

        share.check_com_with_noise(pp.get_commit_base(),aggregated_com, noise_commitments)
    }


}