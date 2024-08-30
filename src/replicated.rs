use blstrs::{G1Projective, Scalar};
use ff::Field;
use group::Group;
use crate::constants::{SPLIT_LEN,SHARE_LEN,IND_ARR};
use crate::util::random_scalars;
use rand::Rng; // Import the Rng trait
use rand::thread_rng;
use crate::commitment::{Commit,CommitBase};
use serde::{Serialize, Deserialize};


pub struct ReplicaSecret {
    s: Scalar,
    splits: [Scalar; SPLIT_LEN],
    blindings: [Scalar; SPLIT_LEN],
    r_sum: Scalar,
}


#[derive(Clone, Serialize, Deserialize)]

pub struct ReplicaShare{
    ind:usize,
    share:[Scalar; SHARE_LEN],
    blindings:[Scalar; SHARE_LEN],
}



impl ReplicaSecret{
    pub fn new(s:Scalar) -> Self {
        let splits_len = SPLIT_LEN;
        let mut rng = thread_rng();
        let splits_vec = random_scalars(SPLIT_LEN - 1, &mut rng);
        let blindings_vec = random_scalars(SPLIT_LEN, &mut rng);

        let mut splits: [Scalar; SPLIT_LEN] = [Scalar::zero(); SPLIT_LEN];
        let mut blindings: [Scalar; SPLIT_LEN] = [Scalar::zero(); SPLIT_LEN];

        // 将 Vec 转换为数组
        for i in 0..(SPLIT_LEN - 1) {
            splits[i] = splits_vec[i];
        }
        for i in 0..SPLIT_LEN {
            blindings[i] = blindings_vec[i];
        }

        let mut sum = Scalar::zero();
        for i in 0..(SPLIT_LEN - 1) {
            sum += splits[i];
        }
        let last = s - sum;
        splits[SPLIT_LEN - 1] = last;


        let mut blindings_sum = Scalar::zero();
        for i in 0..splits_len {
            blindings_sum += blindings[i];
        }

        Self {
            s,
            splits,
            blindings,
            r_sum: blindings_sum,
        }
    }

    pub fn get_s(&self) -> Scalar {
        self.s.clone()
    }

    pub fn get_splits(&self) -> [Scalar; SPLIT_LEN] {
        self.splits.clone()
    }

    pub fn get_share(&self, ind:usize) -> ReplicaShare {
        let mut share: [Scalar; SHARE_LEN] = [Scalar::zero(); SHARE_LEN];
        let mut blindings: [Scalar; SHARE_LEN] = [Scalar::zero(); SHARE_LEN];

        for j in 0..SHARE_LEN {
            let i=IND_ARR[ind][j];//注意这里的索引顺序
            share[j]=self.splits[i];
            blindings[j]=self.blindings[i];
        }

        ReplicaShare {
            ind,
            share,
            blindings,
        }
    }
    
    pub fn commit(&self,base:CommitBase ) -> Vec<G1Projective> {
        let mut coms = Vec::new();
        for i in 0..SPLIT_LEN {
            coms.push(base.commit(self.splits[i], self.blindings[i]));
        }
        coms
    }

    pub fn get_sum_r(&self) -> Scalar {
        self.r_sum.clone()
    }
}

impl ReplicaShare{
    pub fn new_zero(ind:usize) -> Self {
        let share = [Scalar::zero(); SHARE_LEN];
        let blindings = [Scalar::zero(); SHARE_LEN];
        Self {
            ind,
            share,
            blindings,
        }
        
    }
    
    pub fn get_ind(&self) -> usize {
        self.ind
    }

    pub fn get_share(&self) -> [Scalar; SHARE_LEN]{
        self.share.clone()
    }

    pub fn check_com(&self,base:&CommitBase,com:ReplicaCommitment) -> bool {
        for i in 0..SHARE_LEN {
            let ind=IND_ARR[self.ind][i];
            if !base.vrfy(self.share[i], self.blindings[i], com.ind_value(ind)) {
                return false;
            }
        }
        true
    }

    pub fn check_com_with_noise(&self, base: &CommitBase, com:ReplicaCommitment, noise_commitment: G1Projective) -> bool {
        for i in 0..SHARE_LEN {
            let ind = IND_ARR[self.ind][i];
            if !base.vrfy(self.share[i], self.blindings[i], com.ind_value(ind) + noise_commitment) {
                return false;
            }
        }
        true
    }

    pub fn add_noise(&self, noise: Scalar, noise_proof: Scalar)-> ReplicaShare{
        let share_with_noise: [Scalar; SHARE_LEN] = self.share.iter().map(|&s| s + noise).collect::<Vec<Scalar>>().try_into().unwrap();
        let blindings_with_noise: [Scalar; SHARE_LEN] = self.blindings.iter().map(|&b| b + noise_proof).collect::<Vec<Scalar>>().try_into().unwrap();

        ReplicaShare {
            ind: self.ind,
            share: share_with_noise,
            blindings: blindings_with_noise,
        }
    }
}

use std::ops::Add;



impl Add for ReplicaShare {
    type Output = Self;

    fn add(self, other: Self) -> Self {

        // 对应元素相加
        let share: [Scalar; SHARE_LEN] = self.share.iter().zip(other.share.iter()).map(|(a, b)| *a + *b).collect::<Vec<Scalar>>().try_into().unwrap();
        let blindings = self.blindings.iter().zip(other.blindings.iter()).map(|(a, b)| *a + *b).collect::<Vec<Scalar>>().try_into().unwrap();

        Self {
            ind: self.ind,
            share,
            blindings,
        }
    }
}



#[derive(Clone, Serialize, Deserialize)]

pub struct ReplicaCommitment{
    com:Vec<G1Projective>,
}

impl ReplicaCommitment{
    pub fn new(com:Vec<G1Projective>) -> Self {
        if com.len() != SPLIT_LEN {
            panic!("Invalid length of commitment");
        }
        Self {
            com,
        }
    }

    pub fn ind_value(&self,ind:usize) -> G1Projective {
        self.com[ind]
    }

    pub fn get_sum(&self) -> G1Projective {
        let mut sum = G1Projective::identity();
        for i in 0..SPLIT_LEN {
            sum += self.com[i];
        }
        sum
    }

    pub fn new_zero() -> Self {
        let com = vec![G1Projective::identity(); SPLIT_LEN];
        Self {
            com,
        }
    }

    
}

impl Add for ReplicaCommitment {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        let com = self.com.iter().zip(other.com.iter()).map(|(a, b)| *a + *b).collect::<Vec<G1Projective>>();

        Self {
            com,
        }
    }
}

pub fn recon_shares(shares:Vec<ReplicaShare>)->Option<Scalar>{
    let mut splits: [Vec<_>; SPLIT_LEN] = Default::default();
    for share in shares {
        for i in 0..SHARE_LEN {
            let ind = IND_ARR[share.ind][i];
            splits[ind].push(share.share[i]);
        }
    }

    let mut sum = Scalar::zero();
    for i in 0..SPLIT_LEN {
        let len = splits[i].len();
        if len == 0 {
            return None;
        }
        let random_pick = thread_rng().gen_range(0, len);
        sum += splits[i][random_pick];
    }
    Some(sum)

}


#[cfg(test)]
mod tests{
    use blstrs::Scalar;
    use ff::Field;

    use crate::constants;

    use super::{recon_shares, ReplicaSecret};

    #[test]
    fn test_recon(){
        let secret = ReplicaSecret::new(Scalar::from(1 as u64));
        let splits=secret.get_splits();
        let mut sum=Scalar::zero();
        for i in 0..constants::SPLIT_LEN{
            sum+=splits[i];
        }
        println!("sum:{}",sum.to_string());
        let mut shares =Vec::new();
        for i in 1..constants::PROVER_NUM{
            shares.push(secret.get_share(i))
        }

        let res=recon_shares(shares);
        println!("{}",res.unwrap().to_string());
        assert_eq!(res.unwrap(),Scalar::from(1 as u64))
    }
}