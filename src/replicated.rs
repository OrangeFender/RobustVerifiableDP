use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::traits::Identity;
use crate::constants::{SPLIT_LEN,SHARE_LEN,IND_ARR};
use crate::util::{random_scalars, scalar_zero};
use rand::Rng; // Import the Rng trait
use rand::thread_rng;
use crate::commitment::{Commit,CommitBase};

#[derive(Clone)]

pub struct ReplicaSecret {
    s: Scalar,
    splits: [Scalar; SPLIT_LEN],
    blindings: [Scalar; SPLIT_LEN],
    r_sum: Scalar,
}


#[derive(Clone)]

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

        let mut splits: [Scalar; SPLIT_LEN] = [s; SPLIT_LEN];
        let mut blindings: [Scalar; SPLIT_LEN] = [scalar_zero(); SPLIT_LEN];

        // 将 Vec 转换为数组
        for i in 0..(SPLIT_LEN - 1) {
            splits[i] = splits_vec[i];
        }
        for i in 0..SPLIT_LEN {
            blindings[i] = blindings_vec[i];
        }

        let mut sum = scalar_zero();
        for i in 0..(SPLIT_LEN - 1) {
            sum += splits[i];
        }
        let last = s - sum;
        splits[SPLIT_LEN - 1] = last;


        let mut blindings_sum = scalar_zero();
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

    pub fn new_zero()->Self{
        let splits: [Scalar; SPLIT_LEN] = [scalar_zero(); SPLIT_LEN];
        let blindings: [Scalar; SPLIT_LEN] = [scalar_zero(); SPLIT_LEN];
        let r_sum = scalar_zero();

        Self {
            s: scalar_zero(),
            splits,
            blindings,
            r_sum,
        }
    }

    pub fn get_s(&self) -> Scalar {
        self.s.clone()
    }

    pub fn get_splits(&self) -> [Scalar; SPLIT_LEN] {
        self.splits.clone()
    }

    pub fn get_share(&self, ind:usize) -> ReplicaShare {
        let mut share: [Scalar; SHARE_LEN] = [scalar_zero(); SHARE_LEN];
        let mut blindings: [Scalar; SHARE_LEN] = [scalar_zero(); SHARE_LEN];

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
    
    pub fn commit(&self,base:CommitBase ) -> Vec<RistrettoPoint> {
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
        let share = [scalar_zero(); SHARE_LEN];
        let blindings = [scalar_zero(); SHARE_LEN];
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

    pub fn check_com_with_noise(&self, base: &CommitBase, com:ReplicaCommitment, noise_commitment: Vec<RistrettoPoint>) -> bool {
        for i in 0..SHARE_LEN {
            let ind = IND_ARR[self.ind][i];
            if !base.vrfy(self.share[i], self.blindings[i], com.ind_value(ind) + noise_commitment[i]) {
                return false;
            }
        }
        true
    }

    pub fn add_noise(&self, noise: Vec<Scalar>, noise_proof: Vec<Scalar>)-> ReplicaShare{
        let share_with_noise: [Scalar; SHARE_LEN] = self.share.iter().zip(noise.iter()).map(|(&s, &n)| s + n).collect::<Vec<Scalar>>().try_into().unwrap();
        let blindings_with_noise: [Scalar; SHARE_LEN] = self.blindings.iter().zip(noise_proof.iter()).map(|(&b, &n)| b + n).collect::<Vec<Scalar>>().try_into().unwrap();
        ReplicaShare {
            ind: self.ind,
            share: share_with_noise,
            blindings: blindings_with_noise,
        }
    }
}

impl Default for ReplicaShare {
    fn default() -> Self {
        let share = [scalar_zero(); SHARE_LEN];
        let blindings = [scalar_zero(); SHARE_LEN];
        Self {
            ind: 0,
            share,
            blindings,
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



#[derive(Clone)]
pub struct ReplicaCommitment{
    com: [RistrettoPoint; SPLIT_LEN],
}

impl ReplicaCommitment{
    pub fn new(com:Vec<RistrettoPoint>) -> Self {
        if com.len() != SPLIT_LEN {
            panic!("Invalid length of commitment");
        }
        Self {
            com: com.try_into().expect("Invalid length of commitment"),
        }
    }

    pub fn ind_value(&self,ind:usize) -> RistrettoPoint {
        self.com[ind]
    }

    pub fn get_sum(&self) -> RistrettoPoint {
        let mut sum = self.com[0];
        for i in 1..SPLIT_LEN {
            sum += self.com[i];
        }
        sum
    }

    pub fn new_zero() -> Self {
        let com = vec![RistrettoPoint::identity(); SPLIT_LEN];
        Self {
            com: com.try_into().expect("Invalid length of commitment"),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for i in 0..SPLIT_LEN {
            bytes.extend_from_slice(&self.com[i].compress().to_bytes());
        }
        bytes
    }
    

    
}

impl Add for ReplicaCommitment {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        let com = self.com.iter().zip(other.com.iter()).map(|(a, b)| *a + *b).collect::<Vec<RistrettoPoint>>().try_into().expect("Invalid length of commitment");

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

    let mut sum = scalar_zero();
    for i in 0..SPLIT_LEN {
        let len = splits[i].len();
        if len == 0 {
            return None;
        }
        let random_pick = thread_rng().gen_range(0..len);
        sum += splits[i][random_pick];
    }
    Some(sum)

}


#[cfg(test)]
mod tests{

    use curve25519_dalek::scalar::Scalar;
    use crate::constants;
    use crate::util::scalar_zero;

    use super::{recon_shares, ReplicaSecret};

    #[test]
    fn test_recon(){
        let secret = ReplicaSecret::new(Scalar::from(1 as u64));
        let splits=secret.get_splits();
        let mut sum=scalar_zero();
        for i in 0..constants::SPLIT_LEN{
            sum+=splits[i];
        }
        println!("sum:{:?}", sum);
        let mut shares =Vec::new();
        for i in 1..constants::PROVER_NUM{
            shares.push(secret.get_share(i))
        }

        let res=recon_shares(shares);
        println!("res:{:?}", res);
        assert_eq!(res.unwrap(),Scalar::from(1 as u64))
    }

    
}