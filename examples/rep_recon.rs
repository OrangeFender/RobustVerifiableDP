extern crate robust_verifiable_dp as dp;

use dp::constants;
use dp::replicated::{ReplicaSecret,recon_shares};
use std::time::Instant;
use dp::util::{random_scalar, scalar_zero};

fn main(){
    let mut rng = rand::thread_rng();
    let secret = ReplicaSecret::new(random_scalar(&mut rng));
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

        let start=Instant::now();
        let res=recon_shares(shares);
        println!("Time elapsed in reconstructing shares is: {:?}", start.elapsed());
        println!("res:{:?}", res);
}