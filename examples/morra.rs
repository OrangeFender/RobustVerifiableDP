extern crate robust_verifiable_dp as dp;

use rand::rngs::OsRng;
use std::time::{Instant};
use curve25519_dalek::traits::Identity;
use dp::commitment::Commit;
use dp::public_parameters::PublicParameters;
use dp::constants;
use dp::sigma_or::{create_proof_0_with_com, create_proof_1_with_com, ProofStruct};
use dp::util::{random_scalar, random_scalars, scalar_one, scalar_zero};
use curve25519_dalek::{RistrettoPoint, Scalar};

fn main(){

    let pp = PublicParameters::new( b"seed");

    let mut csprng = OsRng;
    let num_shares = 2;

    let n_b = 128;

    let mut b_sum = 0;    
    let now = Instant::now();    
    for _ in 0..n_b{
        
        let x0 = random_scalar(&mut csprng);
        let r0 = random_scalar(&mut csprng);
        let c = pp.get_commit_base().commit(x0, r0);

        let x1 = random_scalar(&mut csprng);
        let r1 = random_scalar(&mut csprng);
        // For an assert
        let _ = pp.get_commit_base().commit(x1, r1);

        // Threshold
        if (x0 + x1).to_bytes()[0] %2  == 0{
            b_sum += 1;
        }
        else{
            b_sum += 0;
        }
    }
    let end = now.elapsed().as_millis();
    println!("Time Taken generate {} coins; {} ms", n_b, end);
    println!("{:?}", b_sum);
}