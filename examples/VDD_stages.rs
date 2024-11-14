extern crate robust_verifiable_dp as dp;


use dp::public_parameters::PublicParameters;
use dp::constants;
use dp::sign;
use dp::replicated::{ReplicaSecret,ReplicaCommitment};
use std::time::Instant;
use dp::sigma_or::{create_proof_1, create_proof_0};

use blstrs::Scalar;

const NUM_CLIENTS: usize = 1000;

fn format_duration(nanos: u128) -> String {
    let secs = nanos / 1_000_000_000;
    let millis = (nanos % 1_000_000_000) / 1_000_000;
    let micros = (nanos % 1_000_000) / 1_000;
    let ns = nanos % 1_000;
    format!("{}s {}ms {}µs {}ns", secs, millis, micros, ns)
}
fn main(){
    println!("Number of clients is: {}", NUM_CLIENTS);
    println!("Number of bits is: {}", constants::BITS_NUM);

    // Create public parameters
    //生成公共参数
    let pp = PublicParameters::new( b"seed");

    let mut pks=Vec::new();
    let mut sig_keys =Vec::new();
    for _ in 0..constants::PROVER_NUM {
        let (sk,pk)=sign::gen_keys();
        pks.push(pk);
        sig_keys.push(sk);
    }

    let mut sharesvec = Vec::new();
    let mut comsvec = Vec::new();
    let mut xvec = Vec::new();
    let mut secretvec = Vec::new();

    for i in 0..NUM_CLIENTS{
        let x: bool = rand::random();
        xvec.push(x);
        let x_scalar = Scalar::from(x as u64);
        let secret=ReplicaSecret::new(x_scalar.clone());
        let coms=ReplicaCommitment::new(secret.commit(pp.get_commit_base().clone()));
        comsvec.push(coms);
        let mut shares = Vec::new();
        for i in 0..constants::PROVER_NUM{
            shares.push(secret.get_share(i));
        }
        sharesvec.push(shares);
        secretvec.push(secret);
    }


    let mut proofvec = Vec::new();   
    for i in 0..NUM_CLIENTS{
        let r_sum=secretvec[i].get_sum_r();
        let proof;
        if xvec[i]{
            proof = create_proof_1(&pp.get_commit_base(), Scalar::from(xvec[i] as u64), r_sum.clone());
        }
        else{
            proof = create_proof_0(&pp.get_commit_base(), Scalar::from(xvec[i] as u64), r_sum.clone());
        }
        proofvec.push(proof);
    }

    for i in 0..NUM_CLIENTS{
        let share=sharesvec[i][0].clone();
        let coms=comsvec[i].clone();
        share.check_com(pp.get_commit_base(), coms);
        
    }

    for i in 0..NUM_CLIENTS{
        let proof=proofvec[i].clone();
        let coms=comsvec[i].clone();
        let recon=coms.get_sum();
        proof.verify(pp.get_commit_base(), recon);
    }

    
}