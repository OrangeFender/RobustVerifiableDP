extern crate robust_verifiable_dp as dp;


use dp::public_parameters::PublicParameters;
use dp::constants;
use dp::sign;
use dp::replicated::{ReplicaSecret,ReplicaCommitment};
use std::time::Instant;
use dp::sigma_or::{create_proof_1, create_proof_0};

use curve25519_dalek::scalar::Scalar;

const NUM_CLIENTS: usize = 1;
const BAD_PROVERS: usize = 0;


fn main(){

    println!("Number of clients is: {}", NUM_CLIENTS);
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

    let rss= Instant::now();
    for _ in 0..NUM_CLIENTS{
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
    println!("Time elapsed in creating shares and commitments is: {:?}", rss.elapsed());

    

    let or_proof= Instant::now();
    let mut proofvec = Vec::new();   
    for i in 0..NUM_CLIENTS{
        let r_sum=secretvec[i].get_sum_r();
        let proof;
        if xvec[i]{
            proof = create_proof_1(&pp.get_commit_base(), r_sum.clone());
        }
        else{
            proof = create_proof_0(&pp.get_commit_base(), r_sum.clone());
        }
        proofvec.push(proof);
    }
    println!("Time elapsed in creating proofs is: {:?}", or_proof.elapsed());

    let share_verify= Instant::now();
    for i in 0..NUM_CLIENTS{
        let share=sharesvec[i][0].clone();
        let coms=comsvec[i].clone();
        share.check_com(pp.get_commit_base(), coms);
    }
    println!("Time elapsed in verifying shares is: {:?}", share_verify.elapsed());

    let proof_verify= Instant::now();
    for i in 0..NUM_CLIENTS{
        let proof=proofvec[i].clone();
        let recon=comsvec[i].get_sum();
        assert!(proof.verify(pp.get_commit_base(), recon));
    }
    println!("Time elapsed in verifying proofs is: {:?}", proof_verify.elapsed());


    let (skey,vkey)= sign::gen_keys();
    let mut sig_vec= Vec::new();

    let start_ack= Instant::now();
    for i in 0..NUM_CLIENTS{
        let coms=comsvec[i].clone();
        let sig=sign::sign_verified_deal(&skey, &coms);
        sig_vec.push(sig);
    }

    println!("Time elapsed in ack is: {:?}", start_ack.elapsed());
    

    let start_ack_verify= Instant::now();
    for i in 0..NUM_CLIENTS{
        for _ in 0..constants::PROVER_NUM-BAD_PROVERS{//here repeat to simulate multiple provers
            let coms=comsvec[i].clone();
            let sig=sig_vec[i].clone();
            sign::verify_sig(&coms,&vkey, &sig);
        }
        for _ in 0..BAD_PROVERS{
            let share=sharesvec[i][0].clone();
            let coms=comsvec[i].clone();
            share.check_com(pp.get_commit_base(), coms);
        }
    }
    println!("Time elapsed in ack verify and reveal share verify is: {:?}", start_ack_verify.elapsed());

    let start_agg_coms = Instant::now();
    let mut coms_sum=ReplicaCommitment::new_zero();
    for i in 0..NUM_CLIENTS{
        let coms=comsvec[i].clone();
        coms_sum=coms_sum+coms;
    }
    println!("Time elapsed in aggregating commitments is: {:?}", start_agg_coms.elapsed());

    let start_agg_shares = Instant::now();
    let mut sum=sharesvec[0][0].clone();
    for i in 1..NUM_CLIENTS
    {
        sum=sum+sharesvec[i][0].clone();
    }
    println!("Time elapsed in aggregating shares is: {:?}", start_agg_shares.elapsed()/NUM_CLIENTS.try_into().unwrap());

    
}