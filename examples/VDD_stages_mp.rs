
extern crate robust_verifiable_dp as dp;

use dp::public_parameters::PublicParameters;
use dp::constants;
use dp::sigma_or::ProofStruct;
use dp::sign;
use dp::replicated::{ReplicaSecret, ReplicaCommitment};
use std::time::Instant;
use dp::sigma_or::{create_proof_1, create_proof_0};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::Signature;
use std::sync::Arc;
use std::thread;
use threadpool::ThreadPool;

const NUM_CLIENTS: usize = 100;
const BAD_PROVERS: usize = 0;
const NUM_THREADS: usize = 8; // 线程池中的线程数

fn main() {
    assert!(BAD_PROVERS < constants::PROVER_NUM - constants::THRESHOLD);

    println!("Number of clients is: {}", NUM_CLIENTS);
    println!("Number of bad provers is: {}", BAD_PROVERS);
    println!("Number of provers is: {}", constants::PROVER_NUM);
    println!("Threshold is: {}", constants::THRESHOLD);

    // Create public parameters
    let pp = PublicParameters::new(b"seed");

    let mut pks = Vec::new();
    let mut sig_keys = Vec::new();
    for _ in 0..constants::PROVER_NUM {
        let (sk, pk) = sign::gen_keys();
        pks.push(pk);
        sig_keys.push(sk);
    }

    use rayon::prelude::*; // 引入 Rayon 的并行功能

let RSS = Instant::now();

// 切分数据，按线程数进行分块
let thread_count = rayon::current_num_threads();
let chunk_size = (NUM_CLIENTS + thread_count - 1) / thread_count; // 确保分块覆盖所有数据

let mut sharesvec = vec![Vec::new(); NUM_CLIENTS];
let mut comsvec = vec![ReplicaCommitment::new_zero(); NUM_CLIENTS];
let mut xvec = vec![false; NUM_CLIENTS];
let mut secretvec = vec![ReplicaSecret::new_zero(); NUM_CLIENTS];

// 使用 `par_iter_mut` 并行处理每一块
sharesvec
    .chunks_mut(chunk_size)
    .zip(comsvec.chunks_mut(chunk_size))
    .zip(xvec.chunks_mut(chunk_size))
    .zip(secretvec.chunks_mut(chunk_size))
    .enumerate()
    .for_each(|(chunk_idx, ((((shares_chunk, coms_chunk), x_chunk), secrets_chunk)))| {
        for (i, (((shares, coms), x), secret)) in shares_chunk
            .iter_mut()
            .zip(coms_chunk)
            .zip(x_chunk)
            .zip(secrets_chunk)
            .enumerate()
        {
            let global_idx = chunk_idx * chunk_size + i; // 计算全局索引
            if global_idx >= NUM_CLIENTS {
                break;
            }

            let rand_x: bool = rand::random();
            *x = rand_x;

            let x_scalar = Scalar::from(rand_x as u64);
            let replica_secret = ReplicaSecret::new(x_scalar.clone());
            let replica_commitment =
                ReplicaCommitment::new(replica_secret.commit(pp.get_commit_base().clone()));

            *secret = replica_secret;
            *coms = replica_commitment;

            let mut shares_ = Vec::new();
            for i in 0..constants::PROVER_NUM {
                shares_.push(secret.get_share(i));
            }
            *shares = shares_;
        }
    });

println!("Time elapsed in creating shares and commitments is: {:?}", RSS.elapsed());

    

    

    let or_proof= Instant::now();
    let mut proofvec = vec![ProofStruct::new(); NUM_CLIENTS];
    for i in 0..NUM_CLIENTS{
        let r_sum=secretvec[i].get_sum_r();
        let proof;
        if xvec[i]{
            proof = create_proof_1(&pp.get_commit_base(), r_sum.clone());
        }
        else{
            proof = create_proof_0(&pp.get_commit_base(), r_sum.clone());
        }
        proofvec[i]=proof;
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
    let mut sig_vec = vec![Signature::from_bytes(&[0u8; 64]); NUM_CLIENTS];

    let start_ack= Instant::now();
    for i in 0..NUM_CLIENTS{
        let coms=comsvec[i].clone();
        let sig=sign::sign_verified_deal(&skey, &coms);
        sig_vec[i]=sig;
    }

    println!("Time elapsed in ack is: {:?}", start_ack.elapsed());
    

    let start_ack_verify= Instant::now();
    for i in 0..NUM_CLIENTS{
        for _ in 0..constants::PROVER_NUM-BAD_PROVERS{//here repeat to simulate multiple provers
            let coms=comsvec[i].clone();
            let sig=sig_vec[i].clone();
            sign::verify_sig(&coms,&vkey, &sig);
        }
    }
    println!("Time elapsed in ack verify is: {:?}", start_ack_verify.elapsed());

    let start_reveal= Instant::now();
    for i in 0..NUM_CLIENTS{
        for _ in 0..BAD_PROVERS{
            let share=sharesvec[i][0].clone();
            let coms=comsvec[i].clone();
            share.check_com(pp.get_commit_base(), coms);
        }
    }
    println!("Time elapsed in reveal share verify is: {:?}", start_reveal.elapsed());

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
    println!("Time elapsed in aggregating shares is: {:?}", start_agg_shares.elapsed());

    
}