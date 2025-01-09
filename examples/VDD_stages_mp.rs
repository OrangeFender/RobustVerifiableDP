
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

const NUM_CLIENTS: usize = 10000;
const BAD_PROVERS: usize = 0;

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

    let rss = Instant::now();
    let pp_commit_base = pp.get_commit_base(); // 假设这个函数返回正确的基数

    // 使用线程数动态确定分块大小
    let num_threads = rayon::current_num_threads();
    let chunk_size = (NUM_CLIENTS + num_threads - 1) / num_threads;
    let num_chunks = (NUM_CLIENTS + chunk_size - 1) / chunk_size;

    let results: Vec<_> = (0..num_chunks)
        .into_par_iter() // 使用 Rayon 的并行迭代器
        .map(|chunk_idx| {
            let start = chunk_idx * chunk_size;
            let end = ((chunk_idx + 1) * chunk_size).min(NUM_CLIENTS);

            let mut xvec = Vec::new();
            let mut comsvec = Vec::new();
            let mut sharesvec = Vec::new();
            let mut secretvec = Vec::new();

            for _ in start..end {
                let x: bool = rand::random();
                xvec.push(x);
                let x_scalar = Scalar::from(x as u64);
                let secret = ReplicaSecret::new(x_scalar.clone());
                let coms = ReplicaCommitment::new(secret.commit(pp_commit_base.clone()));
                comsvec.push(coms);
                let mut shares = Vec::new();
                for i in 0..constants::PROVER_NUM {
                    shares.push(secret.get_share(i));
                }
                sharesvec.push(shares);
                secretvec.push(secret);
            }

            (xvec, comsvec, sharesvec, secretvec)
        })
        .collect();

    // 合并所有分块结果
    let mut xvec = Vec::new();
    let mut comsvec = Vec::new();
    let mut sharesvec = Vec::new();
    let mut secretvec = Vec::new();

    for (xv, comsv, sharesv, secretv) in results {
        xvec.extend(xv);
        comsvec.extend(comsv);
        sharesvec.extend(sharesv);
        secretvec.extend(secretv);
    }

    println!(
        "Time elapsed in creating shares and commitments is: {:?}",
        rss.elapsed()
    );
    

    

    let or_proof = Instant::now();
    let mut proofvec = vec![ProofStruct::new(); NUM_CLIENTS];

    // 使用 `par_iter_mut` 并行处理每一块
    proofvec
        .par_iter_mut()
        .zip(secretvec.par_iter())
        .zip(xvec.par_iter())
        .for_each(|((proof, secret), x)| {
            let r_sum = secret.get_sum_r();
            let created_proof = if *x {
                create_proof_1(&pp.get_commit_base(), r_sum.clone())
            } else {
                create_proof_0(&pp.get_commit_base(), r_sum.clone())
            };
            *proof = created_proof;
        });

    println!("Time elapsed in creating proofs is: {:?}", or_proof.elapsed());

    let share_verify = Instant::now();
    sharesvec
        .par_iter()
        .zip(comsvec.par_iter())
        .for_each(|(shares, coms)| {
            let share = shares[0].clone();
            share.check_com(pp.get_commit_base(), coms.clone());
        });
    println!("Time elapsed in verifying shares is: {:?}", share_verify.elapsed());

    let proof_verify = Instant::now();
    proofvec
        .par_iter()
        .zip(comsvec.par_iter())
        .for_each(|(proof, coms)| {
            let recon = coms.get_sum();
            assert!(proof.verify(pp.get_commit_base(), recon));
        });
    println!("Time elapsed in verifying proofs is: {:?}", proof_verify.elapsed());


    let (skey,vkey)= sign::gen_keys();
    let mut sig_vec = vec![Signature::from_bytes(&[0u8; 64]); NUM_CLIENTS];

    let start_ack = Instant::now();
    sig_vec
        .par_iter_mut()
        .zip(comsvec.par_iter())
        .for_each(|(sig, coms)| {
            let signed_sig = sign::sign_verified_deal(&skey, coms);
            *sig = signed_sig;
        });

    println!("Time elapsed in ack is: {:?}", start_ack.elapsed());
    

    let start_ack_verify = Instant::now();
    sig_vec
        .par_iter()
        .zip(comsvec.par_iter())
        .for_each(|(sig, coms)| {
            for _ in 0..constants::PROVER_NUM - BAD_PROVERS {
                sign::verify_sig(coms, &vkey, sig);
            }
        });
    println!("Time elapsed in ack verify is: {:?}", start_ack_verify.elapsed());

    let start_reveal = Instant::now();
    (0..NUM_CLIENTS).into_par_iter().for_each(|i| {
        (0..BAD_PROVERS).into_par_iter().for_each(|_| {
            let share = sharesvec[i][0].clone();
            let coms = comsvec[i].clone();
            share.check_com(pp.get_commit_base(), coms);
        });
    });
    println!("Time elapsed in reveal share verify is: {:?}", start_reveal.elapsed());

    let start_agg_coms = Instant::now();
    let _coms_sum: ReplicaCommitment = comsvec
        .par_iter()
        .cloned()
        .reduce(|| ReplicaCommitment::new_zero(), |a, b| a + b);

    println!("Time elapsed in aggregating commitments is: {:?}", start_agg_coms.elapsed());

    let start_agg_shares = Instant::now();
    let sum  = sharesvec
        .par_iter()
        .skip(1)
        .map(|shares| shares[0].clone())
        .reduce(|| sharesvec[0][0].clone(), |a, b| a + b);

    println!("Time elapsed in aggregating shares is: {:?}", start_agg_shares.elapsed());

    
}