
extern crate robust_verifiable_dp as dp;

use dp::public_parameters::PublicParameters;
use dp::constants;
use dp::sign;
use dp::replicated::{ReplicaSecret, ReplicaCommitment};
use std::time::Instant;
use dp::util::{random_scalars, scalar_one, scalar_zero};
use curve25519_dalek::{RistrettoPoint, Scalar};
use dp::commitment::Commit;
use curve25519_dalek::traits::Identity;


const NUM_CLIENTS: usize = 100;
const BAD_PROVERS: usize = 0;

fn main() {
    assert!(BAD_PROVERS < constants::PROVER_NUM - constants::THRESHOLD);

    println!("Number of clients is: {}", NUM_CLIENTS);
    println!("Number of bad provers is: {}", BAD_PROVERS);
    println!("Number of provers is: {}", constants::PROVER_NUM);
    println!("Threshold is: {}", constants::THRESHOLD);

    let mut pks = Vec::new();
    let mut sig_keys = Vec::new();
    for _ in 0..constants::PROVER_NUM {
        let (sk, pk) = sign::gen_keys();
        pks.push(pk);
        sig_keys.push(sk);
    }

// Create public parameters
    //生成公共参数
    let pp = PublicParameters::new( b"seed");

    let mut rng = rand::thread_rng();
    let mut s_blinding = Vec::new();
    let mut bit_vector = vec![vec![scalar_zero(); constants::BITS_NUM]; constants::SHARE_LEN];
    for _ in 0..constants::SHARE_LEN {
        s_blinding.push(random_scalars(constants::BITS_NUM, &mut rng));
    }
    use rayon::prelude::*;

    bit_vector.par_iter_mut().enumerate().for_each(|(_i, bit_vector_i)| {
        bit_vector_i.par_iter_mut().enumerate().for_each(|(j, bit_vector_ij)| {
            if j < constants::BITS_NUM / 2 {
                *bit_vector_ij = scalar_one();
            } else {
                *bit_vector_ij = scalar_zero();
            }
        });
    });


    let start_of_agg_bits = Instant::now();
    let mut bit = scalar_zero();
    let mut blind = scalar_zero();

    for i in 0..constants::SHARE_LEN {
            for j in 0..constants::BITS_NUM {
                if j %2==1 {
                    let xor=scalar_one()-bit_vector[i][j];
                    bit+=xor;
                    let xor=scalar_one()-s_blinding[i][j];
                    blind+=xor;
                } else {
                    bit+=bit_vector[i][j];
                    blind+=s_blinding[i][j];

            }
        }
        
    }
    println!("Time elapsed in aggregating bits is: {:?}", start_of_agg_bits.elapsed());





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
    .for_each(|(chunk_idx, (((shares_chunk, coms_chunk), x_chunk), secrets_chunk))| {
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


    let start_agg_shares = Instant::now();
    let mut sum=sharesvec[0][0].clone();
    for i in 1..NUM_CLIENTS
    {
        sum=sum+sharesvec[i][0].clone();
    }
    println!("Time elapsed in aggregating shares is: {:?}", start_agg_shares.elapsed());

    
}