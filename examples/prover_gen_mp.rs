extern crate robust_verifiable_dp as dp;


use std::time::Instant;

use curve25519_dalek::traits::Identity;
use dp::commitment::Commit;
use dp::public_parameters::PublicParameters;
use dp::constants;
use dp::sigma_or::{create_proof_0_with_com, create_proof_1_with_com, ProofStruct};
use dp::util::{random_scalars, scalar_one, scalar_zero};
use curve25519_dalek::{RistrettoPoint, Scalar};



fn main(){

    println!("Number of bits is: {}", constants::BITS_NUM);
    println!("Number of provers is: {}", constants::PROVER_NUM);
    println!("Threshold is: {}", constants::THRESHOLD);

    // Create public parameters
    //生成公共参数
    let pp = PublicParameters::new( b"seed");

    let mut rng = rand::thread_rng();
    let mut s_blinding = Vec::new();
    let mut bit_vector = vec![vec![scalar_zero(); constants::BITS_NUM]; constants::SHARE_LEN];
    let mut bit_proofs = vec![vec![ProofStruct::new(); constants::BITS_NUM]; constants::SHARE_LEN];

    for _ in 0..constants::SHARE_LEN {
        s_blinding.push(random_scalars(constants::BITS_NUM, &mut rng));
    }
    use rayon::prelude::*;

    bit_vector.par_iter_mut().enumerate().for_each(|(i, bit_vector_i)| {
        bit_vector_i.par_iter_mut().enumerate().for_each(|(j, bit_vector_ij)| {
            if j < constants::BITS_NUM / 2 {
                *bit_vector_ij = scalar_one();
            } else {
                *bit_vector_ij = scalar_zero();
            }
        });
    });

    let start_of_com = Instant::now();
    let mut coms_v_k: Vec<Vec<RistrettoPoint>> = Vec::new();
    coms_v_k.par_extend((0..constants::SHARE_LEN).into_par_iter().map(|i| {
        (0..constants::BITS_NUM).into_par_iter().map(|j| {
            pp.get_commit_base().commit(bit_vector[i][j], s_blinding[i][j])
        }).collect()
    }));
    println!("Time elapsed in creating commitments is: {:?}", start_of_com.elapsed());
    let start_of_or = Instant::now();
    bit_proofs.par_iter_mut().enumerate().for_each(|(i, bit_proofs_i)| {
        bit_proofs_i.par_iter_mut().enumerate().for_each(|(j, bit_proofs_ij)| {
            if j < constants::BITS_NUM / 2 {
                *bit_proofs_ij = create_proof_1_with_com(&pp.get_commit_base(), s_blinding[i][j], coms_v_k[i][j]);
            } else {
                *bit_proofs_ij = create_proof_0_with_com(&pp.get_commit_base(), s_blinding[i][j], coms_v_k[i][j]);
            }
        });
    });
    println!("Time elapsed in creating OR proofs is: {:?}", start_of_or.elapsed());

    let start_of_verify = Instant::now();
    (0..constants::SHARE_LEN).into_par_iter().for_each(|i| {
        (0..constants::BITS_NUM).into_par_iter().for_each(|j| {
            let res = bit_proofs[i][j].verify(&pp.get_commit_base(), coms_v_k[i][j]);
            assert!(res);
        });
    });
    println!("Time elapsed in verifying OR proofs(all provers) is: {:?}", start_of_verify.elapsed()*constants::PROVER_NUM as u32);//multiply by prover num to simulate the time for verifing all provers
    

    let start_of_agg_com = Instant::now();
    let mut com = RistrettoPoint::identity();
    for i in 0..constants::SHARE_LEN {
    for j in 0..constants::BITS_NUM {
        if rand::random() {
            let xor= pp.get_g()+pp.get_h()-coms_v_k[i][j];
                    com+=xor;
            } else {
                com+=coms_v_k[i][j];
            }
        }
    }
    println!("Time elapsed in aggregating commitments is: {:?}", start_of_agg_com.elapsed()*constants::PROVER_NUM as u32);

    let start_of_agg_bits = Instant::now();
    let mut bit = scalar_zero();
    let mut blind = scalar_zero();

    for i in 0..constants::SHARE_LEN {
            for j in 0..constants::BITS_NUM {
                if rand::random() {
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

    

}