
extern crate robust_verifiable_dp as dp;

use dp::{constants, replicated::ReplicaShare};
use dp::replicated::ReplicaSecret;
use std::time::Instant;
use dp::util::{random_scalars, scalar_one, scalar_zero};
use curve25519_dalek::{scalar, Scalar};



const NUM_CLIENTS: usize = 1000000;
const BAD_PROVERS: usize = 0;

fn main() {
    assert!(BAD_PROVERS < constants::PROVER_NUM - constants::THRESHOLD);

    println!("Number of clients is: {}", NUM_CLIENTS);
    println!("Number of bad provers is: {}", BAD_PROVERS);
    println!("Number of provers is: {}", constants::PROVER_NUM);
    println!("Threshold is: {}", constants::THRESHOLD);


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

    let (bit, blind): (Scalar, Scalar) = (0..constants::BITS_NUM).into_par_iter().map(|i| {
        let mut bit = scalar_zero();
        let mut blind = scalar_zero();
        for j in 0..constants::SHARE_LEN {
            if j % 2 == 1 {
                let xor = scalar_one() - bit_vector[j][i];
                bit = bit + xor;
                let xor = scalar_one() - s_blinding[j][i];
                blind += xor;
            } else {
                bit += bit_vector[j][i];
                blind += s_blinding[j][i];
            }
        }
        (bit, blind)
    }).reduce(|| (scalar_zero(), scalar_zero()), |(bit_acc, blind_acc), (bit, blind)| {
        (bit_acc + bit, blind_acc + blind)
    });


    println!("Time elapsed in aggregating bits is: {:?}", start_of_agg_bits.elapsed());


let mut shares = Vec::new();

    for _ in 0..NUM_CLIENTS{
        let x: bool = rand::random();
        let x_scalar = Scalar::from(x as u64);
        let secret=ReplicaSecret::new(x_scalar.clone());
        shares.push(secret.get_share(0));
        
    }


    let start_agg_shares = Instant::now();
    let mut sum=ReplicaShare::default();
    let sum: ReplicaShare = (0..NUM_CLIENTS).into_par_iter()
        .map(|i| shares[i].clone())
        .reduce(|| ReplicaShare::default(), |acc, share| acc + share);

    println!("Time elapsed in aggregating shares is: {:?}", start_agg_shares.elapsed());
}

    
