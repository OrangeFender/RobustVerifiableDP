extern crate robust_verifiable_dp as dp;


use std::time::Instant;

use curve25519_dalek::traits::Identity;
use dp::commitment::Commit;
use dp::public_parameters::PublicParameters;
use dp::constants;
use dp::sigma_or::{create_proof_0_with_com, create_proof_1_with_com};
use dp::util::{random_scalars, scalar_one, scalar_zero};
use curve25519_dalek::RistrettoPoint;



fn main(){
    println!("Number of bits is: {}", constants::BITS_NUM);

    // Create public parameters
    //生成公共参数
    let pp = PublicParameters::new( b"seed");

    let mut rng = rand::thread_rng();
    let mut s_blinding=Vec::new();
    let mut bit_vector = Vec::new();
    let mut bit_proofs=Vec::new();
    for _ in 0..constants::SHARE_LEN {
        s_blinding.push(random_scalars(constants::BITS_NUM, &mut rng));
        bit_vector.push(Vec::new());
        bit_proofs.push(Vec::new());
    }
    for i in 0..constants::BITS_NUM {
            if i<constants::BITS_NUM/2 {
                bit_vector[0].push(scalar_one());

            } else {
                bit_vector[0].push(scalar_zero());
        }
    }

    let start_of_com = Instant::now();
    let mut coms_v_k = Vec::new();
    coms_v_k.push(Vec::new());
    for j in 0..constants::BITS_NUM {
        coms_v_k[0].push(pp.get_commit_base().commit(bit_vector[0][j], s_blinding[0][j]));
    }
    println!("Time elapsed in creating commitments is: {:?}", start_of_com.elapsed());

    let start_of_or = Instant::now();
    for j in 0..constants::BITS_NUM {
        if j<constants::BITS_NUM/2 {
            bit_vector[0].push(scalar_one());
            bit_proofs[0].push(create_proof_1_with_com(&pp.get_commit_base(), s_blinding[0][j], coms_v_k[0][j]));

        } else {
            bit_vector[0].push(scalar_zero());
            bit_proofs[0].push(create_proof_0_with_com(&pp.get_commit_base(), s_blinding[0][j], coms_v_k[0][j]));
        }
    }
    
    println!("Time elapsed in creating OR proofs is: {:?}", start_of_or.elapsed());

    let start_of_verify = Instant::now();
    for j in 0..constants::BITS_NUM {
        let res=bit_proofs[0][j].verify(&pp.get_commit_base(), coms_v_k[0][j]);
        assert!(res);
    }
    println!("Time elapsed in verifying OR proofs is: {:?}", start_of_verify.elapsed()*3);//multiply by 3 because there are 3 provers
    

    let start_of_agg_com = Instant::now();
    let mut com = RistrettoPoint::identity();
    for j in 0..constants::BITS_NUM {
        if rand::random() {
            let xor= pp.get_g()+pp.get_h()-coms_v_k[0][j];
                    com+=xor;
        } else {
            com+=coms_v_k[0][j];
        }
    }
    
    println!("Time elapsed in aggregating commitments is: {:?}", start_of_agg_com.elapsed()*3);

    let start_of_agg_bits = Instant::now();
    let mut bit = scalar_zero();
    let mut blind = scalar_zero();

    for j in 0..constants::BITS_NUM {
        if rand::random() {
            let xor=scalar_one()-bit_vector[0][j];
            bit+=xor;
            let xor=scalar_one()-s_blinding[0][j];
            blind+=xor;
            } else {           
                bit+=bit_vector[0][j];
                blind+=s_blinding[0][j];
        }
    }
    println!("Time elapsed in aggregating bits is: {:?}", start_of_agg_bits.elapsed());

    

}