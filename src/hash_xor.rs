use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use aptos_crypto::hash;
use blstrs::{G1Projective, Scalar};
use rand::Rng;
use rand_core::le;
use group::Curve;
use sha3::digest::typenum::bit;
const DST_ROBUST_DP_PUBLIC_PARAMS_GENERATION : &[u8; 41] = b"DSTofRobustDP'sPublicParametersGeneration";


fn calculate_hash<T: Hash>(t: &T) -> u64 {
    let mut s = DefaultHasher::new();
    t.hash(&mut s);
    s.finish()
}



fn hash_coms(coms: &Vec<Vec<G1Projective>>,nb:usize) -> u64 {//hash the vector of G1Projective
    assert!(nb <= 64);//nb should be less than 64
    let mut concatenated:Vec<u8> = Vec::new();
    for i in 0..coms.len() {
        let msg = bcs::to_bytes(&coms[i]).unwrap();
        concatenated.extend(msg);
    }
    calculate_hash(&concatenated)& ((1 << nb) - 1)//return the last nb bits
}



fn convert_to_bit_array(hash: u64, nb: usize) -> Vec<bool> {//convert hash to binary and then to scalar bit array(nb bits)
    let mut result: Vec<bool> = Vec::new();
    for i in 0..nb {
        let bit = (hash >> i) & 1;
        result.push(bit!=0);
    }
    result
}

pub fn hash_to_bit_array(coms: &Vec<Vec<G1Projective>>,nb:usize) -> Vec<bool> {
    let hash = hash_coms(coms,nb);
    convert_to_bit_array(hash, nb)
}

pub fn xor_commitments(coms: &Vec<G1Projective>,bit_arry: &Vec<bool>, g:G1Projective, h:G1Projective) -> Vec<G1Projective> {
    let mut result = Vec::new();
    for i in 0..coms.len() {
        if bit_arry[i] {
            result.push(g+h- coms[i]);
        }else{
            result.push(coms[i]);
        }
    }
    result
}


