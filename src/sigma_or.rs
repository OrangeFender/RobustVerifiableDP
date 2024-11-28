// 功能：
// 1. Client传入秘密份额(f_i(0), r_{i,0})后，create_or_proof；这里需要实现一个判断是0还是1
// 2. Prover和Verifier执行验证verify_or_proof
use rand::thread_rng;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::RistrettoPoint;
use rand_core::OsRng;
use sha3::{Digest, Sha3_256};
// use num_bigint::BigUint;
// use num_integer::Integer;


use crate::commitment::{CommitBase, Commit};
use crate::util::*;
use serde::{Serialize, Deserialize};

#[derive(Clone)]
pub struct  ProofStruct{
    //pub com: G1Projective,
    pub e0 : Scalar, 
    pub e1 : Scalar, 
    pub e : Scalar, 
    pub v0: Scalar, 
    pub v1: Scalar, 
    pub d0: RistrettoPoint,
    pub d1: RistrettoPoint,
}

// //这个可以改成util里的hashtoScalar
// pub fn from_bytes_to_modscalar(bytes: &[u8;32]) -> Scalar {
//     let bignum = BigUint::from_bytes_le(bytes);
//     let remainder = bignum.mod_floor(&SCALAR_FIELD_ORDER);

//     biguint_to_scalar(&remainder) // 返回值
// }

// create_or_proof
// self替换为commitbase中的g和h, 全都换到G1Projective上
// ct_rand 表示Client的私有randomness
// 应该传x_scalar，因为可能会有不属于{0,1}的值，
pub fn create_proof_0(commit_base: &CommitBase, ct_rand: Scalar)->ProofStruct{

     // create FIAT shamir proof for when the secret is 0
        // let mut hasher = Sha3_256::new();
        let com = commit_base.commit(scalar_zero(), ct_rand);
        let mut rng = OsRng;
        let v1 = random_scalar(&mut rng); // v1
        let mut rng = OsRng;

        let e1 = random_scalar(&mut rng); // e1
        let mut rng = OsRng;

        let b = random_scalar(&mut rng); // b

        // d1 : Cheat
        let ce1 = -(&com * &e1); // 1/c^{e1}
        let ge1 = &commit_base.g * &e1; // g^{e1}
        let hv1 = &commit_base.h * &v1;      
        let d1 = hv1 + ce1 + ge1; //h^{v1} x 1/c^{e1} x g^{e1}

        // d0 : Honest
        let d0 = &b * &commit_base.h; // h^{b}  

        let mut hasher = Sha3_256::new();
        let mut input_to_rom: Vec<u8> = Vec::new();
        input_to_rom.extend(com.compress().as_bytes());        
        input_to_rom.extend(d0.compress().as_bytes());
        input_to_rom.extend(d1.compress().as_bytes());
        hasher.update(input_to_rom); // this will take d0, d1, commitment as a byte array
        let result: [u8;32] =  hasher.finalize().into();        
        let e = Scalar::from_bytes_mod_order(result); // In the interactive version this would come in round 2
        
        let e0 = e - e1;         
        let v0 = b + e0*ct_rand;

        return ProofStruct{e0, e1, e, v0, v1, d0, d1};


}


pub fn create_proof_1(commit_base: &CommitBase, ct_rand: Scalar)->ProofStruct{

      // create FIAT shamir proof for when the secret is 0
        // let mut hasher = Sha3_256::new();
        let com = commit_base.commit(scalar_one(), ct_rand);

      let mut rng = OsRng;
        let v0 = random_scalar(&mut rng); // v0
      let mut rng = OsRng;

        let e0 = random_scalar(&mut rng); // e0
      let mut rng = OsRng;

        let b = random_scalar(&mut rng); // b

        // d0 : Cheat
        let ce0 = -(&com * &e0); // 1/c^{e0}
        let hv0 = &commit_base.h * &v0; // h^{0}     
        let d0 = hv0 + ce0; //h^{v0} x 1/c^{e0} 

        // d1 : Honest
        let d1 = &b * &commit_base.h; // h^{b}  

        let mut hasher = Sha3_256::new();
        let mut input_to_rom: Vec<u8> = Vec::new();
        input_to_rom.extend(com.compress().as_bytes());        
        input_to_rom.extend(d0.compress().as_bytes());
        input_to_rom.extend(d1.compress().as_bytes());
        hasher.update(input_to_rom); // this will take d0, d1, commitment as a byte array
        let result: [u8;32] =  hasher.finalize().into();        
        let e = Scalar::from_bytes_mod_order(result); // In the interactive version this would come in round 2
        
        let e1 = e - e0;         
        let v1 = b + e1*ct_rand;

        return ProofStruct{e0, e1, e, v0, v1, d0, d1};


}

pub fn create_proof_0_with_com(commit_base: &CommitBase, ct_rand: Scalar, com:RistrettoPoint)->ProofStruct{

    // create FIAT shamir proof for when the secret is 0
       // let mut hasher = Sha3_256::new();
       let mut rng = OsRng;
       let v1 = random_scalar(&mut rng); // v1
       let mut rng = OsRng;
       let e1 = random_scalar(&mut rng); // e1
       let mut rng = OsRng;
       let b = random_scalar(&mut rng); // b

       // d1 : Cheat
       let ce1 = -(&com * &e1); // 1/c^{e1}
       let ge1 = &commit_base.g * &e1; // g^{e1}
       let hv1 = &commit_base.h * &v1;      
       let d1 = hv1 + ce1 + ge1; //h^{v1} x 1/c^{e1} x g^{e1}

       // d0 : Honest
       let d0 = &b * &commit_base.h; // h^{b}  

       let mut hasher = Sha3_256::new();
       let mut input_to_rom: Vec<u8> = Vec::new();
       input_to_rom.extend(com.compress().as_bytes());        
       input_to_rom.extend(d0.compress().as_bytes());
       input_to_rom.extend(d1.compress().as_bytes());
       hasher.update(input_to_rom); // this will take d0, d1, commitment as a byte array
       let result: [u8;32] =  hasher.finalize().into();        
       let e = Scalar::from_bytes_mod_order(result); // In the interactive version this would come in round 2
       
       let e0 = e - e1;         
       let v0 = b + e0*ct_rand;

       return ProofStruct{e0, e1, e, v0, v1, d0, d1};


}


pub fn create_proof_1_with_com(commit_base: &CommitBase, ct_rand: Scalar, com:RistrettoPoint)->ProofStruct{

    // create FIAT shamir proof for when the secret is 0
      // let mut hasher = Sha3_256::new();

      let mut rng = OsRng;
      let v0 = random_scalar(&mut rng); // v0
      let mut rng = OsRng;
      let e0 = random_scalar(&mut rng); // e0
      let mut rng = OsRng;
      let b = random_scalar(&mut rng); // b

      // d0 : Cheat
      let ce0 = -(&com * &e0); // 1/c^{e0}
      let hv0 = &commit_base.h * &v0; // h^{0}     
      let d0 = hv0 + ce0; //h^{v0} x 1/c^{e0} 

      // d1 : Honest
      let d1 = &b * &commit_base.h; // h^{b}  

      let mut hasher = Sha3_256::new();
      let mut input_to_rom: Vec<u8> = Vec::new();
      input_to_rom.extend(com.compress().as_bytes());        
      input_to_rom.extend(d0.compress().as_bytes());
      input_to_rom.extend(d1.compress().as_bytes());
      hasher.update(input_to_rom); // this will take d0, d1, commitment as a byte array
      let result: [u8;32] =  hasher.finalize().into();        
      let e = Scalar::from_bytes_mod_order(result); // In the interactive version this would come in round 2
      
      let e1 = e - e0;         
      let v1 = b + e1*ct_rand;

      return ProofStruct{e0, e1, e, v0, v1, d0, d1};


}

// verify_or_proof
pub fn sigma_or_verify(commit_base: &CommitBase, pf_scalar: &ProofStruct, reconcom:RistrettoPoint) -> bool {

    // CHECK the hash of the initial pf_scalar is equal to e and then 
    //let mut hasher = Sha3_256::new();
    let mut input_to_rom: Vec<u8> = Vec::new();
    input_to_rom.extend(reconcom.compress().as_bytes());

    input_to_rom.extend(pf_scalar.d0.compress().as_bytes());
    input_to_rom.extend(pf_scalar.d1.compress().as_bytes());
    let mut hasher = Sha3_256::new();
    hasher.update(input_to_rom); // this will take d0, d1, commitment as a byte array
    let result: [u8;32] =  hasher.finalize().into();        
    let e = Scalar::from_bytes_mod_order(result);
    assert_eq!(e, pf_scalar.e);

    // pf_scalar.e = hash(d0,d1, com. )
    assert_eq!(pf_scalar.e, pf_scalar.e1 + pf_scalar.e0); // CHECK e = e0 + e1

    let ce0 = &reconcom * &pf_scalar.e0; //c^{e0}
    let hv0 = commit_base.h * &pf_scalar.v0; //h^{v0}
    assert_eq!(&pf_scalar.d0 + &ce0, hv0); //d0 c^{e0} = h^{v0}

    let ce1 = &reconcom * &pf_scalar.e1; // c^{e1}

    let ge1 = commit_base.g * &pf_scalar.e1; // g^{e1}
    let hv1 = commit_base.h * &pf_scalar.v1;// h^{v1}

    assert_eq!(&pf_scalar.d1 + &ce1, &ge1 + &hv1); //d1 c^{e1} = g^{e1}h^{v1}

    return true;
}

impl ProofStruct{
    pub fn verify(&self, commit_base: &CommitBase, reconcom:RistrettoPoint) -> bool {
        sigma_or_verify(commit_base, self, reconcom)
    }
}

