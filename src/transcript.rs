use blstrs::{G1Projective, Scalar};

use crate::commitment::Commit;
use crate::sig::{EdSignature, verify_sig};

#[derive(Clone)]
#[allow(non_snake_case)]
pub struct TranscriptEd {
    /// Pedersen commitment to the polynomial
    coms: Vec<G1Projective>,
    /// Shares of those who did not sign
    shares: Vec<Scalar>,
    /// Pedersen commitment randomness of those who did not sign
    randomness: Vec<Scalar>,
    /// Multisignature from the set of nodes who received valid shares
    agg_sig : EdSignature,

    sigs: Vec<Ed25519Signature>,
}

impl TranscriptEd {
    pub fn new(coms:Vec<G1Projective>, shares:Vec<Scalar>, randomness:Vec<Scalar>, agg_sig: EdSignature, sigs:Vec<Ed25519Signature> ) -> Self {
        Self {
            coms: coms,
            shares: shares,
            randomness: randomness,
            agg_sig: agg_sig,
            sigs: sigs,
        }
    }

    pub fn coms(&self) -> &Vec<G1Projective> {
        &self.coms
    }

    pub fn shares(&self) -> &Vec<Scalar> {
        &self.shares
    }

    pub fn randomness(&self) -> &Vec<Scalar> {
        &self.randomness
    }

    pub fn agg_sig(&self) -> &EdSignature {
        &self.agg_sig
    }
}

use aptos_bitvec::BitVec;
use aptos_crypto::{Uniform, Signature};
use aptos_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature};
use aptos_crypto::multi_ed25519::{MultiEd25519PublicKey, MultiEd25519Signature};
use aptos_crypto::test_utils::{TEST_SEED, KeyPair};
//use blstrs::{G1Projective, Scalar};
use ff::Field;
use rand::rngs::StdRng;
use rand::thread_rng;
use rand_core::SeedableRng;

use crate::prover::Prover;
use crate::client::Client;
use crate::sig::aggregate_sig;
use crate::low_deg::low_deg_test;  // 待实现
use crate::public_parameters::PublicParameters;
use crate::util::random_scalars_range;



// // Prover 收到transcript后进行验证
// pub fn verify_com(coms:&Vec<G1Projective>, pp: &PublicParameters) -> bool {
//     low_deg_test(coms, pp.get_threshold(), pp.get_prover_num())
// }

// pub fn verify_eval(coms:&Vec<G1Projective>, pp: &PublicParameters, i:usize, share: &Share) -> bool {
//     let com = G1Projective::multi_exp(pp.get_commit_base(), share.get());
//     coms[i].eq(&com)
// }

// Prover 验证transcript
// 这里将将原来的PolyComReceiver:self替换为了pv_share
pub fn verify_transcript(pv_share:&Vec<G1Projective>, t: &TranscriptEd, pp: &PublicParameters, pks: &Vec<Ed25519PublicKey>) -> bool {
 
    let num_signed = t.agg_sig().get_num_voters();
    let n = t.coms().len();
    let missing_ct = n-num_signed;
    let threshold= pp.get_threshold();
    // Checking low-degree of the committed polynomial
    assert!(low_deg_test(t.coms(), threshold, pp.get_prover_num())); 
    assert!(t.shares().len() == t.randomness().len());
    assert!(t.shares().len() == missing_ct);

    // Aggregate public key

    let multi_pks=t.agg_sig.get_signers_addresses(pks);

    //let threshold=threshold.try_into().unwrap();

    //let agg_pk = MultiEd25519PublicKey::new(multi_pks.clone(), threshold).unwrap();

    // Checking correctness of aggregate signature
    //let msg = bcs::to_bytes(pv_share).unwrap();
    //assert!(t.agg_sig().verify(msg.as_slice(), &agg_pk));
    //TODO目前还是用的普通签名
    for i in 0..num_signed {
        let ret=verify_sig(&pv_share.clone(), &multi_pks[i], t.sigs[i].clone());
        //assert!(ret.is_ok());
        if ret==false{
            return false;
        }
    }

    let mut missing_coms = Vec::with_capacity(t.shares().len());

    let mut rng = thread_rng();
    let lambdas = random_scalars_range(&mut rng, u64::MAX, missing_ct);

    // Checking the correctness of the revealed shares and randomness 
    let mut idx = 0;
    let mut s = Scalar::zero();
    let mut r = Scalar::zero();
    for pos in 0..n {
        if !t.agg_sig().get_signers_bitvec().is_set(pos as u16) {
            s += lambdas[idx]*t.shares()[idx];
            r += lambdas[idx]*t.randomness()[idx];
            
            idx +=1;
            missing_coms.push(pv_share[pos]);
        }
    }

    if missing_coms.len()==0{
        return true;
    }

    let com_pos = pp.get_commit_base().commit(s, r);
    //let com_pos = G1Projective::multi_exp(pp.get_base(), [s, r].as_slice());
    let com = G1Projective::multi_exp(&missing_coms, &lambdas);
    
    com_pos == com

}