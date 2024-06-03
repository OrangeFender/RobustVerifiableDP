use blstrs::{G1Projective, Scalar};

use crate::commitment::Commit;
use crate::sig::{EdSignature, verify_sig};
use crate::sigma_or::ProofStruct;
use serde::{Serialize, Deserialize};

#[derive(Clone, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct TranscriptEd {
    /// Pedersen commitment to the polynomial
    coms: Vec<G1Projective>,
    /// Shares of those who did not sign
    shares: Vec<Scalar>,
    /// Pedersen commitment randomness of those who did not sign
    randomness: Vec<Scalar>,
    /// Multisignature from the set of nodes who received valid shares
    //agg_sig : EdSignature,

    sigs: Vec<(Ed25519Signature,usize)>,

    sigma_or_proof: ProofStruct,
}

impl TranscriptEd {
    pub fn new(coms:Vec<G1Projective>, shares:Vec<Scalar>, randomness:Vec<Scalar>, sigs:Vec<(Ed25519Signature,usize)>, sigma_or_proof: ProofStruct) -> Self {
        Self {
            coms: coms,
            shares: shares,
            randomness: randomness,
            sigs: sigs,
            sigma_or_proof: sigma_or_proof,
        }
    }

    pub fn coms(&self) -> &Vec<G1Projective> {
        &self.coms
    }

    pub fn sigs(&self) -> &Vec<(Ed25519Signature,usize)> {
        &self.sigs
    }

    pub fn shares(&self) -> &Vec<Scalar> {
        &self.shares
    }

    pub fn randomness(&self) -> &Vec<Scalar> {
        &self.randomness
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
use crate::shamirlib;


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
 
    let num_signed = t.sigs().len();
    let n = t.coms().len();
    let missing_ct = n-num_signed;
    let threshold= pp.get_threshold();
    if t.shares().len() != missing_ct {
        return false;
    }
    if t.randomness().len() != missing_ct {
        return false;
    }
    // Checking low-degree of the committed polynomial
    if shamirlib::low_degree_test(t.coms(), threshold)==false{
        return false;
    }
    
    let xs = (1..=n).map(|i| Scalar::from(i as u64)).collect::<Vec<_>>();

    let reconcom = shamirlib::recon_com(pv_share, &xs);
    // check the sigma_or_proof
    if t.sigma_or_proof.verify(pp.get_commit_base(),reconcom)==false{
        return false;
    }
    

    // Aggregate public key


    //let threshold=threshold.try_into().unwrap();

    //let agg_pk = MultiEd25519PublicKey::new(multi_pks.clone(), threshold).unwrap();

    // Checking correctness of aggregate signature
    //let msg = bcs::to_bytes(pv_share).unwrap();
    //assert!(t.agg_sig().verify(msg.as_slice(), &agg_pk));
    //TODO目前还是用的普通签名
    //长度为sigs.len()的boolvec，初值为false
    let mut boolvec: Vec<bool> = vec![false; pp.get_prover_num()];

    for i in 0..num_signed {
        let (sig,id) = &t.sigs[i];
        let ret=verify_sig(&pv_share.clone(), &pks[*id], sig.clone());
        //assert!(ret.is_ok());
        if ret==false{
            return false;
        }else {
            boolvec[*id] = true;
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
        if boolvec[pos] == false{
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

impl TranscriptEd{
    pub fn verify(&self, pp: &PublicParameters, pks: &Vec<Ed25519PublicKey>, pv_share: &Vec<G1Projective>) -> bool {
        verify_transcript(pv_share, self, pp, pks)
    }
}