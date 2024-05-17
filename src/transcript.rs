use blstrs::{G1Projective, Scalar};

use crate::sigs::EdSignature;

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
}

impl TranscriptEd {
    pub fn new(coms:Vec<G1Projective>, shares:Vec<Scalar>, randomness:Vec<Scalar>, agg_sig: EdSignature) -> Self {
        Self {
            coms: coms,
            shares: shares,
            randomness: randomness,
            agg_sig: agg_sig,
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
use blstrs::{G1Projective, Scalar};
use ff::Field;
use rand::rngs::StdRng;
use rand::thread_rng;
use rand_core::SeedableRng;

use crate::vss::common::random_scalars_range;
use crate::vss::transcript::TranscriptEd;
use crate::fft::fft;
use crate::vss::public_parameters::PublicParameters;
use crate::vss::keys::InputSecret;
use crate::pvss::SharingConfiguration;

use crate::prover::Prover;
use crate::client::Client;
use crate::sig::aggregate_sig;
use crate::low_deg::low_deg_test;  // 待实现

// Client 获取transcript
// This function outputs the Mixed-VSS transcript. 
// This function assumes that all signatures are valid
pub fn get_transcript(ct:&Clitnt, num_prover:usize, signers: &Vec<bool>, sigs: Vec<Ed25519Signature>) -> TranscriptEd {
    let agg_sig = aggregate_sig(signers.clone(), sigs);
    let missing_count = num_prover-agg_sig.get_num_voters();

    let mut shares = Vec::with_capacity(missing_count);
    let mut randomness = Vec::with_capacity(missing_count);

    for (i, &is_set) in signers.iter().enumerate() {
        if !is_set {
            // shares.push(self.shares[i].share[0]);  // 这是f_share
            // randomness.push(self.shares[i].share[1]);  // 这是r_share
            shares.push(ct.f_poly[i]);
            randomness.push(ct.r_poly[i]);
        }
    }

    TranscriptEd::new(ct.coms_f_x.clone(), shares, randomness, agg_sig)  // Ii能够从agg_sig的bitmask中得到，在上面函数中也最后一句也设置了签名的集合是哪些

}

// Prover 收到transcript后进行验证
pub fn verify_com(coms:&Vec<G1Projective>, sc: &SharingConfiguration) -> bool {
    low_deg_test(coms, sc)
}

pub fn verify_eval(coms:&Vec<G1Projective>, pp: &PublicParameters, i:usize, share: &Share) -> bool {
    let com = G1Projective::multi_exp(pp.get_bases(), share.get());
    coms[i].eq(&com)
}

// Prover 验证transcript
// 这里将将原来的PolyComReceiver:self替换为了pv_share
pub fn verify_transcript(pv_share:&Vec<G1Projective>, t: &TranscriptEd, sc: &SharingConfiguration, pp: &PublicParameters, pk: &MultiEd25519PublicKey) -> bool {
    let num_signed = t.agg_sig().get_num_voters();
    let n = t.coms().len();
    let missing_ct = n-num_signed;
    
    // Checking low-degree of the committed polynomial
    assert!(verify_com(t.coms(), sc)); 
    assert!(t.shares().len() == t.randomness().len());
    assert!(t.shares().len() == missing_ct);

    // Checking correctness of aggregate signature
    let msg = bcs::to_bytes(pv_share).unwrap();
    assert!(t.agg_sig().verify(msg.as_slice(), &pk));

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

    let com_pos = G1Projective::multi_exp(pp.get_bases(), [s, r].as_slice());
    let com = G1Projective::multi_exp(&missing_coms, &lambdas);
    
    com_pos == com

}