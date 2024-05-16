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

// Client 获取transcript
// This function outputs the Mixed-VSS transcript. 
// This function assumes that all signatures are valid
pub fn get_transcript(num_prover:usize, signers: &Vec<bool>, sigs: Vec<Ed25519Signature>) -> TranscriptEd {
    let agg_sig = aggregate_sig(signers.clone(), sigs);
    let missing_count = num_prover-agg_sig.get_num_voters();

    let mut shares = Vec::with_capacity(missing_count);
    let mut randomness = Vec::with_capacity(missing_count);

    for (i, &is_set) in signers.iter().enumerate() {
        if !is_set {
            shares.push(self.shares[i].share[0]);
            randomness.push(self.shares[i].share[1]);
        }
    }

    TranscriptEd::new(self.coms.clone(), shares, randomness, agg_sig)  // Ii能够从agg_sig的bitmask中得到，在上面函数中也最后一句也设置了签名的集合是哪些

}

// Prover 发送transcript