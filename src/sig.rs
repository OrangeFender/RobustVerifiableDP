/// This struct represents a BLS multi-signature or aggregated signature:
/// it stores a bit mask representing the set of validators participating in the signing process
/// and the multi-signature/aggregated signature itself,
/// which was aggregated from these validators' partial BLS signatures.
/// ed25519指的是在Edwards椭圆曲线上的签名方案，这里应该是设计了一个多重签名方案
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, CryptoHasher, BCSCryptoHash)]
pub struct EdSignature {
    // 用bitmask掩码来表示哪些validator签名了，哪些没签名
    validator_bitmask: BitVec,
    sig: Option<MultiEd25519Signature>,
}

impl EdSignature {
    pub fn new(
        validator_bitmask: BitVec,
        ed_signature: Option<MultiEd25519Signature>,
    ) -> Self {
        Self {
            validator_bitmask,
            sig: ed_signature,
        }
    }

    pub fn empty() -> Self {
        Self {
            validator_bitmask: BitVec::default(),
            sig: None,
        }
    }

    pub fn get_signers_bitvec(&self) -> &BitVec {
        &self.validator_bitmask
    }

    pub fn get_signers_addresses(
        &self,
        validator_addresses: &[Ed25519PublicKey],
    ) -> Vec<Ed25519PublicKey> {
        validator_addresses
            .iter()
            .enumerate()
            .filter_map(|(index, addr)| {
                let addr_copy = addr.clone();
                if self.validator_bitmask.is_set(index as u16) {
                    Some(addr_copy)
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn get_num_voters(&self) -> usize {
        self.validator_bitmask.count_ones() as usize
    }

    pub fn sig(&self) -> &Option<MultiEd25519Signature> {
        &self.sig
    }

    pub fn verify(&self, msg: &[u8], pk: &MultiEd25519PublicKey) -> bool {
        let sig = self.sig.clone().unwrap();
        let valid = sig.verify_arbitrary_msg(&msg, &pk).is_ok();
        valid
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

// 生成签名密钥对的函数
pub fn generate_ed_sig_keys(n: usize) -> Vec<KeyPair<Ed25519PrivateKey, Ed25519PublicKey>> {
    let mut rng = StdRng::from_seed(TEST_SEED);
    (0..n)
        .map(|_| KeyPair::<Ed25519PrivateKey, Ed25519PublicKey>::generate(&mut rng))
        .collect()
}

// 对于Prover需要签名, 这里需要在其他函数完成两步验证, 验证通过后再进行签名
// 利用prover的签名密钥签名
pub fn sign_verified_deal(pv:&Prover, ct:&Client) -> Option<Ed25519Signature> {
    // Return signature the dealing is valid
    let msg = bcs::to_bytes(&ct.coms_f_x).unwrap();
    return Some(pv.sig_key.sign_arbitrary_message(msg.as_slice()));
}

// 对于Client需要验证签名。
// 利用prover的签名公钥验签
pub fn verify_sig(ct:&Client, pk: &Ed25519PublicKey, sig: Ed25519Signature) -> bool {
    let msg = bcs::to_bytes(&ct.coms).unwrap();
    sig.verify_arbitrary_msg(msg.as_slice(), pk).is_ok()
}

// 生成聚合签名，这样就不需要再生成一个多重签名的序列了
// signers 表示签名的prover集合。函数体没动，感觉这里ct可以不需要
pub fn aggregate_sig(signers: Vec<bool>, sigs: Vec<Ed25519Signature>) -> EdSignature {
    // AggregateSignature::new(BitVec::from(signers), Some(bls12381::Signature::aggregate(sigs).unwrap()))
    let mut indices: Vec<usize> = Vec::with_capacity(sigs.len());
    for i in 0..signers.len() {
        if signers[i] {
            indices.push(i);
        }
    }

    let new_sigs = sigs.iter().zip(indices.iter()).map(|(s, &i)| (s.clone(),i)).collect::<Vec<(Ed25519Signature,usize)>>();
    let mt_sig = MultiEd25519Signature::new(new_sigs);
    EdSignature::new(BitVec::from(signers), Some(mt_sig.unwrap()))
}
