use ed25519_dalek::{Signature, Keypair, PublicKey, Signer, Verifier};
use blstrs::G1Projective;
use serde::{Serialize, Deserialize};
use crate::replicated::ReplicaCommitment;

pub fn sign_verified_deal(sig_key:&Keypair, coms: &ReplicaCommitment) -> Signature {
    // Return signature the dealing is valid
    let msg = bcs::to_bytes(&coms).unwrap();
    //return Some(sig_key.sign_arbitrary_message(msg.as_slice()));//去掉了some
    return sig_key.sign(msg.as_slice());
}

pub fn verify_sig(coms: &ReplicaCommitment, pk: &PublicKey, sig: Signature) -> bool {
    let msg = bcs::to_bytes(&coms).unwrap();
    pk.verify(msg.as_slice(), &sig).is_ok()
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct mySignature(Vec<u8>);  // Assuming the signature is 64 bytes
impl From<Signature> for mySignature {
    fn from(sig: Signature) -> Self {
        mySignature(sig.to_bytes().to_vec())
    }
}
impl Into<Signature> for mySignature {
    fn into(self) -> Signature {
        Signature::from_bytes(&self.0).unwrap()
    }
}