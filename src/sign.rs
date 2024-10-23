use ed25519_dalek::{Signature, SigningKey, VerifyingKey, Signer, Verifier};
use serde::{Serialize, Deserialize};
use crate::replicated::ReplicaCommitment;
use rand::rngs::OsRng;


pub fn gen_keys() -> (SigningKey, VerifyingKey) {
    let mut rng = OsRng;
    let pair: SigningKey = SigningKey::generate(&mut rng);
    let pk = pair.verifying_key();
    (pair, pk)
}

pub fn sign_verified_deal(sig_key:&SigningKey, coms: &ReplicaCommitment) -> Signature {
    // Return signature the dealing is valid
    let msg = bcs::to_bytes(&coms).unwrap();
    //return Some(sig_key.sign_arbitrary_message(msg.as_slice()));//去掉了some
    return sig_key.sign(msg.as_slice());
}

pub fn verify_sig(coms: &ReplicaCommitment, pk: &VerifyingKey, sig: Signature) -> bool {
    let msg = bcs::to_bytes(&coms).unwrap();
    pk.verify(msg.as_slice(), &sig).is_ok()
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct MySignature(Vec<u8>);  // Assuming the signature is 64 bytes
impl From<Signature> for MySignature {
    fn from(sig: Signature) -> Self {
        MySignature(sig.to_bytes().to_vec())
    }
}
impl Into<Signature> for MySignature {
    fn into(self) -> Signature {
        Signature::from_bytes(&self.0.try_into().unwrap())
    }
}
impl Default for MySignature {
    fn default() -> Self {
        MySignature(vec![0; 64])
    }
}
