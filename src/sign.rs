use ed25519_dalek::{Signature, SigningKey, VerifyingKey, Signer, Verifier};
use serde::{Serialize, Deserialize};
use crate::replicated::ReplicaCommitment;
use rand::rngs::OsRng;
use std::thread;
use std::sync::mpsc;
use std::sync::Arc;


pub fn gen_keys() -> (SigningKey, VerifyingKey) {
    let mut rng = OsRng;
    let pair: SigningKey = SigningKey::generate(&mut rng);
    let pk = pair.verifying_key();
    (pair, pk)
}

pub fn sign_verified_deal(sig_key:&SigningKey, coms: &ReplicaCommitment) -> Signature {
    // Return signature the dealing is valid
    let msg = coms.to_bytes();
    //return Some(sig_key.sign_arbitrary_message(msg.as_slice()));//去掉了some
    return sig_key.sign(msg.as_slice());
}

pub fn verify_sig(coms: &ReplicaCommitment, pk: &VerifyingKey, sig: &Signature) -> bool {
    let msg = coms.to_bytes();
    pk.verify(msg.as_slice(), &sig).is_ok()
}

pub fn verify_sigs_multithreaded(coms: Vec<ReplicaCommitment>, pks: Vec<VerifyingKey>, sigs: Vec<Signature>) -> Vec<bool> {
    let (tx, rx) = mpsc::channel();

    for ((com, pk), sig) in coms.into_iter().zip(pks.into_iter()).zip(sigs.into_iter()) {
        let tx = tx.clone();

        thread::spawn(move || {
            let result = verify_sig(&com, &pk, &sig);
            tx.send(result).expect("Failed to send result");
        });
    }

    drop(tx); // Close the channel

    rx.iter().collect()
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
