use blstrs::{G1Projective, Scalar};
use rand::seq::index;
use crate::commitment::Commit;
use crate::public_parameters::PublicParameters;
use crate::util;
use crate::fft::fft;
use crate::sig::aggregate_sig;
use aptos_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature};
use crate::transcript::TranscriptEd;
use crate::sig::verify_sig;

pub struct Client{
    index: usize,
    x_int: usize,
    x_scalar: Scalar,
    r_poly: Vec<Scalar>,//commitment blinding factor's polynomial coefficients
    f_poly: Vec<Scalar>,//polynomial coefficients
    f_eval: Vec<Scalar>,//
    r_eval: Vec<Scalar>,//
    coms_f_x: Vec<G1Projective>,//
}

impl Client{
    pub fn new(index: usize, x: bool,pp:&PublicParameters) -> Self {
        let x_int = if x {1} else {0};
        
        let x_scalar = Scalar::from(x_int as u64);

        
        let t = pp.get_threshold();
        let mut rng = rand::thread_rng();

        // let mut r_poly = Vec::new();
        // let mut f_poly = Vec::new();
        // for _ in 0..t {
        //     //random generation of r_blinding and f_poly
        //     r_poly.push(util::random_scalar(&mut rng));
        //     f_poly.push(util::random_scalar(&mut rng));
        // }

        let r_poly = util::random_scalars(t, &mut rng);
        let mut f_poly = util::random_scalars(t, &mut rng);

        f_poly[0] = x_scalar;

        let mut f_evals = fft(&f_poly, pp.get_dom());
        f_evals.truncate(pp.get_prover_num());

        let mut r_evals = fft(&r_poly, pp.get_dom());
        r_evals.truncate(pp.get_prover_num());
        //注意这里的eval都是从x=1开始的

        let mut coms_f_x = Vec::new();

        for i in 0..pp.get_prover_num() {
            coms_f_x.push(pp.get_commit_base().commit(f_evals[i], r_evals[i]));
        }

        Self {
            index,
            x_int,
            x_scalar,
            r_poly,
            f_poly,
            f_eval: f_evals,
            r_eval: r_evals,
            coms_f_x,
        }
    }

    pub fn get_coms_f_x(&self) -> Vec<G1Projective> {
        self.coms_f_x.clone()
    }

    pub fn get_evals(&self, ind:usize) -> (Scalar, Scalar) {
        (self.f_eval[ind].clone(), self.r_eval[ind].clone())
    }

    pub fn send_ith_share(&self, i: usize) -> (Scalar, Scalar) {
        (self.f_eval[i], self.r_eval[i])
    }


    pub fn vrfy_sig(&self, pk: &Ed25519PublicKey, sig: &Ed25519Signature) -> bool {
        verify_sig(&self.coms_f_x, pk, sig.clone())
    }

    // This function outputs the Mixed-VSS transcript. 
    // This function assumes that all signatures are valid
    pub fn get_transcript(&self, num_prover:usize, signers: &Vec<bool>, sigs: Vec<Ed25519Signature>) -> TranscriptEd {
        let agg_sig = aggregate_sig(signers.clone(), sigs);
        let missing_count = num_prover-agg_sig.get_num_voters();

        let mut shares = Vec::with_capacity(missing_count);
        let mut randomness = Vec::with_capacity(missing_count);

        for (i, &is_set) in signers.iter().enumerate() {
            if !is_set {
                shares.push(self.f_poly[i]);
                randomness.push(self.r_poly[i]);
            }
        }

        TranscriptEd::new(self.coms_f_x.clone(), shares, randomness, agg_sig)
    }

    

}