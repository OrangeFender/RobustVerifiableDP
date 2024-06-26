use blstrs::{G1Projective, Scalar};
use crate::commitment::Commit;
use crate::public_parameters::PublicParameters;
use crate::util;
use crate::fft::fft;
use aptos_crypto::ed25519::{ Ed25519PublicKey, Ed25519Signature};
use crate::transcript::TranscriptEd;
use crate::sig::verify_sig;
use crate::sigma_or::{ProofStruct, create_proof_0, create_proof_1};
use crate::msg_structs::ComsAndShare;
use crate::shamirlib;

pub struct Client{
    id: u64,
    x_int: usize,
    x_scalar: Scalar,
    r_poly: Vec<Scalar>,//commitment blinding factor's polynomial coefficients
    f_poly: Vec<Scalar>,//polynomial coefficients
    f_eval: Vec<Scalar>,//
    r_eval: Vec<Scalar>,//
    coms_f_x: Vec<G1Projective>,//
    sigma_proof: ProofStruct,
}

impl Client{
    pub fn new(id: u64, x: bool,pp:&PublicParameters) -> Self {
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

        let r_poly = util::random_scalars(t+1, &mut rng);
        let mut f_poly = util::random_scalars(t+1, &mut rng);

        f_poly[0] = x_scalar;

        let mut f_evals = shamirlib::eval_poly_at_1_n(&f_poly, pp.get_prover_num());
        let mut r_evals = shamirlib::eval_poly_at_1_n(&r_poly, pp.get_prover_num());

        let mut coms_f_x = Vec::new();

        for i in 0..pp.get_prover_num() {
            coms_f_x.push(pp.get_commit_base().commit(f_evals[i], r_evals[i]));
        }

        let proof;
        if x{
            proof = create_proof_1(&pp.get_commit_base(), x_scalar.clone(), r_poly[0].clone());
        }
        else{
            proof = create_proof_0(&pp.get_commit_base(), x_scalar.clone(), r_poly[0].clone());
        }

        Self {
            id,
            x_int,
            x_scalar,
            r_poly,
            f_poly,
            f_eval: f_evals,
            r_eval: r_evals,
            coms_f_x,
            sigma_proof: proof,
        }
    }

    pub fn get_coms_f_x(&self) -> Vec<G1Projective> {
        self.coms_f_x.clone()
    }

    pub fn get_evals(&self, ind:usize) -> (Scalar, Scalar) {
        (self.f_eval[ind].clone(), self.r_eval[ind].clone())
    }



    pub fn vrfy_sig(&self, pk: &Ed25519PublicKey, sig: &Ed25519Signature) -> bool {
        verify_sig(&self.coms_f_x, pk, sig.clone())
    }

    // This function outputs the Mixed-VSS transcript. 
    // This function assumes that all signatures are valid
    pub fn get_transcript(&self, num_prover:usize, signers: &Vec<bool>, sigs: Vec<(Ed25519Signature,usize)>) -> TranscriptEd {
        //let agg_sig = aggregate_sig(signers.clone(), sigs.clone());
        let missing_count = num_prover-sigs.len();

        let mut shares = Vec::with_capacity(missing_count);
        let mut randomness = Vec::with_capacity(missing_count);

        for (i, &is_set) in signers.iter().enumerate() {
            if !is_set {
                shares.push(self.f_eval[i]);
                randomness.push(self.r_eval[i]);
            }
        }
        TranscriptEd::new(self.id,self.coms_f_x.clone(), shares, randomness, sigs.clone(),self.sigma_proof.clone())
    }

    pub fn create_sigma_proof(&self, pp: &PublicParameters) -> ProofStruct {
        let create_proof;
        // 这里应该能改成pub吧，因为在实际实现的时候这个地方是由Client自己去调用自己的x_int.
        if self.x_int == 0 {
            create_proof = create_proof_0(&pp.get_commit_base(), self.x_scalar, self.r_poly[0]);
        }
        else {
            create_proof = create_proof_1(&pp.get_commit_base(), self.x_scalar, self.r_poly[0]);
        }
        
        create_proof
    }

    pub fn create_prover_msg(&self,pp: &PublicParameters,proverind:usize)->ComsAndShare{
        //let sigma_proof=self.create_sigma_proof(pp);
        let coms=self.get_coms_f_x();
        let (f,r)=self.get_evals(proverind);
        ComsAndShare{
            id:self.id,
            coms,
            share:f,
            pi:r,
            proof:self.sigma_proof.clone(),
        }
    }

}

