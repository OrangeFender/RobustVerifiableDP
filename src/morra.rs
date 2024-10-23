use blstrs::{G1Projective, Scalar};
use crate::commitment::Commit;
use crate::constants::PROVER_NUM;
use crate::public_parameters::PublicParameters;
use ff::Field;

pub trait MorraBroad{
    fn commit(&mut self, prover_id:usize, com:G1Projective);
    fn reveal(&mut self, prover_id:usize, m:Scalar, r:Scalar);
    fn get_morra_scalar(&self) -> Option<Scalar>;
}

pub struct MorraBroadCast{
    pp:PublicParameters,
    coms:[Option<G1Projective>;PROVER_NUM],
    ms:[Option<Scalar>;PROVER_NUM],
    rs:[Option<Scalar>;PROVER_NUM],
    round_com:usize,
    round_reveal:usize,
}

impl MorraBroadCast{
    pub fn new(pp:PublicParameters) -> Self {
        MorraBroadCast {
            pp,
            coms:[None;PROVER_NUM],
            ms:[None;PROVER_NUM],
            rs:[None;PROVER_NUM],
            round_com:0,
            round_reveal:PROVER_NUM-1,
        }
    }
}

impl MorraBroad for MorraBroadCast{
    fn commit(&mut self, prover_id:usize, com:G1Projective){
        if prover_id!=self.round_com {
            return;
        }
        self.coms[prover_id]=Some(com);
        self.round_com+=1;
    }

    fn reveal(&mut self, prover_id:usize, m:Scalar, r:Scalar){
        if prover_id!=self.round_reveal {
            return;
        }
        if !self.pp.get_commit_base().vrfy(m,r,self.coms[prover_id].unwrap()) {
            return;
        }
        self.ms[prover_id]=Some(m);
        self.rs[prover_id]=Some(r);
        if self.round_reveal>0 {
            self.round_reveal-=1;
            return;
        }
        return;
    }

    fn get_morra_scalar(&self) -> Option<Scalar>{
        let mut morra_scalar=Scalar::zero();
        for i in 0..PROVER_NUM{
            if let Some(m)=self.ms[i]{
                morra_scalar+=m;
            }else{
                return None;
            }
        }
        Some(morra_scalar)
    }
}
