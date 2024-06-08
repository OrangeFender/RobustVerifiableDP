use std::io::Write;
use rand::Rng;

use blstrs::{G1Projective,Scalar};
use robust_verifiable_dp::sig;
use robust_verifiable_dp::util;
use robust_verifiable_dp::public_parameters::PublicParameters;
use robust_verifiable_dp::prover::Prover;

const N_B: usize = 10;
// NUM_PROVERS >= 2*THRESHOLD + 1
const NUM_PROVERS: usize = 7;
const THRESHOLD: usize = 3;
const TYPES: usize = 20;




fn main(){
    let pp = PublicParameters::new(
        N_B, NUM_PROVERS, THRESHOLD, b"seed"
    );


    // 生成密钥文件
    let keys=sig::generate_ed_sig_keys(NUM_PROVERS);
    let mut pks = Vec::new();
    let mut sks = Vec::new();
    for i in 0..NUM_PROVERS {
        let (sk,pk)=keys[i];
        pks.push(pk);
        sks.push(sk);
    }
    //将pks整体使用bcs库序列化到文件中
    let pk_bytes = bcs::to_bytes(&pks).unwrap();
    let mut pk_file = std::fs::File::create("pks.dpfile").unwrap();
    pk_file.write_all(&pk_bytes).unwrap();
    //将sks的每个元素使用bcs库序列化到文件中，并标号
    for i in 0..NUM_PROVERS {
        let sk_bytes = sks[i];
        let mut sk_file = std::fs::File::create(format!("sk{}.dpfile",i)).unwrap();
        sk_file.write_all(&sk_bytes).unwrap();
    }
    let mut rng = rand::thread_rng();

    let mut comsvecvecvec=Vec::new();
    for i in 0..NUM_PROVERS {
        let mut boolvecvec=Vec::new();
        let mut Scalarvecvec=Vec::new();
        let mut comsvecvec=Vec::new();
        for j in 0..TYPES {
            let boolvec:Vec<bool>=(0..(N_B)).map(|_| rng.gen_bool(0.5)).collect();
            boolvecvec.push(boolvec.clone());
            let Scalarvec = util::random_scalars(N_B, &mut rng);
            Scalarvecvec.push(Scalarvec.clone());
            let prover = Prover::new(i,boolvec,Scalarvec,&pp,keys[i].0.clone());
            comsvecvec.push(prover.get_coms_v_k().clone());
        }
        //将boolvecvec整体使用bcs库序列化到文件中
        let boolvecvec_bytes = bcs::to_bytes(&boolvecvec).unwrap();
        let mut boolvecvec_file = std::fs::File::create(format!("boolvecvec{}.dpfile",i)).unwrap();
        boolvecvec_file.write_all(&boolvecvec_bytes).unwrap();
        //将Scalarvecvec整体使用bcs库序列化到文件中
        let Scalarvecvec_bytes = bcs::to_bytes(&Scalarvecvec).unwrap();
        let mut Scalarvecvec_file = std::fs::File::create(format!("Scalarvecvec{}.dpfile",i)).unwrap();
        Scalarvecvec_file.write_all(&Scalarvecvec_bytes).unwrap();
        //将comsvecvec传入comsvecvecvec
        comsvecvecvec.push(comsvecvec.clone());
    }
    //将comsvecvecvec整体使用bcs库序列化到文件中
    let comsvecvecvec_bytes = bcs::to_bytes(&comsvecvecvec).unwrap();
    let mut comsvecvecvec_file = std::fs::File::create("comsvecvecvec.dpfile").unwrap();
    comsvecvecvec_file.write_all(&comsvecvecvec_bytes).unwrap();
    
    

}