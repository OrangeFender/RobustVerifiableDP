extern crate robust_verifiable_dp as dp;


use ed25519_dalek::{Keypair, PublicKey, Signature};
use blstrs::{G1Projective,Scalar};
use dp::sigma_or::ProofStruct;
use dp::{util, verifier};
use dp::client::Client;
use dp::public_parameters::PublicParameters;
use dp::prover::Prover;
use dp::verifier::VerifierBroad;
use dp::commitment::Commit;
use dp::msg_structs::{ShareProof,Transcript};
use dp::constants;
use dp::sign;
use dp::datastore::{self, MemoryShareStore, MemoryCommitmentStore};
use dp::replicated::{recon_shares, ReplicaShare};

use rand::Rng;

use std::time::Instant;


const NUM_CLIENTS: usize = 1000;

fn main(){

    let start = Instant::now();

    // Create public parameters
    //生成公共参数
    let pp = PublicParameters::new( b"seed");

    let mut pks=Vec::new();
    let mut sig_keys =Vec::new();
    for i in 0..constants::PROVER_NUM {
        let (sk,pk)=sign::gen_keys();
        pks.push(pk);
        sig_keys.push(sk);
    }

    // Create clients
    //生成客户端
    let mut clients: Vec<Client> = Vec::new();
    for i in 0..NUM_CLIENTS {
        let random_bool = rand::random();
        let client = Client::new(i as u64 ,random_bool,&pp, pks.clone().try_into().unwrap());
        clients.push(client);
    }

    // Create share stores first
    let mut share_stores: Vec<MemoryShareStore> = (0..constants::PROVER_NUM)
    .map(|_| MemoryShareStore::new())
    .collect();

    // Create provers
    //生成服务器
    let mut provers: Vec<Prover<MemoryShareStore>> = share_stores
    .iter_mut()
    .enumerate()
    .map(|(i, store)| Prover::new(i, &pp, sig_keys[i].to_bytes(), store))
    .collect();

    //创建数据库相关
    let mut share_stores_by_verifier = Vec::new();
    let mut coms_v_ks = Vec::new();
    for i in 0..constants::PROVER_NUM {
        share_stores_by_verifier.push(MemoryShareStore::new());
        coms_v_ks.push(provers[i].get_coms_v_k());
    }


    let share_stores_by_verifier_refs: Vec<&mut MemoryShareStore> = share_stores_by_verifier.iter_mut().collect();

    let mut commitment_store = MemoryCommitmentStore::new();

    let mut verifier= VerifierBroad::new(coms_v_ks, pks.clone(), share_stores_by_verifier_refs, &mut commitment_store);


    //客户上传数据过程

    for i in 0..NUM_CLIENTS{
        for j in 0..constants::PROVER_NUM{
            let msg = clients[i].create_prover_msg(j);
            let res=provers[j].handle_msg(&msg, &pp);
            assert!(res.is_some());
            let res=res.unwrap();
            clients[i].verify_sig_and_add(res, j);
        }
        let transcript=clients[i].gen_transcript();

        let res=verifier.handle_trancript(transcript, &pp);

        assert!(res);

    }


    let start2 = Instant::now();

    //验证过程
    let uids=verifier.list_clients();

    let mut shares=Vec::new();
    for j in 0..constants::PROVER_NUM{
        let verifier = &verifier;
        let get_share_fn: Box<dyn Fn(u64) -> ReplicaShare> = Box::new(move |uid: u64| {
            verifier.get_share(j, uid)
        });
        let res=provers[j].response_verifier(uids.clone(), get_share_fn);
        shares.push(res.clone());
        let res= verifier.handle_prover_share(j, res, verifier.aggregate_coms(), uids.clone(), &pp);
        assert!(res);
    }

    let res=recon_shares(shares);
    assert!(res.is_some());
    println!("Result in HEX is: {}",res.unwrap().to_string());

    let duration = start.elapsed();

    let duration2 = start2.elapsed();

    println!("Number of clients is: {}", NUM_CLIENTS);

    println!("Time elapsed in total is: {:?}", duration);

    println!("Time elapsed in sum clients, reconstruction and verification is: {:?}", duration2);

    println!("All tests passed!");
}
