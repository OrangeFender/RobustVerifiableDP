extern crate robust_verifiable_dp as dp;


use dp::client::Client;
use dp::public_parameters::PublicParameters;
use dp::prover::Prover;
use dp::verifier::Verifier;
use dp::constants;
use dp::sign;
use dp::share_store::MemoryShareStore;
use dp::user_store::MemoryUserStore;
use dp::replicated::{recon_shares, ReplicaShare};
use std::time::Instant;


const NUM_CLIENTS: usize = 500;

fn main(){

    let start = Instant::now();

    // Create public parameters
    //生成公共参数
    let pp = PublicParameters::new( b"seed");

    let mut pks=Vec::new();
    let mut sig_keys =Vec::new();
    for _ in 0..constants::PROVER_NUM {
        let (sk,pk)=sign::gen_keys();
        pks.push(pk);
        sig_keys.push(sk);
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
    let mut coms_v_ks = Vec::new();
    for i in 0..constants::PROVER_NUM {
        coms_v_ks.push(provers[i].get_coms_v_k());
    }

    let mut broad = MemoryUserStore::new();

    let mut verifier= Verifier::new(coms_v_ks, pks.clone());


    //客户上传数据过程

    for i in 0..NUM_CLIENTS{
        let random_bool = rand::random();
        let mut client = Client::new(i as u64 ,random_bool,&pp, pks.clone().try_into().unwrap());
        client.send_proof_coms(&mut broad);
        for j in 0..constants::PROVER_NUM{
            client.send_share(proverind, comm)
        }


        assert!(res);

    }

    let duration = start.elapsed();

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


    let duration2 = start2.elapsed();

    println!("Number of clients is: {}", NUM_CLIENTS);

    println!("Time elapsed in interaction with clients is: {:?}", duration);

    println!("Time elapsed in sum clients, reconstruction and verification is: {:?}", duration2);

    println!("All tests passed!");
}
