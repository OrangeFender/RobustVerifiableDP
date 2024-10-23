extern crate robust_verifiable_dp as dp;


use dp::client::Client;
use dp::public_parameters::PublicParameters;
use dp::prover::Prover;
use dp::verifier::Verifier;
use dp::constants;
use dp::sign;
use dp::share_store::MemoryShareStore;
use dp::user_store::MemoryUserStore;
use dp::replicated::recon_shares;
use dp::morra::{MorraBroad,MorraBroadCast};
use std::time::Instant;

const NUM_CLIENTS: usize = 100;

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
    .map(|(i, store)| Prover::new(i, &pp, sig_keys[i].clone(),&pks, store))
    .collect();

    let mut coms_v_ks = Vec::new();
    for i in 0..constants::PROVER_NUM {
        coms_v_ks.push(provers[i].get_coms_v_k());
    }

    let mut broad = MemoryUserStore::new();

    let verifier= Verifier::new(coms_v_ks, pks.clone());


    //客户上传数据过程

    for i in 0..NUM_CLIENTS{
        let random_bool = rand::random();
        let client = Client::new(i as u64 ,random_bool,&pp, pks.clone().try_into().unwrap());
        client.send_proof_coms(&mut broad);
        for j in 0..constants::PROVER_NUM{
            let tuple = client.send_share(j);
            let res=provers[j].handle_client(tuple, &mut broad);
            assert!(res);
        }
        
        assert!(client.reveal_share(&mut broad));

    }

    let duration = start.elapsed();

    let start2 = Instant::now();

    //morra游戏过程
    let mut morra_broad = MorraBroadCast::new(pp.clone());
    for i in 0..constants::PROVER_NUM{
        provers[i].morra_commit(&mut morra_broad);
    }
    for i in (0..constants::PROVER_NUM).rev(){
        provers[i].morra_reveal(&mut morra_broad);
    }
    //验证过程

    let mut shares=Vec::new();
    let aggregated_com = verifier.check_all_users_and_sum_coms(&broad, &pp);

    for j in 0..constants::PROVER_NUM{
        let share=provers[j].check_all_users_and_sum_share( &broad);
        let morra_scalar= morra_broad.get_morra_scalar().unwrap();
        let share_with_noise=provers[j].add_noise_from_morra_scalar(morra_scalar, share);
        shares.push(share_with_noise.clone());
        let res= verifier.handle_prover_share_with_morra_scalar(j, share_with_noise, aggregated_com.clone(), morra_broad.get_morra_scalar().unwrap(), &pp);
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
