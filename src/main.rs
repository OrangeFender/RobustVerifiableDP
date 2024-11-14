extern crate robust_verifiable_dp as dp;


use dp::client::Client;
use dp::public_parameters::PublicParameters;
use dp::prover::Prover;
use dp::verifier::Verifier;
use dp::constants;
use dp::sign;
use dp::share_store::MemoryShareStore;
use dp::user_store::MemoryUserStore;
use dp::replicated::{recon_shares,ReplicaShare};
use std::time::Instant;

const NUM_CLIENTS: usize = 100;
const BAD_PROVERS: usize = 0;

fn main(){
    println!("Number of clients is: {}", NUM_CLIENTS);
    println!("Number of bits is: {}", constants::BITS_NUM);

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

    let start_of_prover = Instant::now();
    // Create provers
    //生成服务器
    let mut provers: Vec<Prover<MemoryShareStore>> = share_stores
    .iter_mut()
    .enumerate()
    .map(|(i, store)| Prover::new(i, &pp, sig_keys[i].clone(),&pks, store))
    .collect();

    let duration_prover = start_of_prover.elapsed();
    println!("Time elapsed in prover is: {:?}", duration_prover);
    
    let mut coms_v_ks = Vec::new();
    for i in 0..constants::PROVER_NUM {
        coms_v_ks.push(provers[i].get_coms_v_k());
    }

    let mut broad = MemoryUserStore::new();

    let verifier= Verifier::new(coms_v_ks, pks.clone());


    //客户上传数据过程

    let mut client_prover_tuple: Vec<Vec<(u64, ReplicaShare)>>=Vec::new();

    let start_of_VDDC = Instant::now();

    let mut clients=Vec::new();
    for i in 0..NUM_CLIENTS{
        let random_bool = rand::random();
        let client = Client::new(i as u64 ,random_bool,&pp, pks.clone().try_into().unwrap());
        client.send_proof_coms(&mut broad);
        let mut tuples=Vec::new();
        for j in 0..constants::PROVER_NUM{
            let tuple: (u64, ReplicaShare) = client.send_share(j);
            tuples.push(tuple);
        }
        client_prover_tuple.push(tuples);
        clients.push(client);
    }

    let duration_client_1 = start_of_VDDC.elapsed();


    let start_of_VDDP1 = Instant::now();

    for i in 0..NUM_CLIENTS{
        for j in 0..constants::PROVER_NUM-BAD_PROVERS{
            let tuple=client_prover_tuple[i][j].clone();
            let res=provers[j].handle_client(tuple, &mut broad);
            assert!(res);
            
        }
    }
    let duration_VDDP1 = start_of_VDDP1.elapsed();

    let start_of_VDDC2 = Instant::now();
    for i in 0..NUM_CLIENTS{
        clients[i].reveal_share(&mut broad);
    }
    let duration_client_2 = start_of_VDDC2.elapsed();

    let start_of_VDDP2 = Instant::now();

    let user_ids = provers[0].check_all_users(&broad); // every prover's user_ids are the same
    for j in 1..constants::PROVER_NUM-BAD_PROVERS{
        provers[j].check_all_users(&broad);
    }

    let duration_VDDP2 = start_of_VDDP2.elapsed();

    
    println!("Time elapsed in VDDC is: {:?}", duration_client_1+duration_client_2);
    println!("Time elapsed in VDDP is: {:?}", duration_VDDP1+duration_VDDP2);


    //gen public random bits
    let mut rand_bits: Vec<Vec<bool>> = Vec::new();
    for _ in 0..constants::SPLIT_LEN {
        let bits: Vec<bool> = (0..constants::BITS_NUM).map(|_| rand::random()).collect();
        rand_bits.push(bits);
    }

    //验证过程
    let start_of_VDPP = Instant::now();

    let mut shares_with_noise: Vec<ReplicaShare> = Vec::new();
    for j in 0..constants::PROVER_NUM-BAD_PROVERS{
        let share=provers[j].sum_share(&broad, &user_ids);
        let share_with_noise=provers[j].add_noise_from_rand_bits(&rand_bits, share);
        shares_with_noise.push(share_with_noise.clone());
    }

    let duration = start_of_VDPP.elapsed();
    println!("Time elapsed in VDPP is: {:?}", duration);

    let start_of_VDPV = Instant::now();

    let aggregated_com = verifier.check_all_users_and_sum_coms(&broad, &pp);
    for j in 0..constants::PROVER_NUM-BAD_PROVERS{
        let res=verifier.handle_prover_share(j,shares_with_noise[j].clone(),aggregated_com.clone(),&rand_bits, &pp);
        assert!(res);
    }
    let duration = start_of_VDPV.elapsed();
    println!("Time elapsed in VDPV is: {:?}", duration);

    let res=recon_shares(shares_with_noise);
    assert!(res.is_some());
    //println!("Result in HEX is: {}",res.unwrap().to_string());
    //println!("All tests passed!");
}
