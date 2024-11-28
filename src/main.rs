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

const NUM_CLIENTS: usize = 1000000;
const BAD_PROVERS: usize = 0;

fn main(){
    println!("Number of clients is: {}", NUM_CLIENTS);
    println!("Number of bits is: {}", constants::BITS_NUM);
    println!("Number of provers is: {}", constants::PROVER_NUM);
    println!("Number of bad provers is: {}", BAD_PROVERS);

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
    println!("Time elapsed in crate prover is: {:?}", duration_prover);
    
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

    for i in 0..NUM_CLIENTS {
        let tuple = client_prover_tuple[i][0].clone();
        let res = provers[0].handle_client(tuple, &mut broad);
        assert!(res);
    }
    let duration_VDDP1 = start_of_VDDP1.elapsed();

    println!("Time elapsed in verify com, OR and sig ACK is: {:?}", duration_VDDP1);

    for j in 1..constants::PROVER_NUM-BAD_PROVERS {
        for i in 0..NUM_CLIENTS {
            let tuple = client_prover_tuple[i][j].clone();
            let res = provers[j].handle_client(tuple, &mut broad);
            assert!(res);
        }
    }

    let start_of_VDDC2 = Instant::now();
    for i in 0..NUM_CLIENTS{
        clients[i].reveal_share(&mut broad);
    }
    let duration_client_2 = start_of_VDDC2.elapsed();
    
    let start_of_VDDP2 = Instant::now();

    let user_ids = provers[0].check_all_users(&broad); // every prover's user_ids are the same

    let duration_VDDP2 = start_of_VDDP2.elapsed();
    println!("Time elapsed in verify other's sig is: {:?}", duration_VDDP2);
    for j in 1..constants::PROVER_NUM-BAD_PROVERS{
        provers[j].check_all_users(&broad);
    }


    
    println!("Time elapsed in VDDC is: {:?}", duration_client_1+duration_client_2);
    println!("Time elapsed in VDDP is: {:?}", (duration_VDDP1+duration_VDDP2));


    //gen public random bits
    let mut rand_bits: Vec<Vec<bool>> = Vec::new();
    for _ in 0..constants::SPLIT_LEN {
        let bits: Vec<bool> = (0..constants::BITS_NUM).map(|_| rand::random()).collect();
        rand_bits.push(bits);
    }

    //验证过程

    
    let mut share_vec: Vec<ReplicaShare> = Vec::new();

    let mut shares_with_noise: Vec<ReplicaShare> = Vec::new();

    let start_of_VDPP_agg = Instant::now();
    for j in 0..constants::PROVER_NUM-BAD_PROVERS{
        let share=provers[j].sum_share(&broad, &user_ids);
        share_vec.push(share.clone());
    }
    println!("Time elapsed in summing shares is: {:?}(per prover)", start_of_VDPP_agg.elapsed()/((constants::PROVER_NUM-BAD_PROVERS)).try_into().unwrap() );

    let start_of_VDPP_bits = Instant::now();
    for j in 0..constants::PROVER_NUM-BAD_PROVERS{
        let share_with_noise=provers[j].add_noise_from_rand_bits(&rand_bits, share_vec[j].clone());
        shares_with_noise.push(share_with_noise.clone());
    }

    println!("Time elapsed in agg bits is: {:?}(per prover)", start_of_VDPP_bits.elapsed()/((constants::PROVER_NUM-BAD_PROVERS)).try_into().unwrap() );


    let start_of_verify_prover_bits = Instant::now();
    for j in 0..constants::PROVER_NUM-BAD_PROVERS{
        let prover_bits_com=provers[j].get_coms_v_k();
        let prover_bits_proof=provers[j].get_bit_proofs();
        for i in 0..constants::SHARE_LEN {
            for k in 0..constants::BITS_NUM {
                let res=prover_bits_proof[i][k].verify(&pp.get_commit_base(), prover_bits_com[i][k]);
                assert!(res);
            }
        }
    }
    println!("Time elapsed in verifying prover bits is: {:?}", start_of_verify_prover_bits.elapsed());

    let start_of_VDPV = Instant::now();

    let aggregated_com = verifier.check_all_users_and_sum_coms(&broad, &pp);

    let duration = start_of_VDPV.elapsed();

    println!("Time elapsed in VDPV agg client is: {:?}", duration);

    let start_of_VDPV_prover = Instant::now();
    for j in 0..constants::PROVER_NUM-BAD_PROVERS{
        let res=verifier.handle_prover_share(j,shares_with_noise[j].clone(),aggregated_com.clone(),&rand_bits, &pp);
        assert!(res);
    }
    let duration_prover = start_of_VDPV_prover.elapsed();
    println!("Time elapsed in VDPV agg prover is: {:?}", duration_prover);

    let start_of_recon = Instant::now();
    let res=recon_shares(shares_with_noise);
    assert!(res.is_some());
    let duration_recon = start_of_recon.elapsed();
    println!("Time elapsed in reconstructing shares is: {:?}", duration_recon);
    //println!("Result in HEX is: {}",res.unwrap().to_string());
    //println!("All tests passed!");
}
