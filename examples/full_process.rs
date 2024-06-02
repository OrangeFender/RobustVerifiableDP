extern crate robust_verifiable_dp as dp;

use blstrs::{G1Projective,Scalar};
use dp::sigma_or::ProofStruct;
use dp::transcript::{self, verify_transcript, TranscriptEd};
use dp::{client::Client, sig};
use dp::public_parameters::PublicParameters;
use dp::prover::Prover;
use dp::recon::reconstruct_com;
use dp::sigma_or::{sigma_or_verify};
use dp::hash_xor::{hash_to_bit_array,xor_commitments};
use dp::commitment::Commit;
use dp::msg_structs::ComsAndShare;

use aptos_crypto::{ed25519::Signature, multi_ed25519::{MultiEd25519PublicKey, MultiEd25519Signature}};
use dp::sig::{generate_ed_sig_keys};
use aptos_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature};
use rand::Rng;


const N_B: usize = 10;
const NUM_CLIENTS: usize = 15;
const NUM_PROVERS: usize = 10;
const THRESHOLD: usize = 4;
fn main(){
    // Create public parameters
    //生成公共参数
    let pp = PublicParameters::new(
        N_B, NUM_PROVERS, THRESHOLD, b"seed"
        );


    // Create clients
    //生成客户端
    let mut clients: Vec<Client> = Vec::new();
    for i in 0..NUM_CLIENTS {
        let random_bool = rand::random();
        let client = Client::new(i,random_bool, &pp);
        clients.push(client);
    }

    //----------------新测试的内容----------------
    let mut clientmsg: Vec<Vec<ComsAndShare>> = Vec::new();
    for i in 0..NUM_CLIENTS {
        let mut msgs:Vec<ComsAndShare>=Vec::new();
        for proverind in 0..NUM_PROVERS {
            msgs.push(clients[i].create_prover_msg(&pp, proverind));
        }
        clientmsg.push(msgs);
    }
    //--------------------------------

    // Create provers
    //生成服务器
    let mut provers: Vec<Prover> = Vec::new();
    let sig_keys = generate_ed_sig_keys(NUM_PROVERS);
    let mut pks: Vec<Ed25519PublicKey> = Vec::new();
    for i in 0..NUM_PROVERS {
        let prover = Prover::new(i,&pp,sig_keys[i].private_key.clone(), sig_keys[i].public_key.clone());
        provers.push(prover);
        pks.push(sig_keys[i].public_key.clone());
    }
    
    //----------------新测试的内容----------------
    for i in 0..NUM_CLIENTS {
        for j in 0..NUM_PROVERS {
            let msg = &clientmsg[i][j];
            let ret=provers[j].verify_share_and_sig(&msg.coms, &pp, msg.share, msg.pi);
            assert!(ret.is_some());
        }
    }

    //-----------------------------------------

    //二维数组，sigs[i][j]表示第i个prover对第j个client的签名
    // prover验证私人秘密
    let mut sigs_client_prover: Vec<Vec<Option<Ed25519Signature>>> = vec![vec![None; NUM_PROVERS]; NUM_CLIENTS];

    for i in 0..NUM_PROVERS {
        let prover = &provers[i];
        for j in 0..NUM_CLIENTS {
            let client = &clients[j];
            let coms_f_x = client.get_coms_f_x();
            let (f_eval , r_eval) = client.get_evals(i);
            let ret=prover.verify_share_and_sig(&coms_f_x, &pp, f_eval, r_eval);
            assert!(ret.is_some());
            sigs_client_prover[j][i] = ret;
        }
    }

    let bytes= bcs::to_bytes(&sigs_client_prover.clone()).unwrap();
    //打印消息的长度
    println!("{}*{} sigs length:{}",NUM_CLIENTS,NUM_PROVERS,bytes.len());

    //客户端验证签名
    for i in 0..NUM_PROVERS {
        let pk= sig_keys[i].public_key.clone();
        for j in 0..NUM_CLIENTS {
            let client = &clients[j];
            let sig = sigs_client_prover[j][i].clone().unwrap();            
            let valid = client.vrfy_sig( &pk, &sig);
            assert!(valid);
        }
    }

    //随机使prover损坏
    let mut valid_sigs: Vec<Vec<bool>> = vec![vec![true; NUM_PROVERS]; NUM_CLIENTS];
    //至多使3个prover损坏,只破坏一半client对应的签名，后半段是完好的
    for _ in 0..3 {
        let mut rng = rand::thread_rng();
        let index = rng.gen_range(0, NUM_PROVERS);
        for j in 0..(NUM_CLIENTS/2) {
            valid_sigs[j][index] = false;  // 这两个不对应吗就是？
            sigs_client_prover[j][index] = None;
        }
    }
    //纰漏秘密，聚合签名生成transcript
    let mut transcripts: Vec<TranscriptEd> = Vec::new();
    for i in 0..NUM_CLIENTS {
        let client = &clients[i];
        let mut sigs = Vec::new();
        for j in 0..NUM_PROVERS {
            if valid_sigs[i][j] {
                sigs.push(sigs_client_prover[i][j].clone().unwrap());
            }
        }
        let transcript = client.get_transcript(NUM_PROVERS, &valid_sigs[i], sigs);
        transcripts.push(transcript);
    }

    //验证transcript
    for i in 0..NUM_CLIENTS {
        let client = &clients[i];
        let transcript = &transcripts[i];
        let valid = verify_transcript(&client.get_coms_f_x(), transcript, &pp, &pks);
        assert!(valid);  
    }

    //测试序列化后的transcript------------------------------------
    let bytes= bcs::to_bytes(&transcripts.clone()).unwrap();
    println!("{}transcripts length:{}",NUM_CLIENTS,bytes.len());
    //----------------------------------------------------------
    
     // 对于通过验证的Clients, 生成simga_or proof
     let mut create_proofs: Vec<ProofStruct> = Vec::new();
     for i in 0..NUM_CLIENTS {
         let client = &clients[i];
         let create_proof = client.create_sigma_proof(&pp);
         create_proofs.push(create_proof);
     }
 
     // 对于每个Provers来说, 需要首先重构出ci
     let mut com_recons: Vec<G1Projective> = Vec::new();
     // 通过验证后直接选取Prover的前t+1个commit重构，因为已经验证过Client秘密分享的安全性了
     let players: Vec<usize> = (0..NUM_PROVERS)
     .take(THRESHOLD)
     .collect::<Vec<usize>>();
 
     for i in 0..NUM_CLIENTS {
         let com_recon = reconstruct_com(&clients[i].get_coms_f_x(),  NUM_PROVERS);
         com_recons.push(com_recon);
     }
     
     // Provers重构出ci之后, 所有的prover对ci做验证
     // let mut vrfy_recon_com: Vec<bool> = Vec::new();
     // Provers在验证的时候，commit需要利用自己重构出的commit来验证
    for i in 0..NUM_CLIENTS {
            let valid = sigma_or_verify(&pp.get_commit_base(), &create_proofs[i], com_recons[i].clone());
            assert!(valid);
            for j in 0..NUM_PROVERS {
                let (f,r)=clients[i].get_evals(j);
                provers[j].input_shares(f,r);
            }
    }

    //计算哈希值
    let mut all_commitments: Vec<Vec<G1Projective>> = Vec::new();
    for i in 0..NUM_PROVERS {
        let coms = provers[i].get_coms_v_k();
        all_commitments.push(coms);
    }
    let hash = hash_to_bit_array(&all_commitments,pp.get_n_b());


    // prover给出最后结果的share
    let mut res_shares: Vec<Scalar> = Vec::new();
    let mut res_proof: Vec<Scalar> = Vec::new();
    for i in 0..NUM_PROVERS{
        provers[i].x_or(&pp,&hash);
        let (y,proof) = provers[i].calc_output(&pp);
        res_shares.push(y);
        res_proof.push(proof);

        //verifier最后的验证
        let noise_commitment = xor_commitments(&provers[i].get_coms_v_k(), &hash,pp.get_g(), pp.get_h());
        let mut last_commitment = noise_commitment[0];
        for j in 1..pp.get_n_b() {
            last_commitment = last_commitment + noise_commitment[j];
        }
        for j in 0..NUM_CLIENTS {
            last_commitment = last_commitment + clients[j].get_coms_f_x()[i];
        }
        assert!(last_commitment == pp.get_commit_base().commit(y,proof));
    }

    println!("All tests passed!");
}
