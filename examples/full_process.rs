extern crate robust_verifiable_dp as dp;

use blstrs::G1Projective;
use dp::sigma_or::{create_proof_0, create_proof_1, ProofScalar};
use dp::transcript::{self, verify_transcript, TranscriptEd};
use dp::{client::Client, sig};
use dp::public_parameters::PublicParameters;
use dp::prover::Prover;
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

    // // 对于通过验证的Clients, 生成simga_or proof
    // let mut create_proofs: Vec<ProofScalar> = Vec::new();
    // for i in 0..NUM_CLIENTS {
    //     let client = &clients[i];
    //     let mut create_proof;
    //     // 这里应该能改成pub吧，因为在实际实现的时候这个地方是由Client自己去调用自己的x_int.
    //     if client.x_int == 0 {
    //         create_proof = create_proof_0(&pp.get_commit_base(), &client.x_scalar, &client.r_poly);
    //     }
    //     else {
    //         create_proof = create_proof_1(&pp.get_commit_base(), &client.x_scalar, &client.r_poly);
    //     }
    //     create_proofs.push(create_proof);
    // }

    // // 对于Provers来说, 需要首先重构出ci
    // // 我觉着需要一个公开变量来存储所有的commit，不能都让commit在clients的transcript中，第一步就应该广播
    // let mut com_recons: Vec<G1Projective> = Vec::new();

    // // Provers重构出ci之后, 所有的prover对ci做验证
    // for i in 0..NUM_CLIENTS {

    // }

    //产生DP证明
    

}
