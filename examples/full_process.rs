extern crate robust_verifiable_dp as dp;

use dp::client::Client;
use dp::public_parameters::PublicParameters;
use dp::prover::Prover;
use aptos_crypto::multi_ed25519::{MultiEd25519PublicKey, MultiEd25519Signature};
use dp::sig::{generate_ed_sig_keys};

const NUM_CLIENTS: usize = 100;
const NUM_PROVERS: usize = 10;
const THRESHOLD: usize = 5;
fn main(){
    // Create public parameters
    //生成公共参数
    let pp = PublicParameters::new(
        NUM_CLIENTS, NUM_PROVERS, THRESHOLD, b"seed"
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
    for i in 0..NUM_PROVERS {
        let prover = Prover::new(i,&pp,sig_keys[i].private_key.clone(), sig_keys[i].public_key.clone());
        provers.push(prover);
    }
    
    //二维数组，sigs[i][j]表示第i个prover对第j个client的签名
    let mut sigs: Vec<Vec<MultiEd25519Signature>> = Vec::new();
    // prover验证私人秘密
    for i in 0..NUM_PROVERS {
        let prover = &provers[i];
        for j in 0..NUM_CLIENTS {
            let client = &clients[j];
            let coms_f_x = client.get_coms_f_x();
            let (f_eval , r_eval) = client.get_evals(j);
            let ret=prover.verify_share_and_sig(&coms_f_x, &pp, f_eval, r_eval);
            //TODO
        }
    }
}