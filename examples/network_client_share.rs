
extern crate robust_verifiable_dp as dp;

use std::net::{TcpStream, TcpListener};
use rand::Rng;
use curve25519_dalek::scalar::Scalar;
use dp::replicated::ReplicaShare;
use dp::constants;
use std::time::Instant;
use std::env;

use std::io::prelude::*;



fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <server_ip>", args[0]);
        std::process::exit(1);
    }
    let server_ip = &args[1];
    let start = Instant::now();
    let mut stream = TcpStream::connect(server_ip).unwrap();
    let mut buffer = [0; 8 + 2 * constants::SHARE_LEN * 32]; // the share is 32 bytes long
    stream.read_exact(&mut buffer).unwrap();
    let deserialized_share = ReplicaShare::from_bytes(&buffer);
    println!("Received share");
    println!("time elapsed is: {:?}", start.elapsed());
}