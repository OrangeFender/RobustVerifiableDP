
extern crate robust_verifiable_dp as dp;

use std::net::{TcpStream, TcpListener};
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
    let mut buffer = vec![0; 32*262144]; // Assuming the share is 32 bytes long
    stream.read_exact(&mut buffer).unwrap();
    println!("Received share");
    println!("time elapsed is: {:?}", start.elapsed());
}