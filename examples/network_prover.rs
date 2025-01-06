
extern crate robust_verifiable_dp as dp;

use dp::constants;
use dp::sign;
use dp::replicated::ReplicaSecret;
use std::time::Instant;
use dp::util::{random_scalars, scalar_one, scalar_zero};
use curve25519_dalek::Scalar;
use std::net::{TcpListener, TcpStream};
use std::io::Write;


const NUM_CLIENTS: usize = 1000000;
const BAD_PROVERS: usize = 0;

fn main() {
    

    let x: bool = rand::random();
    let x_scalar = Scalar::from(x as u64);
    let secret=ReplicaSecret::new(x_scalar.clone());
    let share=(secret.get_share(0));
        


    let listener = TcpListener::bind("0.0.0.0:7878").unwrap();
    println!("Server listening on port 7878");

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let share=(secret.get_share(0));
        
                let bytes = share.to_bytes();

                stream.write_all(&bytes).unwrap();
            }
            Err(e) => {
                eprintln!("Connection failed: {}", e);
            }
        }
    }

    
}