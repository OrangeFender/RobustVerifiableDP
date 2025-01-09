
extern crate robust_verifiable_dp as dp;

use std::net::{TcpListener, TcpStream};
use std::io::Write;



fn main() {

    let listener = TcpListener::bind("0.0.0.0:7878").unwrap();
    println!("Server listening on port 7878");

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let bytes = vec![7u8; 32*2*262144];

                stream.write_all(&bytes).unwrap();
            }
            Err(e) => {
                eprintln!("Connection failed: {}", e);
            }
        }
    }

    
}