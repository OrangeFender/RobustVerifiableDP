extern crate robust_verifiable_dp as dp;
use dp::prg::prg_mp;
use dp::constants;

use std::time::Instant;
fn main(){
    let start = Instant::now();
    let seed = [0u8; 16];
    let bitslen = constants::BITS_NUM*constants::SHARE_LEN;
    let result = prg_mp(&seed, bitslen);
    assert_eq!(result.len(), bitslen / 8);
    println!("Time elapsed in prg is: {:?}", start.elapsed());
}