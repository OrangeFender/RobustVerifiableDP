extern crate robust_verifiable_dp as dp;

use dp::util::{random_scalars, scalar_zero};

use std::time::Instant;

fn main(){
    let scalars = random_scalars(3, &mut rand::thread_rng());
    let start = Instant::now();
    let mut sum = scalar_zero();
    for i in 0..scalars.len() {
        sum += scalars[i];
    }
    println!("Time elapsed in summing scalars is: {:?}", start.elapsed());

}