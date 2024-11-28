use robust_verifiable_dp::constants;
use rand::Rng;

const SHARE_SPLIT: usize = 3;
const TEST_TIME:usize=500;

fn main(){
    let mut ct=0;
    let mut boolvec=Vec::new();

    for _ in 0..TEST_TIME{
        for _ in 0..constants::BITS_NUM*SHARE_SPLIT {
            let x: bool = rand::rngs::OsRng.gen();
            boolvec.push(x);
        }
    }
    for i in 0..constants::BITS_NUM*SHARE_SPLIT*TEST_TIME {
        let b:bool=rand::rngs::OsRng.gen();
        if boolvec[i]^b {
            ct+=1;
        }
    }

    let num=ct as f64 / TEST_TIME as f64;
    println!("Number is: {:.2}", num);
    let e=constants::BITS_NUM*SHARE_SPLIT/2;
    println!("Expected number is: {}", e);
    println!("Difference is: {}", num-e as f64);
}