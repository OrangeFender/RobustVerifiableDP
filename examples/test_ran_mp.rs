use robust_verifiable_dp::constants;
use rand::Rng;
use std::sync::{Arc, Mutex};
use std::thread;

const SHARE_SPLIT: [usize; 5] = [1, 2, 4, 8, 16];
const TEST_TIME:usize=1000;


fn test_rand(split:usize){
    println!("Split is: {}", split);
    let mut ct=0;
    let mut boolvec: Vec<bool> = Vec::new();
    let boolvec = Arc::new(Mutex::new(Vec::new()));
    let mut handles = vec![];

    for _ in 0..TEST_TIME {
        let boolvec = Arc::clone(&boolvec);
        let handle = thread::spawn(move || {
            let mut local_boolvec = vec![];
            for _ in 0..constants::BITS_NUM * split {
                let x: bool = rand::rngs::OsRng.gen();
                local_boolvec.push(x);
            }
            let mut boolvec = boolvec.lock().unwrap();
            boolvec.extend(local_boolvec);
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let mut ct = 0;
    let boolvec = Arc::try_unwrap(boolvec).unwrap().into_inner().unwrap();

    let mut handles = vec![];
    let ct_arc = Arc::new(Mutex::new(0));

    for chunk in boolvec.chunks(constants::BITS_NUM * split) {
        let ct_arc = Arc::clone(&ct_arc);
        let chunk = chunk.to_vec();
        let handle = thread::spawn(move || {
            let mut local_ct = 0;
            for b in chunk {
                let rand_b: bool = rand::rngs::OsRng.gen();
                if b ^ rand_b {
                    local_ct += 1;
                }
            }
            let mut ct = ct_arc.lock().unwrap();
            *ct += local_ct;
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    ct = *ct_arc.lock().unwrap();
    let num=ct as f64 / TEST_TIME as f64;
    println!("Number is: {:.2}", num);
    let e=constants::BITS_NUM*split/2;
    println!("Expected number is: {}", e);
    println!("Difference is: {}", num-e as f64);
}

fn main(){
    for i in SHARE_SPLIT.iter(){
        test_rand(*i);
    }
}