
use num_traits::abs;
use rand::Rng;

const SHARE_SPLIT: [usize; 3] = [3, 5, 10];
const TEST_TIME: [usize; 1]=[100];
const NB:[u64;8]=[1<<10,1<<12,1<<14,1<<16,1<<18,1<<20,1<<22,1<<24];



fn test_rand(split:usize, test_time:usize, nb:u64){
    
    let mut sum=0;
    for _ in 0..test_time{
        let mut ct=0;

        let mut boolvec=Vec::new();

        for _ in 0..(nb as usize)*split {
            let x: bool = rand::rngs::OsRng.gen();
            boolvec.push(x);
        }
        for i in 0..(nb as usize)*split {
            let b:bool=rand::rngs::OsRng.gen();
            if boolvec[i]^b {
            ct+=1;
            }
        }
        let dif=abs(ct as isize - nb as isize * split as isize / 2);
        sum+=dif;
    }
    println!("Split is: {}, Test time is: {}, Nb is: {}, Difference is: {}", split, test_time, nb, sum as f64 / test_time as f64);
}

fn main(){
    use rayon::prelude::*;

    NB.par_iter().for_each(|nb| {
        SHARE_SPLIT.par_iter().for_each(|i| {
            TEST_TIME.par_iter().for_each(|j| {
                test_rand(*i, *j, *nb);
            });
        });
    });
}