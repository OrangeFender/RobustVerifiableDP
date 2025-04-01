use rustc_hash::FxHashSet;
use std::collections::BTreeSet;

use rand::seq::SliceRandom;
use rand::thread_rng;


fn test_all_in(length:usize){
    let mut set = FxHashSet::default();
    while set.len() < length {
        set.insert(rand::random::<u64>());
    }
    let mut unique_array: Vec<u64> = set.into_iter().collect();
    println!("Generated array of length: {}", unique_array.len());
    
    let mut H= FxHashSet::default();
    let start= std::time::Instant::now();
    for num in unique_array.iter() {
        H.insert(num);
        }
    println!("Time taken to create set: {:?}", start.elapsed());

    let mut rng = thread_rng();
    let mut more_number=unique_array.clone();
    more_number.shuffle(&mut rng);
    let start = std::time::Instant::now();
    let mut counter: i32 = 0;
    for number in more_number.iter() {
        if H.contains(number) {
            counter += 1;
        }
    }
    println!("Time taken to check numbers: {:?}", start.elapsed());
    println!("Count of numbers in both sets: {}", counter);

}

fn test_all_in_bt(length:usize){
    let mut set = FxHashSet::default();
    while set.len() < length {
        set.insert(rand::random::<u64>());
    }
    let mut unique_array: Vec<u64> = set.into_iter().collect();
    println!("Generated array of length: {}", unique_array.len());
    
    let mut H= BTreeSet::default();
    let start= std::time::Instant::now();
    for num in unique_array.iter() {
        H.insert(num);
        }
    println!("Time taken to create set: {:?}", start.elapsed());

    let mut rng = thread_rng();
    let mut more_number=unique_array.clone();
    more_number.shuffle(&mut rng);
    let start = std::time::Instant::now();
    let mut counter: i32 = 0;
    for number in more_number.iter() {
        if H.contains(number) {
            counter += 1;
        }
    }
    println!("Time taken to check numbers: {:?}", start.elapsed());
    println!("Count of numbers in both sets: {}", counter);

}


fn test_all_not_in(length:usize){
    let mut set = FxHashSet::default();
    while set.len() < length*2 {
        set.insert(rand::random::<u64>());
    }
    let mut unique_array: Vec<u64> = set.into_iter().collect();
    let (mut fisrt_half, mut second_half) = unique_array.split_at(length);
    println!("Length of first half: {}", fisrt_half.len());
    println!("Length of second half: {}", second_half.len());

    let mut H= FxHashSet::default();
    let start= std::time::Instant::now();
    for num in fisrt_half.iter() {
        H.insert(num);
        }
    println!("Time taken to create set: {:?}", start.elapsed());
    let mut rng = thread_rng();
    let mut more_number=second_half.to_vec();
    more_number.shuffle(&mut rng);
    let start = std::time::Instant::now();
    let mut counter: i32 = 0;
    for number in more_number.iter() {
        if H.contains(number) {
            counter += 1;
        }
    }
    println!("Time taken to check numbers: {:?}", start.elapsed());
    println!("Count of numbers in both sets: {}", counter);
}


fn test_all_not_in_bt(length:usize){
    let mut set = FxHashSet::default();
    while set.len() < length*2 {
        set.insert(rand::random::<u64>());
    }
    let mut unique_array: Vec<u64> = set.into_iter().collect();
    let (mut fisrt_half, mut second_half) = unique_array.split_at(length);
    println!("Length of first half: {}", fisrt_half.len());
    println!("Length of second half: {}", second_half.len());

    let mut H= BTreeSet::default();
    let start= std::time::Instant::now();
    for num in fisrt_half.iter() {
        H.insert(num);
        }
    println!("Time taken to create set: {:?}", start.elapsed());
    let mut rng = thread_rng();
    let mut more_number=second_half.to_vec();
    more_number.shuffle(&mut rng);
    let start = std::time::Instant::now();
    let mut counter: i32 = 0;
    for number in more_number.iter() {
        if H.contains(number) {
            counter += 1;
        }
    }
    println!("Time taken to check numbers: {:?}", start.elapsed());
    println!("Count of numbers in both sets: {}", counter);
}

fn test_vector(length:usize){
    let mut set = FxHashSet::default();
    while set.len() < length {
        set.insert(rand::random::<u64>());
    }
    let mut unique_array: Vec<u64> = set.into_iter().collect();
    println!("Generated array of length: {}", unique_array.len());
    
    let RandomNumber:u64= rand::random::<u64>();
    let start = std::time::Instant::now();
    let mut counter: i32 = 0;
    for number in unique_array.iter() {
        if number == &RandomNumber {
            counter += 1;
        }
    }
    println!("Time taken to check number: {:?}", start.elapsed());
    println!("Count of number in vector: {}", counter);
}


fn main(){
    for _i in 0..3{
    println!("--------test of hash set---------");
    
    test_all_in(1_000_000);
    test_all_not_in(1_000_000);

    println!("--------test of btree set---------");

    test_all_in_bt(1_000_000);
    test_all_not_in_bt(1_000_000);

    println!("--------test of vector---------");
    test_vector(1_000_000);
}
}