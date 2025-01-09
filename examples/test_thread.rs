use std::thread;
use std::time::Instant;

fn main() {
    let num_threads = 3;
    let start = Instant::now();

    let mut handles = vec![];
    for _ in 0..num_threads {
        let handle = thread::spawn(|| {
            // 模拟一些工作
            let _ = 1 + 1;
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let duration = start.elapsed();
    println!("Time elapsed for creating and joining {} threads: {:?}", num_threads, duration);
}
