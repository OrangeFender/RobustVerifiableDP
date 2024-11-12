pub const BITS_NUM:usize = 1000;
pub const PROVER_NUM:usize = 5;
pub const THRESHOLD:usize = 2;
pub const SHARE_LEN:usize = 6;
pub const SPLIT_LEN:usize = 10;
pub const IND_ARR: [[usize; 6];5] = [
    [0, 1, 2, 3, 4, 5],//1,2,3,4,5,6
    [0, 1, 2, 6, 7, 8],//1,2,3,7,8,9
    [0, 3, 4, 6, 7, 9],//1,4,5,7,8,10
    [1, 3, 5, 6, 8, 9],//2,4,6,7,9,10
    [2, 4, 5, 7, 8, 9],//3,5,6,8,9,10
];

