pub const BITS_NUM:usize = 262144;


//===============m=5, t=2 ==================
// pub const PROVER_NUM:usize = 5;
// pub const THRESHOLD:usize = 2;
// pub const SHARE_LEN:usize = 6;
// pub const SPLIT_LEN:usize = 10;
// pub const IND_ARR: [[usize; 6];5] = [
//     [0, 1, 2, 3, 4, 5],//1,2,3,4,5,6
//     [0, 1, 2, 6, 7, 8],//1,2,3,7,8,9
//     [0, 3, 4, 6, 7, 9],//1,4,5,7,8,10
//     [1, 3, 5, 6, 8, 9],//2,4,6,7,9,10
//     [2, 4, 5, 7, 8, 9],//3,5,6,8,9,10
// ];



//===============m=5, t=4 ==================
pub const PROVER_NUM:usize = 5;
pub const THRESHOLD:usize = 4;
pub const SHARE_LEN:usize = 1;
pub const SPLIT_LEN:usize = 5;
pub const IND_ARR: [[usize; 1];5] = [
    [0],//1
    [1],//2
    [2],//3
    [3],//4
    [4],//5
];

//===============m=3, t=1 ==================
// //pub const BITS_NUM:usize = 100;
// pub const PROVER_NUM:usize = 3;
// pub const THRESHOLD:usize = 1;
// pub const SHARE_LEN:usize = 2;
// pub const SPLIT_LEN:usize = 3;
// pub const IND_ARR: [[usize; 2];3] = [
//     [0, 1],//1,2
//     [0, 2],//1,3
//     [1, 2],//2,3
// ];

// //===============m=3, t=2 ==================
// pub const PROVER_NUM:usize = 3;
// pub const THRESHOLD:usize = 2;
// pub const SHARE_LEN:usize = 1;
// pub const SPLIT_LEN:usize = 3;
// pub const IND_ARR: [[usize; 1];3] = [
//     [0],//1,2
//     [1],//1,3
//     [2],//2,3
// ];