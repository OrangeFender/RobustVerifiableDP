use aes::{cipher, Aes128};
use aes::cipher::{
    BlockCipher, BlockEncrypt, BlockDecrypt, KeyInit,
    generic_array::GenericArray,
};
use num_traits::ops::bytes;

use rayon::prelude::*;

fn expand(seed:&[u8;16])->([u8;16],[u8;16]){
    let key = GenericArray::from_slice(seed);
    let cipher = Aes128::new(&key);

    let mut block0 = GenericArray::from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

    let mut block1 = GenericArray::from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

    cipher.encrypt_block(&mut block0);
    cipher.encrypt_block(&mut block1);

    (block0.as_slice().try_into().unwrap(),block1.as_slice().try_into().unwrap())
}

pub fn prg(seed:&[u8;16],bitslen:usize)->Vec<u8>{
    let blocklen = (bitslen+127)/128;
    let byteslen = (bitslen+7)/8;
    let mut tempvec: Vec<[u8; 16]> = vec![seed.clone()];
    while tempvec.len()<blocklen{
        let mut newtempvec = Vec::new();
        for i in 0..tempvec.len(){
            let (block0,block1) = expand(&tempvec[i]);
            if newtempvec.len()<blocklen{
                newtempvec.push(block0);
            }
            if newtempvec.len()<blocklen{
                newtempvec.push(block1);
            }
        }
        tempvec = newtempvec;
    }
    tempvec
.iter()
.flat_map(|&block| block.iter().copied().collect::<Vec<_>>())
.take(byteslen)
.collect()
}

pub fn prg_mp(seed:&[u8;16],bitslen:usize)->Vec<u8>{
    let blocklen = (bitslen+127)/128;
    let byteslen = (bitslen+7)/8;
    let mut tempvec: Vec<[u8; 16]> = vec![seed.clone()];
    while tempvec.len() < blocklen {
        let chunk_size = if tempvec.len() > 1000 { tempvec.len() / 4 } else { tempvec.len() };
        let newtempvec: Vec<[u8; 16]> = tempvec
            .par_chunks(chunk_size)
            .flat_map(|chunk| {
                chunk.iter().flat_map(|block| {
                    let (block0, block1) = expand(block);
                    vec![block0, block1]
                }).collect::<Vec<_>>()
            })
            .collect::<Vec<_>>()
            .into_iter()
            .take(blocklen)
            .collect();
        tempvec = newtempvec;
    }
    tempvec
.iter()
.flat_map(|&block| block.iter().copied().collect::<Vec<_>>())
.take(byteslen)
.collect()
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prg() {
        let seed = [0u8; 16];
        let bitslen = 256*6;
        let result = prg(&seed, bitslen);
        assert_eq!(result.len(), bitslen / 8);
    }

    #[test]
    fn test_prg_mp() {
        let seed = [0u8; 16];
        let bitslen = 256*6;
        let result = prg_mp(&seed, bitslen);
        assert_eq!(result.len(), bitslen / 8);
    }

    #[test]
    fn test_prg_and_prg_mp_consistency() {
        let seed = [0u8; 16];
        let bitslen = 256*6;
        let result_prg = prg(&seed, bitslen);
        let result_prg_mp = prg_mp(&seed, bitslen);
        assert_eq!(result_prg, result_prg_mp);
    }

    #[test]
    fn test_prg_different_seed() {
        let seed1 = [0u8; 16];
        let seed2 = [1u8; 16];
        let bitslen = 256*6;
        let result1 = prg(&seed1, bitslen);
        let result2 = prg(&seed2, bitslen);
        assert_ne!(result1, result2);
    }

    #[test]
    fn test_prg_mp_different_seed() {
        let seed1 = [0u8; 16];
        let seed2 = [1u8; 16];
        let bitslen = 256*6;
        let result1 = prg_mp(&seed1, bitslen);
        let result2 = prg_mp(&seed2, bitslen);
        assert_ne!(result1, result2);
    }
}
