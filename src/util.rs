use curve25519_dalek::scalar::Scalar;
use num_traits::ops::bytes;


pub fn random_scalar(rng: &mut impl rand::Rng)->Scalar{
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    Scalar::from_bytes_mod_order(bytes[..32].try_into().unwrap())
}

pub fn random_scalars(num:usize, rng: &mut impl rand::Rng)->Vec<Scalar>{
    let mut scalars=Vec::new();
    for _ in 0..num {
        scalars.push(random_scalar(rng));
    }
    scalars
}

pub fn scalar_one()->Scalar{
    Scalar::from(1u64)
}

pub fn scalar_zero()->Scalar{
    Scalar::from(0u64)
}