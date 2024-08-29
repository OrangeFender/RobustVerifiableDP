use std::hash::{Hash, Hasher};

pub fn hash_bit_vec<T: Hash>(item: &T, length: usize) -> Vec<bool> {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    item.hash(&mut hasher);
    let hash_value = hasher.finish();

    let mut bit_vec = Vec::new();
    let mut current_bit = 0;

    while current_bit < length {
        bit_vec.push((hash_value >> current_bit) & 1 == 1);
        current_bit += 1;
    }

    bit_vec
}