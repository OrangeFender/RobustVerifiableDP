
pub mod public_parameters;
pub mod prover;
pub mod client;
pub mod util;
pub mod constants;
pub mod commitment;
pub mod sigma_or;
pub mod hash_xor;
pub mod msg_structs;
pub mod replicated;
pub mod sign;

pub const DST_ROBUST_DP_PUBLIC_PARAMS_GENERATION : &[u8; 41] = b"DSTofRobustDP'sPublicParametersGeneration";
pub const DST_ROBUST_DP_SIGMA_OR_GENERATION : &[u8; 37] = b"DSTofRobustDP'sSigmaORProofGeneration";
