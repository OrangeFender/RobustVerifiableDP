
pub mod public_parameters;
pub mod prover;
pub mod client;
pub mod verifier;
pub mod util;
pub mod constants;
pub mod commitment;
pub mod sigma_or;
pub mod hash;
pub mod msg_structs;
pub mod replicated;
pub mod sign;
pub mod datastore;
pub mod communicator;

pub const DST_ROBUST_DP_PUBLIC_PARAMS_GENERATION : &[u8; 41] = b"DSTofRobustDP'sPublicParametersGeneration";
pub const DST_ROBUST_DP_SIGMA_OR_GENERATION : &[u8; 37] = b"DSTofRobustDP'sSigmaORProofGeneration";
