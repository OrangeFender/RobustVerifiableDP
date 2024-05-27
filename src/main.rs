use robust_verifiable_dp::util;
use blstrs::G1Projective;


fn main() {
    let rng= &mut rand::thread_rng();
    let g1= util::random_g1_points(10, rng);
    let g1_ser=bcs::to_bytes(&g1).unwrap();
    let g1_des:Vec<G1Projective>=bcs::from_bytes(&g1_ser).unwrap();
    assert_eq!(g1,g1_des);
}
