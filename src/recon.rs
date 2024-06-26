use std::ops::Mul;

use blstrs::{G1Projective, Scalar};
use ff::Field;
use crate::{evaluation_domain::BatchEvaluationDomain, lagrange::lagrange_coefficients_at_zero};

// 第7步重构
// 调用m次来恢复f_1(0),...,f_m(0)，n是Client的个数
// players 表示所需重构的prover的个数，share_f和share_r对应其拥有的秘密份额
// pub fn reconstruct_com(ct_coms: &Vec<G1Projective>, share_f: &Vec<Scalar>, share_r: &Vec<Scalar>, players: &Vec<usize>, n:usize, commit_base: &CommitBase) -> (Scalar, Scalar) {
//     let batch_dom = BatchEvaluationDomain::new(n);
//     let lagr = lagrange_coefficients_at_zero(&batch_dom, players.as_slice());

//     let mut s = Scalar::zero();
//     let mut r = Scalar::zero();

//     // 转化为所需类型的格式
//     let mut shares: Vec<[Scalar; 2]> = share_f
//     .iter()
//     .zip(share_r)
//     .map(|(a, b)| [a.clone(), b.clone()])
//     .collect();

//     let t = shares.len();
//     for i in 0..t {
//         let com = G1Projective::multi_exp(commit_base.bases.as_slice(), shares[i].as_slice().clone());
//         assert!(ct_coms[players[i]].eq(&com));

//         s += lagr[i].mul(shares[i][0]);
//         r += lagr[i].mul(shares[i][1]);
//     }

//     (s, r)
// }

// 最后一步重构
// players 表示所需重构的prover的个数，即多项式的次数deg+1
// n表示prover的个数
pub fn reconstruct_y(y_k: &Vec<Scalar>, players: &Vec<usize>, n:usize) -> Scalar {
    let batch_dom = BatchEvaluationDomain::new(n);
    let lagr = lagrange_coefficients_at_zero(&batch_dom, players.as_slice());

    let mut y = Scalar::zero();

    let t = y_k.len();
    for i in 0..t {
        y += lagr[i].mul(y_k[i]);
    }
    
    y

}

// 调用m次来恢复f_1(0),...,f_m(0)，n是Client的个数
// players 表示所需重构的prover的个数，share_f和share_r对应其拥有的秘密份额
// prover 重构出请求的第i个Client的commitment
pub fn reconstruct_com(ct_com: &Vec<G1Projective>, n:usize) -> G1Projective {
    let batch_dom = BatchEvaluationDomain::new(n+1);
    let vec: Vec<_> = (1..=n).collect();
    let lagr = lagrange_coefficients_at_zero(&batch_dom, vec.as_slice());

    // let com_i = ct_com[0];

    // let t = ct_com.len();
    // for i in 1..t {
    //     com_i = &ct_com[i];
    //     com_i = G1Projective::multi_exp(com_i, lagr[i]);
    // }
    // let com_arr: [G1Projective; t] = ct_com.try_into().unwrap();
    // 两个数组对应元素相乘再相加，即c_i=\sum_k[c_i(k)*L_k(0)]
    let mut com0=ct_com[0].mul(lagr[0]);
    
    for i in 1..n {
        com0 = com0+&ct_com[i].mul(lagr[i]);
    }

    com0
}

#[cfg(test)]
mod tests {
    use crate::fft::fft;
    use std::ops::Mul;
    use blstrs::{G1Projective, Scalar};
    use group::Group;
    use ff::Field;
    use crate::util;
    use crate::{evaluation_domain::BatchEvaluationDomain, lagrange::lagrange_coefficients_at_zero};
    #[test]
    fn test_reconstruct() {
        let t=3;
        let n=10;
        let mut rng = rand::thread_rng();
        let r_poly = util::random_scalars(t, &mut rng);
        //let f_poly = util::random_scalars(t, &mut rng);
        let f_poly = vec![Scalar::from(1u64), Scalar::from(2u64), Scalar::from(3u64)];
        let g=G1Projective::generator();
        let h = G1Projective::hash_to_curve(b"seed", b"DST_ROBUST_DP_PUBLIC_PARAMS_GENERATION", b"h");

        let batchdom=BatchEvaluationDomain::new(n);
        let dom=batchdom.get_subdomain(n);
        let mut f_evals = fft(&f_poly, &dom);
        f_evals.truncate(n);
        let mut r_evals = fft(&r_poly, &dom);
        r_evals.truncate(n);
        //evals都是从1开始的
        assert_eq!(Scalar::from(6u64),f_poly[0]);

        

        let mut coms_f_x = Vec::new();
        for i in 0..n{
            coms_f_x.push(G1Projective::multi_exp(&[g,h], &[f_evals[i], r_evals[i]]));
        }
        let players: Vec<usize> = (1..=t).collect();
        let com0 = super::reconstruct_com(&coms_f_x, t);
        let f0 = super::reconstruct_y(&f_evals, &players, t);
        assert_eq!(f0,f_poly[0]);
        let r0 = super::reconstruct_y(&r_evals, &players, t);
        assert_eq!(r0,r_poly[0]);
        let com1 = G1Projective::multi_exp(&[g,h], &[super::reconstruct_y(&f_evals, &players, t), super::reconstruct_y(&r_evals, &players, t)]);
        assert_eq!(com0, com1);
    }
}