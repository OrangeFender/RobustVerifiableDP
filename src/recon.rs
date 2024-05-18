use std::ops::Mul;

use blstrs::{G1Projective, Scalar};
use ff::Field;
use crate::commitment::CommitBase;
use crate::{evaluation_domain::BatchEvaluationDomain, lagrange::lagrange_coefficients_at_zero};

// 第7步重构
// 调用m次来恢复f_1(0),...,f_m(0)，n是Client的个数
// players 表示所需重构的prover的个数，share_f和share_r对应其拥有的秘密份额
pub fn reconstruct_com(ct_coms: &Vec<G1Projective>, share_f: &Vec<Scalar>, share_r: &Vec<Scalar>, players: &Vec<usize>, n:usize, commit_base: &CommitBase) -> (Scalar, Scalar) {
    let batch_dom = BatchEvaluationDomain::new(n);
    let lagr = lagrange_coefficients_at_zero(&batch_dom, players.as_slice());

    let mut s = Scalar::zero();
    let mut r = Scalar::zero();

    // 转化为所需类型的格式
    let mut shares: Vec<[Scalar; 2]> = share_f
    .iter()
    .zip(share_r)
    .map(|(a, b)| [a.clone(), b.clone()])
    .collect();

    let t = shares.len();
    for i in 0..t {
        let com = G1Projective::multi_exp(commit_base.bases.as_slice(), shares[i].as_slice().clone());
        assert!(ct_coms[players[i]].eq(&com));

        s += lagr[i].mul(shares[i][0]);
        r += lagr[i].mul(shares[i][1]);
    }

    (s, r)
}

// 最后一步重构
// players 表示所需重构的prover的个数
pub fn reconstruct_y(ct_coms: &Vec<G1Projective>, y_k: &Vec<Scalar>, players: &Vec<usize>, n:usize, commit_base: &CommitBase) -> Scalar {
    let batch_dom = BatchEvaluationDomain::new(n);
    let lagr = lagrange_coefficients_at_zero(&batch_dom, players.as_slice());

    let mut Y = Scalar::zero();

    let t = y_k.len();
    for i in 0..t {
        Y += lagr[i].mul(y_k[i]);
    }

    Y
}