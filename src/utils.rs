use polynomial_ring::Polynomial;
use rand_distr::{Uniform, Distribution};
use rand::SeedableRng;
use rand::rngs::StdRng;
use ring_lwe::utils::{polyadd, polymul_fast, gen_uniform_poly,nearest_int};
use ntt::omega;
use base64::{engine::general_purpose, Engine as _};
use bincode;

#[derive(Debug)]
/// Default parameters for module-LWE
pub struct Parameters {
    /// Degree of the polynomials
    pub n: usize,
    /// Ciphertext modulus
    pub q: i64,
    /// Module rank	
    pub k: usize,
    /// 2n-th root of unity	
    pub omega: i64,
    /// Polynomial modulus
    pub f: Polynomial<i64>,
}

impl Default for Parameters {
    fn default() -> Self {
        let n = 512;
        let q = 12289;
        let k = 8;
        let omega = omega(q, 2 * n);
        let mut poly_vec = vec![0i64; n + 1];
        poly_vec[0] = 1;
        poly_vec[n] = 1;
        let f = Polynomial::new(poly_vec);
        Parameters { n, q, k, omega, f }
    }
}

pub fn add_vec(v0: &Vec<Polynomial<i64>>, v1: &Vec<Polynomial<i64>>, modulus: i64, poly_mod: &Polynomial<i64>) -> Vec<Polynomial<i64>> {
    assert_eq!(v0.len(), v1.len());
    v0.iter()
        .zip(v1.iter())
        .map(|(a, b)| polyadd(a, b, modulus, poly_mod))
        .collect()
}

pub fn mul_vec_simple(v0: &Vec<Polynomial<i64>>, v1: &Vec<Polynomial<i64>>, modulus: i64, poly_mod: &Polynomial<i64>, omega: i64) -> Polynomial<i64> {
    assert_eq!(v0.len(), v1.len());
    v0.iter()
        .zip(v1.iter())
        .map(|(a, b)| polymul_fast(a, b, modulus, poly_mod, omega))
        .fold(Polynomial::new(vec![]), |acc, p| polyadd(&acc, &p, modulus, poly_mod))
}

pub fn mul_mat_vec_simple(m: &Vec<Vec<Polynomial<i64>>>, v: &Vec<Polynomial<i64>>, modulus: i64, poly_mod: &Polynomial<i64>, omega: i64) -> Vec<Polynomial<i64>> {
    m.iter()
        .map(|row| mul_vec_simple(row, v, modulus, poly_mod, omega))
        .collect()
}

pub fn transpose(m: &Vec<Vec<Polynomial<i64>>>) -> Vec<Vec<Polynomial<i64>>> {
    let rows = m.len();
    let cols = m[0].len();
    let mut result = vec![vec![Polynomial::new(vec![]); rows]; cols];
    for i in 0..rows {
        for j in 0..cols {
            result[j][i] = m[i][j].clone();
        }
    }
    result
}

pub fn gen_small_vector(size: usize, rank: usize, seed: Option<u64>) -> Vec<Polynomial<i64>> {
    let between = Uniform::new(0, 3);
    let mut rng = match seed {
        Some(s) => StdRng::seed_from_u64(s),
        None => StdRng::from_entropy(),
    };

    (0..rank)
        .map(|_| {
            let coeffs: Vec<i64> = (0..size).map(|_| between.sample(&mut rng) - 1).collect();
            Polynomial::new(coeffs)
        })
        .collect()
}

pub fn gen_uniform_matrix(size: usize, rank: usize, modulus: i64, seed: Option<u64>) -> Vec<Vec<Polynomial<i64>>> {
    (0..rank)
        .map(|_| {
            (0..rank)
                .map(|_| gen_uniform_poly(size, modulus, seed))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>()
}

pub fn compress(data: &Vec<i64>) -> String {
    let serialized = bincode::serialize(data).expect("Failed to serialize data");
    general_purpose::STANDARD.encode(&serialized)
}

pub fn decompress(base64_str: &str) -> Vec<i64> {
    let decoded = general_purpose::STANDARD.decode(base64_str).expect("Failed to decode base64 string");
    bincode::deserialize(&decoded).expect("Failed to deserialize data")
}

pub fn encode_message(m_b: &Vec<i64>, q: i64) -> Polynomial<i64> {

    // Round q/2 to the nearest integer
    let half_q = nearest_int(q,2);

    // Convert binary message to polynomial
    Polynomial::new(vec![half_q])*Polynomial::new(m_b.to_vec())
    
}