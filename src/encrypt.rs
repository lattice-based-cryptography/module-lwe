use polynomial_ring::Polynomial;
use ring_lwe::utils::{polyadd,polysub};
use crate::utils::{Parameters, add_vec, mul_mat_vec_simple, transpose, mul_vec_simple, gen_small_vector, compress, decompress, encode_message};

/// Encrypt a message using the ring-LWE cryptosystem
/// # Arguments
/// * `a` - public key matrix
/// * `t` - public key vector
/// * `m_b` - binary message
/// * `params` - Parameters for the ring-LWE cryptosystem
/// * `seed` - random seed
/// # Returns
/// * `(u, v)` - ciphertext
/// # Example
/// ```
/// let params = module_lwe::utils::Parameters::default();
/// let (pk,sk) = module_lwe::keygen::keygen(&params, None);
/// let m_b = vec![0,1,0,1,1,0,1,0];
/// let (u, v) = module_lwe::encrypt::encrypt(&pk.0, &pk.1, &m_b, &params, None);
/// ```
pub fn encrypt(
    a: &Vec<Vec<Polynomial<i64>>>,
    t: &Vec<Polynomial<i64>>,
    m_b: &Vec<i64>,
    params: &Parameters,
    seed: Option<u64>
) -> (Vec<Polynomial<i64>>, Polynomial<i64>) {

    //get parameters
    let (n, q, k, f, omega) = (params.n, params.q, params.k, &params.f, params.omega);
    
    //generate random ephermal keys
    let r = gen_small_vector(n, k, seed);
    let e1 = gen_small_vector(n, k, seed);
    let e2 = gen_small_vector(n, 1, seed)[0].clone(); // Single polynomial

    // encode the message from binary to polynomial
    let m = encode_message(&m_b, q);

    // Compute u = a^T * r + e_1 mod q
    let u = add_vec(&mul_mat_vec_simple(&transpose(a), &r, q, f, omega), &e1, q, f);

    // Compute v = t * r + e_2 - m mod q
    let v = polysub(&polyadd(&mul_vec_simple(t, &r, q, &f, omega), &e2, q, f), &m, q, f);

    (u, v)
}

/// function to encrypt a message given a public_key string
/// # Arguments
/// * `pk_string` - public key string in base64 encoding
/// * `message_string` - message string in base64 encoding
/// * `params` - Parameters for the ring-LWE cryptosystem
/// * `seed` - random seed
/// # Returns
/// * `ciphertext_str` - ciphertext string in base64 encoding
/// # Example
/// ```
/// let params = module_lwe::utils::Parameters::default();
/// let keypair = module_lwe::keygen::keygen_string(&params,None);
/// let pk_string = keypair.get("public").unwrap();
/// let sk_string = keypair.get("secret").unwrap();
/// let message_string = "Hello, world!".to_string();
/// let ciphertext_string = module_lwe::encrypt::encrypt_string(&pk_string, &message_string, &params, None);
/// ```
pub fn encrypt_string(pk_string: &String, message_string: &String, params: &Parameters, seed: Option<u64>) -> String {
    // Get parameters
    let (n, k) = (params.n, params.k);

    // Decode and deserialize the base64-encoded public key string
    let pk_list: Vec<i64> = decompress(pk_string);

    // Parse the public key
    let a: Vec<Vec<Polynomial<i64>>> = pk_list[..k * k * n]
        .chunks(k * n)
        .map(|chunk| {
            chunk.chunks(n).map(|coeffs| Polynomial::new(coeffs.to_vec())).collect()
        })
        .collect();

    let t: Vec<Polynomial<i64>> = pk_list[k * k * n..]
        .chunks(n)
        .map(|coeffs| Polynomial::new(coeffs.to_vec()))
        .collect();

    // Parse message
    let message_binary: Vec<i64> = message_string
        .bytes()
        .flat_map(|byte| (0..8).rev().map(move |i| ((byte >> i) & 1) as i64))
        .collect();

    // Break message into blocks
    let message_blocks: Vec<Vec<i64>> = message_binary
        .chunks(n) // Divide the binary message into chunks of size `n`
        .map(|chunk| chunk.to_vec()) // Convert each chunk into a vector
        .collect();

    // Encrypt each block
    let mut ciphertext_list = vec![];
    for block in message_blocks {
        let (u, v) = encrypt(&a, &t, &block, params, seed);
        let u_flattened: Vec<i64> = u.iter()
            .flat_map(|poly| {
                let mut coeffs = poly.coeffs().to_vec();
                coeffs.resize(n, 0); // Resize to include leading zeros up to size `n`
                coeffs
            })
            .collect();
        let mut v_flattened: Vec<i64> = v.coeffs().to_vec();
        v_flattened.resize(n, 0);
        ciphertext_list.extend(u_flattened);
        ciphertext_list.extend(v_flattened);
    }

    // Serialize and Base64 encode the ciphertext coefficient list
    compress(&ciphertext_list)
}