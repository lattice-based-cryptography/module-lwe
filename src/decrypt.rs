use polynomial_ring::Polynomial;
use ring_lwe::utils::{polysub,nearest_int};
use crate::utils::{Parameters,mul_vec_simple,decompress};

/// Decrypt a ciphertext
/// # Arguments
/// * `sk` - secret key
/// * `q` - ciphertext modulus
/// * `f` - polynomial modulus
/// * `u` - ciphertext vector
/// * `v` - ciphertext polynomial
/// # Returns
/// * `decrypted_coeffs` - plaintext vector
/// # Example
/// ```
/// let params = module_lwe::utils::Parameters::default();
/// let (pk,sk) = module_lwe::keygen::keygen(&params, None);
/// let mut m_b = vec![0,1,0,1,0,0,1,1,1,0,1];
/// m_b.resize(params.n, 0);
/// let (u, v) = module_lwe::encrypt::encrypt(&pk.0, &pk.1, &m_b, &params, None);
/// let decrypted_coeffs = module_lwe::decrypt::decrypt(&sk, &u, &v, &params);
/// assert_eq!(m_b, decrypted_coeffs);
/// ```
pub fn decrypt(
    sk: &Vec<Polynomial<i64>>,    //secret key
    u: &Vec<Polynomial<i64>>, //ciphertext vector
	v: &Polynomial<i64> ,		//ciphertext polynomial
    params: &Parameters
) -> Vec<i64> {
	let (q, f, omega) = (params.q, &params.f, params.omega); //get parameters
	let scaled_pt = polysub(&v, &mul_vec_simple(&sk, &u, q, &f, omega), q, f); //Compute v-sk*u mod q
	let half_q = nearest_int(q,2); // compute nearest integer to q/2
	let mut decrypted_coeffs = vec![];
	let mut s;
	for c in scaled_pt.coeffs().iter() {
		s = nearest_int(*c,half_q).rem_euclid(2);
		decrypted_coeffs.push(s);
	}
    decrypted_coeffs
}

/// decrypt a ciphertext string given a secret key
/// # Arguments
/// * `sk_string` - secret key string in base64 encoding
/// * `ciphertext_string` - ciphertext string in base64 encoding
/// * `params` - Parameters for the ring-LWE cryptosystem
/// # Returns
/// * `message_string` - decrypted message string as plaintext
pub fn decrypt_string(sk_string: &String, ciphertext_base64: &String, params: &Parameters) -> String {
    // Get parameters
    let (n, k) = (params.n, params.k);

    // Base64 decode the secret key string
    let sk_array: Vec<i64> = decompress(sk_string);

    // Convert the secret key into a Vec<Polynomial<i64>>
    let sk: Vec<Polynomial<i64>> = sk_array.chunks(n)
        .map(|chunk| Polynomial::new(chunk.to_vec()))
        .collect();

    // Base64 decode and deserialize the ciphertext string
    let ciphertext_list: Vec<i64> = decompress(ciphertext_base64);

    let block_size = (k + 1) * n;
    let num_blocks = ciphertext_list.len() / block_size;

    let mut message_binary = vec![];

    for i in 0..num_blocks {
        // Get u and v for this block
        let u_array = &ciphertext_list[i * block_size..i * block_size + k * n];
        let v_array = &ciphertext_list[i * block_size + k * n..(i + 1) * block_size];

        let u: Vec<Polynomial<i64>> = u_array.chunks(n)
            .map(|chunk| Polynomial::new(chunk.to_vec()))
            .collect();
        let v = Polynomial::new(v_array.to_vec());

        // Abstracted block decryption
        let m_b = decode_block(&sk, &u, &v, params);

        message_binary.extend(m_b);
    }

    // Group the bits back into bytes (8 bits each)
    let byte_chunks: Vec<String> = message_binary.chunks(8)
        .map(|chunk| chunk.iter().map(|bit| bit.to_string()).collect())
        .collect();

    // Convert each binary string back into a character
    let message_string: String = byte_chunks.iter()
        .map(|byte| char::from_u32(i64::from_str_radix(byte, 2).unwrap() as u32).unwrap())
        .collect();

    // Trim the null characters \0 = '00000000' from the end
    message_string.trim_end_matches('\0').to_string()
}

fn decode_block(sk: &Vec<Polynomial<i64>>, u: &Vec<Polynomial<i64>>, v: &Polynomial<i64>, params: &Parameters) -> Vec<i64> {
    let mut m_b = decrypt(sk, u, v, params);
    m_b.resize(params.n, 0);
    m_b
}
