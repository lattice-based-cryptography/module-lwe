use polynomial_ring::Polynomial;
use ring_lwe::utils::{polysub,nearest_int};
use crate::utils::{Parameters,mul_vec_simple};

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
/// * `sk_string` - secret key string
/// * `ciphertext_string` - ciphertext string
/// * `params` - Parameters for the ring-LWE cryptosystem
/// # Returns
/// * `message_string` - decrypted message string
pub fn decrypt_string(sk_string: &String, ciphertext_string: &String, params: &Parameters) -> String {

    //get parameters
    let (n, k) = (params.n, params.k);
    
    // Convert the secret key string into a Vec<Polynomial<i64>>
    let sk_array: Vec<i64> = sk_string.split(',')
        .filter_map(|s| s.parse().ok())
        .collect();
    let sk: Vec<Polynomial<i64>> = sk_array.chunks(n)
        .map(|chunk| Polynomial::new(chunk.to_vec()))
        .collect();
    
    // Parse ciphertext into u and v
    let ciphertext_list: Vec<i64> = ciphertext_string.split(',')
        .filter_map(|s| s.parse().ok())
        .collect();
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
            
        // Decrypt the ciphertext
        let mut m_b = decrypt(&sk, &u, &v, &params);
        m_b.resize(n,0);
            
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
    
    //trim the null characters \0 = '00000000' from the end
    message_string.trim_end_matches('\0').to_string()
}