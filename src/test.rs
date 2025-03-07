#[cfg(test)]  // This makes the following module compile only during tests
mod tests {
    use crate::keygen::{keygen,keygen_string};
    use crate::encrypt::{encrypt,encrypt_string};
    use crate::decrypt::{decrypt,decrypt_string};
    use crate::utils::{Parameters,add_vec};
    use ring_lwe::utils::polyadd;

    // Test for basic keygen/encrypt/decrypt of a message
    #[test]
    pub fn test_basic() {
        let seed = None; //set random seed
        let message = String::from("hello");
        let params = Parameters::default();  // Adjust this if needed
        let keypair = keygen_string(&params,seed);
        let pk_string = keypair.get("public").unwrap();
        let sk_string = keypair.get("secret").unwrap();
        let ciphertext_string = encrypt_string(&pk_string, &message, &params,seed);
        let decrypted_message = decrypt_string(&sk_string, &ciphertext_string, &params);
        assert_eq!(message, decrypted_message, "test failed: {} != {}", message, decrypted_message);
    }

    // Test homomorphic addition property: 
    // for plaintext polynomials m0, m1
    // assert: dec(enc(m0) + enc(m1)) = m0 + m1
    // note that the plaintext modulus is t=2 implicitly
    // since we are using half_q = q/2 = q/t = delta
    // the homomorphism is enc: R_q -> R_t, and dec: R_t -> R_q
    #[test]
    pub fn test_hom_add() {

        let seed = None; //set the random seed
        let params = Parameters::default();
        let (n, q, f) = (params.n, params.q, &params.f);

        let mut m0 = vec![1, 0, 1];
        m0.resize(n, 0);
        let mut m1 = vec![0, 0, 1];
        m1.resize(n, 0);
        let mut plaintext_sum = vec![1, 0, 0];
        plaintext_sum.resize(n, 0);
        let (pk, sk) = keygen(&params,seed);

        // Encrypt plaintext messages
        let u = encrypt(&pk.0, &pk.1, &m0, &params, seed);
        let v = encrypt(&pk.0, &pk.1, &m1, &params, seed);

        // Compute sum of encrypted data
        let ciphertext_sum = (add_vec(&u.0,&v.0,q,f), polyadd(&u.1,&v.1,q,f));

        // Decrypt ciphertext sum u+v
        let mut decrypted_sum = decrypt(&sk, &ciphertext_sum.0, &ciphertext_sum.1, &params);
        decrypted_sum.resize(n, 0);

        assert_eq!(decrypted_sum, plaintext_sum, "test failed: {:?} != {:?}", decrypted_sum, plaintext_sum);
    }
}