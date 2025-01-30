# module-LWE

![example workflow](https://github.com/lattice-based-cryptography/module-lwe/actions/workflows/basic.yml/badge.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-brightgreen.svg)](https://opensource.org/licenses/MIT)

Implmentation of lattice-based encryption method ring-LWE in pure Rust.

**Description**: This provides the basic PKE (keygen, encryption, and decryption) operations for the module learning-with-errors scheme.

**Disclaimer**: This is not secure. It is not written in constant-time nor resistant to other side-channel attacks. This is intended for educational use and not for real-world applications.

**Usage**: In the `src` directory,

`cargo build`

To build the binary.

`cargo test`

- Performs keygen/encrypt/decrypt for a test message.
- Checks homomorphic addition and multiplcation hold for small values.

_Note_: Parameters optional via 

- `--params <n> <q> <k>`

where `n` is polynomial degree, `q` is modulus, `k` is the module rank.

If ommitted, the default parameters will be used.

`cargo run -- keygen`

This will generate a public/secret keypair. 

`cargo run -- encrypt <public_key> <message>`

Generates the ciphertext.

`cargo run -- decrypt <secret_key> <ciphertext>`

Decrypts the ciphertext given a secret key, printing the plaintext message.

