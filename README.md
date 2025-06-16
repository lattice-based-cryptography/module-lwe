# module-LWE

[![Workflow Status](https://github.com/lattice-based-cryptography/module-lwe/actions/workflows/basic.yml/badge.svg)](https://github.com/lattice-based-cryptography/module-lwe/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-brightgreen.svg)](https://opensource.org/licenses/MIT)
[![Crates.io](https://img.shields.io/crates/v/module-lwe.svg)](https://crates.io/crates/module-lwe)

A pure Rust implementation of the **Module Learning With Errors (module-LWE)** encryption scheme.

---

## 📖 Description

This crate implements basic **public-key encryption (PKE)** operations — key generation, encryption, and decryption — based on the Module-LWE problem, a lattice-based post-quantum cryptographic assumption.

---

## ⚠️ Security Warning

> **This library is not secure.**
>
> It is:
> - Not constant-time
> - Not hardened against timing, cache, or other side-channel attacks
> - Intended **only for educational and experimental purposes**

Do **not** use this in production or real-world cryptographic systems.

---

## 🔧 Usage

Ensure you're in the project root:

```sh
cargo build
```

Builds the module.

```sh
cargo test
```

Runs tests to verify:
- Keygen, encryption, and decryption round-trip correctness
- Homomorphic addition and multiplication (limited cases)

---

## 🧪 Command-line Options

The binary accepts optional parameters using:

```sh
--params <n> <q> <k>
```

Where:
- `n`: Polynomial degree
- `q`: Ciphertext modulus
- `k`: Module rank

If omitted, defaults are: `n = 512`, `q = 12289`, `k = 8`.

---

## 💻 Example Commands

```sh
cargo run -- keygen
```

Generates a public/secret keypair.

```sh
cargo run -- encrypt <public_key> <message>
```

Encrypts the message using the given public key.

```sh
cargo run -- decrypt <secret_key> <ciphertext>
```

Decrypts the ciphertext using the given secret key.

---

## 📊 Benchmarks

| n   | q     | k | KeyGen    | Encrypt   | Decrypt   | KeyGen (str) | Encrypt (str) | Decrypt (str) |
|-----|-------|---|-----------|-----------|-----------|---------------|----------------|----------------|
| 256 | 12289 | 2 | 146.66 µs | 194.11 µs | 61.53 µs  | 230.43 µs     | 255.60 µs      | 88.29 µs       |
| 256 | 12289 | 4 | 562.56 µs | 622.29 µs | 118.37 µs | 819.22 µs     | 787.60 µs      | 167.38 µs      |
| 384 | 12289 | 4 | 1.177 ms  | 1.347 ms  | 260.02 µs | 1.554 ms      | 1.583 ms       | 332.87 µs      |
| 512 | 12289 | 4 | 1.196 ms  | 1.360 ms  | 260.77 µs | 1.717 ms      | 1.698 ms       | 356.75 µs      |
| 512 | 12289 | 8 | 4.699 ms  | 4.876 ms  | 518.81 µs | 6.413 ms      | 5.792 ms       | 677.05 µs      |

---

## 🧐 Educational Focus

This crate is meant to help explore:

- Algebraic structure of Module-LWE
- Effects of parameter choices on performance
- Polynomial arithmetic over rings

For real cryptographic implementations, refer to:
- [PQClean](https://github.com/PQClean/PQClean)
- [Kyber](https://github.com/pq-crystals/kyber)
- [RustCrypto](https://github.com/RustCrypto)

---

## 📄 License

MIT License © 2025  
Part of the [lattice-based-cryptography](https://github.com/lattice-based-cryptography) project.
