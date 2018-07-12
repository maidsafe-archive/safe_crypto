// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

//! Mock cryptographic primitives.
//!
//! These primitives are designed to be very fast (several times faster than the real ones), but
//! they are NOT secure. They are supposed to be used for testing only.

/// Mock hash functions.
pub(crate) mod hashing_impl {
    use super::hash64;

    /// Fast mock version of the Keccak SHA-3 hash function.
    pub(crate) fn sha3_256(data: &[u8]) -> [u8; 32] {
        let mut hash = [0; 32];
        hash64(data)
            .into_iter()
            .cycle()
            .take(32)
            .enumerate()
            .for_each(|(i, b)| hash[i] = *b);
        hash
    }
}

/// Mock version of a subset of the `rust_sodium` crate.
pub(crate) mod crypto_impl {
    use rand::{Rng, SeedableRng, XorShiftRng};
    use std::cell::RefCell;

    thread_local! {
        static RNG: RefCell<XorShiftRng> = RefCell::new(XorShiftRng::new_unseeded());
    }

    /// Initialise mock `rust_sodium`.
    pub(crate) fn init() -> Result<(), ()> {
        Ok(())
    }

    /// Initialise mock `rust_sodium` with the given random number generator. This can be used to
    /// guarantee reproducible test results.
    pub(crate) fn init_with_rng<T: Rng>(other: &mut T) -> Result<(), i32> {
        RNG.with(|rng| rng.borrow_mut().reseed(other.gen()));
        Ok(())
    }

    /// Mock cryptographic functions.
    pub(crate) mod crypto {
        /// Mock signing.
        pub(crate) mod sign {
            use super::super::with_rng;
            use mock_crypto::hash64;
            use rand::Rng;
            use std::ops::{Index, RangeFull};

            /// Number of bytes in a `PublicKey`.
            pub(crate) const PUBLICKEYBYTES: usize = 8;
            /// Number of bytes in a `SecretKey`.
            pub(crate) const SECRETKEYBYTES: usize = 8;
            /// Number of bytes in a `Signature`.
            pub(crate) const SIGNATUREBYTES: usize = 8;

            /// Mock signing public key.
            #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd,
                     Serialize)]
            pub(crate) struct PublicKey(pub(crate) [u8; PUBLICKEYBYTES]);

            impl Index<RangeFull> for PublicKey {
                type Output = [u8];
                fn index(&self, index: RangeFull) -> &[u8] {
                    self.0.index(index)
                }
            }

            /// Mock signing secret key.
            #[derive(Clone, Debug, Eq, PartialEq)]
            pub(crate) struct SecretKey(pub(crate) [u8; SECRETKEYBYTES]);

            /// Mock signature.
            #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, Serialize, PartialEq,
                     PartialOrd)]
            pub(crate) struct Signature(pub(crate) [u8; SIGNATUREBYTES]);

            impl AsRef<[u8]> for Signature {
                fn as_ref(&self) -> &[u8] {
                    &self.0
                }
            }

            /// Generate mock public and corresponding secret key.
            pub(crate) fn gen_keypair() -> (PublicKey, SecretKey) {
                with_rng(|rng| {
                    let value = rng.gen();
                    (PublicKey(value), SecretKey(value))
                })
            }

            /// Sign a message using the mock secret key.
            pub(crate) fn sign_detached(m: &[u8], sk: &SecretKey) -> Signature {
                let mut temp = m.to_vec();
                temp.extend(&sk.0);
                Signature(hash64(&temp))
            }

            /// Verify the mock signature against the message and the signer's mock public key.
            pub(crate) fn verify_detached(signature: &Signature, m: &[u8], pk: &PublicKey) -> bool {
                let mut temp = m.to_vec();
                temp.extend(&pk.0);
                *signature == Signature(hash64(&temp))
            }
        }

        /// Mock encryption.
        pub(crate) mod box_ {
            use super::super::with_rng;
            use rand::Rng;
            use std::ops::{Index, RangeFull};

            /// Number of bytes in a `PublicKey`.
            pub(crate) const PUBLICKEYBYTES: usize = 8;
            /// Number of bytes in a `SecretKey`.
            pub(crate) const SECRETKEYBYTES: usize = 8;
            /// Number of bytes in a `Nonce`.
            pub(crate) const NONCEBYTES: usize = 4;

            /// Mock public key for asymmetric encryption/decryption.
            #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd,
                     Serialize)]
            pub(crate) struct PublicKey(pub(crate) [u8; PUBLICKEYBYTES]);

            impl Index<RangeFull> for PublicKey {
                type Output = [u8];
                fn index(&self, index: RangeFull) -> &[u8] {
                    self.0.index(index)
                }
            }

            /// Mock secret key for asymmetric encryption/decryption.
            #[derive(Clone, Debug, Eq, PartialEq)]
            pub(crate) struct SecretKey(pub(crate) [u8; SECRETKEYBYTES]);

            /// Mock nonce for asymmetric encryption/decryption.
            #[derive(Serialize, Deserialize)]
            pub(crate) struct Nonce(pub(crate) [u8; NONCEBYTES]);

            #[derive(Clone, Debug, Eq, PartialEq)]
            pub(crate) struct PrecomputedKey(pub(crate) [u8; SECRETKEYBYTES]);

            /// Generate mock public and corresponding secret key.
            pub(crate) fn gen_keypair() -> (PublicKey, SecretKey) {
                with_rng(|rng| {
                    let value = rng.gen();
                    (PublicKey(value), SecretKey(value))
                })
            }

            /// Generate mock nonce.
            pub(crate) fn gen_nonce() -> Nonce {
                with_rng(|rng| Nonce(rng.gen()))
            }

            /// Generate mock shared key
            pub(crate) fn precompute(pk: &PublicKey, sk: &SecretKey) -> PrecomputedKey {
                let mut shared_secret: [u8; SECRETKEYBYTES] = [0; SECRETKEYBYTES];
                for (i, shared) in shared_secret.iter_mut().enumerate().take(pk.0.len()) {
                    *shared = pk.0[i] ^ sk.0[i];
                }
                PrecomputedKey(shared_secret)
            }

            /// Perform mock encryption of the given message using the shared key
            /// and nonce.
            pub(crate) fn seal_precomputed(
                m: &[u8],
                nonce: &Nonce,
                sk: &PrecomputedKey,
            ) -> Vec<u8> {
                let mut result = Vec::with_capacity(m.len() + nonce.0.len() + sk.0.len());
                result.extend(&nonce.0);
                result.extend(&sk.0);
                result.extend(m);
                result
            }

            /// Perform mock decryption of the given ciphertext using their secret key, our public
            /// key and nonce.
            pub(crate) fn open_precomputed(
                c: &[u8],
                nonce: &Nonce,
                sk: &PrecomputedKey,
            ) -> Result<Vec<u8>, ()> {
                let n = nonce.0.len();
                let s = sk.0.len();

                if c[0..n] != nonce.0 {
                    return Err(());
                }

                if c[n..n + s] != sk.0 {
                    return Err(());
                }

                Ok(c[n + s..].to_vec())
            }
        }

        pub(crate) mod sealedbox {
            use box_::{PublicKey, SecretKey};

            /// Perform mock anonymous encryption.
            pub(crate) fn seal(m: &[u8], pk: &PublicKey) -> Vec<u8> {
                let mut result = Vec::with_capacity(m.len() + pk.0.len());
                result.extend(&pk.0);
                result.extend(m);
                result
            }

            /// Perform mock anonymous decryption.
            pub(crate) fn open(c: &[u8], pk: &PublicKey, sk: &SecretKey) -> Result<Vec<u8>, ()> {
                let p = pk.0.len();

                if c[0..p] != pk.0 {
                    return Err(());
                }

                if pk.0 != sk.0 {
                    return Err(());
                }

                Ok(c[p..].to_vec())
            }
        }

        /// Mock symmetric encryption.
        pub(crate) mod secretbox {
            use super::super::with_rng;
            use rand::Rng;

            /// Number of bytes in a `Key`.
            pub(crate) const KEYBYTES: usize = 8;
            /// Number of bytes in a `Nonce`.
            pub(crate) const NONCEBYTES: usize = 4;

            /// Mock secret key for symmetric encryption/decryption.
            #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd,
                     Serialize)]
            pub(crate) struct Key(pub(crate) [u8; KEYBYTES]);

            /// Mock nonce for symmetric encryption/decryption.
            #[derive(Serialize, Deserialize)]
            pub(crate) struct Nonce(pub(crate) [u8; NONCEBYTES]);

            /// Generate mock public and corresponding secret key.
            pub(crate) fn gen_key() -> Key {
                with_rng(|rng| Key(rng.gen()))
            }

            /// Generate mock nonce.
            pub(crate) fn gen_nonce() -> Nonce {
                with_rng(|rng| Nonce(rng.gen()))
            }

            /// Perform mock symmetric encryption.
            pub(crate) fn seal(m: &[u8], nonce: &Nonce, key: &Key) -> Vec<u8> {
                let mut result = Vec::with_capacity(m.len() + nonce.0.len() + key.0.len());
                result.extend(&key.0);
                result.extend(&nonce.0);
                result.extend(m);
                result
            }

            /// Perform mock symmetric decryption.
            pub(crate) fn open(c: &[u8], nonce: &Nonce, key: &Key) -> Result<Vec<u8>, ()> {
                let p = key.0.len();
                let n = nonce.0.len();

                if c[0..p] != key.0 {
                    return Err(());
                }

                if c[p..p + n] != nonce.0 {
                    return Err(());
                }

                Ok(c[p + n..].to_vec())
            }
        }
    }

    fn with_rng<F, R>(f: F) -> R
    where
        F: FnOnce(&mut XorShiftRng) -> R,
    {
        RNG.with(|rng| f(&mut *rng.borrow_mut()))
    }
}

fn hash64(data: &[u8]) -> [u8; 8] {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::Hasher;

    let mut hasher = DefaultHasher::new();
    hasher.write(data);

    let hash = hasher.finish();
    [
        (hash >> 56) as u8,
        (hash >> 48) as u8,
        (hash >> 40) as u8,
        (hash >> 32) as u8,
        (hash >> 24) as u8,
        (hash >> 16) as u8,
        (hash >> 8) as u8,
        (hash) as u8,
    ]
}

#[cfg(test)]
mod tests {
    use super::crypto_impl::crypto::{box_, sign};
    use rand::{self, Rng};

    #[test]
    fn keypair_generation() {
        let (sign_pk0, sign_sk0) = sign::gen_keypair();
        let (sign_pk1, sign_sk1) = sign::gen_keypair();
        assert_ne!(sign_pk0, sign_pk1);
        assert_ne!(sign_sk0, sign_sk1);

        let (box_pk0, box_sk0) = box_::gen_keypair();
        let (box_pk1, box_sk1) = box_::gen_keypair();
        assert_ne!(box_pk0, box_pk1);
        assert_ne!(box_sk0, box_sk1);
    }

    #[test]
    fn sign_and_verify() {
        let (pk0, sk0) = sign::gen_keypair();
        let message: Vec<_> = rand::thread_rng().gen_iter().take(10).collect();

        let signature = sign::sign_detached(&message, &sk0);
        assert!(sign::verify_detached(&signature, &message, &pk0));

        let (pk1, _) = sign::gen_keypair();
        assert!(!sign::verify_detached(&signature, &message, &pk1));
    }
}
