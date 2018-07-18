// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

//! This is a convenience library providing abstractions for cryptographic functions required by
//! other SAFE Network libraries.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
    html_favicon_url = "https://maidsafe.net/img/favicon.ico",
    html_root_url = "https://docs.rs/safe_crypto"
)]
#![forbid(
    exceeding_bitshifts, mutable_transmutes, no_mangle_const_items, unknown_crate_types, warnings
)]
#![deny(
    bad_style, deprecated, improper_ctypes, missing_docs, non_shorthand_field_patterns,
    overflowing_literals, plugin_as_library, private_no_mangle_fns, private_no_mangle_statics,
    stable_features, unconditional_recursion, unknown_lints, unsafe_code, unused, unused_allocation,
    unused_attributes, unused_comparisons, unused_features, unused_parens, while_true
)]
#![warn(
    trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
    unused_qualifications, unused_results
)]
#![allow(
    box_pointers, missing_copy_implementations, missing_debug_implementations,
    variant_size_differences
)]

#[cfg(feature = "mock")]
#[macro_use]
extern crate lazy_static;
extern crate maidsafe_utilities;
#[cfg(any(test, feature = "mock"))]
extern crate rand;
#[cfg(not(feature = "mock"))]
extern crate rust_sodium as crypto_impl;
extern crate serde;
#[macro_use]
extern crate serde_derive;
#[cfg(not(feature = "mock"))]
extern crate tiny_keccak as hashing_impl;
#[macro_use]
extern crate quick_error;
#[cfg(any(test, feature = "mock"))]
#[macro_use]
extern crate unwrap;

#[cfg(feature = "mock")]
mod mock_crypto;
#[cfg(feature = "mock")]
mod seeded_rng;
#[cfg(feature = "mock")]
use mock_crypto::crypto_impl;
#[cfg(feature = "mock")]
use mock_crypto::hashing_impl;
#[cfg(feature = "mock")]
pub use seeded_rng::SeededRng;

use crypto_impl::crypto::{box_, sealedbox, secretbox, sign};
use maidsafe_utilities::serialisation::{deserialise, serialise, SerialisationError};
#[cfg(feature = "mock")]
use rand::Rng;
use serde::{de::DeserializeOwned, de::Deserializer, Deserialize, Serialize, Serializer};
use std::fmt;
use std::sync::Arc;

/// Size of an initialisation vector.
pub const IV_SIZE: usize = box_::NONCEBYTES;
/// Size of a secret symmetric key.
pub const SYMMETRIC_KEY_SIZE: usize = secretbox::KEYBYTES;
/// Size of a public signing key.
pub const PUBLIC_SIGN_KEY_SIZE: usize = 32;

/// Represents public signature key.
pub type PublicSignKey = [u8; PUBLIC_SIGN_KEY_SIZE];

/// Initialisation vector.
pub type Iv = [u8; IV_SIZE];

/// Initialise random number generator for the key generation functions.
pub fn init() -> Result<(), ()> {
    crypto_impl::init()
}

/// Initialise the key generation functions with a custom random number generator `rng`.
/// Can be used for deterministic key generation in tests.
/// Returns an error in case of an random generator initialisation error.
#[cfg(feature = "mock")]
pub fn init_with_rng<T: Rng>(rng: &mut T) -> Result<(), Error> {
    crypto_impl::init_with_rng(rng).map_err(Error::InitError)
}

/// Produces a 256-bit crypto hash out of the provided `data`.
pub fn hash(data: &[u8]) -> [u8; 32] {
    hashing_impl::sha3_256(data)
}

/// Represents a set of public keys, consisting of a public signature key and a public
/// encryption key.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Clone)]
pub struct PublicKeys {
    sign: sign::PublicKey,
    encrypt: box_::PublicKey,
}

/// Secret counterpart of the public key set, consisting of a secret signing key and
/// a secret encryption key.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SecretKeys {
    inner: Arc<SecretKeysInner>,
    public: PublicKeys,
}

#[derive(Debug, PartialEq, Eq)]
struct SecretKeysInner {
    sign: sign::SecretKey,
    encrypt: box_::SecretKey,
}

/// Secret key for authenticated symmetric encryption.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SymmetricKey {
    encrypt: Arc<secretbox::Key>,
}

/// Detached signature.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Clone)]
pub struct Signature {
    signature: sign::Signature,
}

/// Precomputed shared secret key.
/// Can be created from a pair of our secret key and the recipient's public key.
/// As a result, we'll get the same key as the recipient with their secret key and
/// our public key.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SharedSecretKey {
    precomputed: Arc<box_::PrecomputedKey>,
}

#[derive(Serialize, Deserialize)]
struct CipherText {
    nonce: Iv,
    ciphertext: Vec<u8>,
}

impl PublicKeys {
    /// Returns a public signing key.
    #[cfg(feature = "mock")]
    pub fn public_sign_key(&self) -> PublicSignKey {
        // Pads the key to 32 bytes for mock-crypto
        let mut full_len_key = [0; PUBLIC_SIGN_KEY_SIZE];
        self.sign
            .0
            .iter()
            .cloned()
            .cycle()
            .take(PUBLIC_SIGN_KEY_SIZE)
            .enumerate()
            .for_each(|(i, v)| full_len_key[i] = v);
        full_len_key
    }

    /// Returns a public signing key.
    #[cfg(not(feature = "mock"))]
    pub fn public_sign_key(&self) -> PublicSignKey {
        self.sign.0
    }

    /// Encrypts serialisable `plaintext` using anonymous encryption.
    ///
    /// Anonymous encryption will use an ephemeral public key, so the recipient won't
    /// be able to tell who sent the ciphertext.
    /// If you wish to encrypt bytestring plaintext, use `encrypt_anonymous_bytes`.
    /// To use authenticated encryption, use `SharedSecretKey`.
    ///
    /// Returns ciphertext in case of success.
    /// Can return an `Error` in case of a serialisation error.
    pub fn encrypt_anonymous<T>(&self, plaintext: &T) -> Result<Vec<u8>, Error>
    where
        T: Serialize,
    {
        Ok(self.encrypt_anonymous_bytes(&serialise(plaintext)?))
    }

    /// Encrypts bytestring `plaintext` using anonymous encryption.
    ///
    /// Anonymous encryption will use an ephemeral public key, so the recipient won't
    /// be able to tell who sent the ciphertext.
    /// To use authenticated encryption, use `SharedSecretKey`.
    ///
    /// Returns ciphertext in case of success.
    pub fn encrypt_anonymous_bytes(&self, plaintext: &[u8]) -> Vec<u8> {
        sealedbox::seal(plaintext, &self.encrypt)
    }

    /// Verifies the detached `signature`.
    ///
    /// Returns `true` if the signature is valid the `data` is verified.
    pub fn verify_detached(&self, signature: &Signature, data: &[u8]) -> bool {
        sign::verify_detached(&signature.signature, data, &self.sign)
    }
}

impl SecretKeys {
    /// Generates a pair of secret and public key sets.
    pub fn new() -> SecretKeys {
        let (sign_pk, sign_sk) = sign::gen_keypair();
        let (encrypt_pk, encrypt_sk) = box_::gen_keypair();
        let public = PublicKeys {
            sign: sign_pk,
            encrypt: encrypt_pk,
        };
        SecretKeys {
            public,
            inner: Arc::new(SecretKeysInner {
                sign: sign_sk,
                encrypt: encrypt_sk,
            }),
        }
    }

    /// Returns the public part of the secret key set.
    pub fn public_keys(&self) -> &PublicKeys {
        &self.public
    }

    /// Decrypts serialised `ciphertext` encrypted using anonymous encryption.
    ///
    /// With anonymous encryption we won't be able to verify the sender and
    /// tell who sent the ciphertext.
    ///
    /// Returns deserialised type `T` in case of success.
    /// Can return `Error` in case of a deserialisation error, if the ciphertext is
    /// not valid, or if it can not be decrypted.
    pub fn decrypt_anonymous<T>(&self, ciphertext: &[u8]) -> Result<T, Error>
    where
        T: Serialize + DeserializeOwned,
    {
        Ok(deserialise(&self.decrypt_anonymous_bytes(ciphertext)?)?)
    }

    /// Decrypts bytestring `ciphertext` encrypted using anonymous encryption.
    ///
    /// With anonymous encryption we won't be able to verify the sender and
    /// tell who sent the ciphertext.
    ///
    /// Returns plaintext in case of success.
    /// Can return `Error` if the ciphertext is not valid or if it can not be decrypted.
    pub fn decrypt_anonymous_bytes(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(sealedbox::open(
            ciphertext,
            &self.public.encrypt,
            &self.inner.encrypt,
        )?)
    }

    /// Produces the detached signature from the `data`.
    ///
    /// Afterwards the returned `Signature` can be used to verify the authenticity of `data`.
    pub fn sign_detached(&self, data: &[u8]) -> Signature {
        Signature {
            signature: sign::sign_detached(data, &self.inner.sign),
        }
    }

    /// Computes a shared secret from our secret key and the recipient's public key.
    pub fn shared_secret(&self, their_pk: &PublicKeys) -> SharedSecretKey {
        let precomputed = Arc::new(box_::precompute(&their_pk.encrypt, &self.inner.encrypt));
        SharedSecretKey { precomputed }
    }
}

impl Default for SecretKeys {
    fn default() -> Self {
        Self::new()
    }
}

impl SharedSecretKey {
    /// Encrypts bytestring `plaintext` using authenticated encryption.
    ///
    /// With authenticated encryption the recipient will be able to verify the authenticity
    /// of the sender using a sender's public key.
    /// If you want to use anonymous encryption, use the functions provided by `PublicKeys`
    /// and `SecretKeys`.
    ///
    /// Returns ciphertext in case of success.
    /// Can return an `Error` in case of a serialisation error.
    pub fn encrypt_bytes(&self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let nonce = box_::gen_nonce();
        let ciphertext = box_::seal_precomputed(plaintext, &nonce, &self.precomputed);
        Ok(serialise(&CipherText {
            nonce: nonce.0,
            ciphertext,
        })?)
    }

    /// Encrypts serialisable `plaintext` using authenticated encryption.
    ///
    /// With authenticated encryption the recipient will be able to verify the authenticity
    /// of the sender using a sender's public key.
    /// If you wish to encrypt bytestring plaintext, use `encrypt_bytes`.
    /// If you want to use anonymous encryption, use the functions provided by `PublicKeys`
    /// and `SecretKeys`.
    ///
    /// Returns ciphertext in case of success.
    /// Can return an `Error` in case of a serialisation error.
    pub fn encrypt<T>(&self, plaintext: &T) -> Result<Vec<u8>, Error>
    where
        T: Serialize,
    {
        self.encrypt_bytes(&serialise(plaintext)?)
    }

    /// Decrypts bytestring `encoded` encrypted using authenticated encryption.
    ///
    /// With authenticated encryption we will be able to verify the authenticity
    /// of the sender using a sender's public key.
    ///
    /// Returns plaintext in case of success.
    /// Can return `Error` in case of a deserialisation error, if the ciphertext
    /// is not valid, or if it can not be decrypted.
    pub fn decrypt_bytes(&self, encoded: &[u8]) -> Result<Vec<u8>, Error> {
        let CipherText { nonce, ciphertext } = deserialise(encoded)?;
        Ok(box_::open_precomputed(
            &ciphertext,
            &box_::Nonce(nonce),
            &self.precomputed,
        )?)
    }

    /// Decrypts serialised `ciphertext` encrypted using authenticated encryption.
    ///
    /// With authenticated encryption we will be able to verify the authenticity
    /// of the sender using a sender's public key.
    ///
    /// Returns deserialised type `T` in case of success.
    /// Can return `Error` in case of a deserialisation error, if the ciphertext
    /// is not valid, or if it can not be decrypted.
    pub fn decrypt<T>(&self, ciphertext: &[u8]) -> Result<T, Error>
    where
        T: Serialize + DeserializeOwned,
    {
        Ok(deserialise(&self.decrypt_bytes(ciphertext)?)?)
    }
}

impl SymmetricKey {
    /// Generates a new symmetric key.
    pub fn new() -> Self {
        let sk = secretbox::gen_key();
        Self {
            encrypt: Arc::new(sk),
        }
    }

    /// Create a new key from bytes.
    pub fn from_bytes(bytes: [u8; SYMMETRIC_KEY_SIZE]) -> Self {
        let sk = secretbox::Key(bytes);
        Self {
            encrypt: Arc::new(sk),
        }
    }

    /// Encrypts serialisable `plaintext` using authenticated symmetric encryption.
    ///
    /// With authenticated encryption the recipient will be able to confirm that the message
    /// is untampered with.
    /// If you wish to encrypt bytestring plaintext, use `encrypt_bytes`.
    ///
    /// Returns ciphertext in case of success.
    /// Can return an `Error` in case of a serialisation error.
    pub fn encrypt<T: Serialize>(&self, plaintext: &T) -> Result<Vec<u8>, Error> {
        self.encrypt_bytes(&serialise(plaintext)?)
    }

    /// Encrypts bytestring `plaintext` using initialisation vector `iv`.
    ///
    /// Returns ciphertext in case of success.
    pub fn encrypt_bytes_iv(&self, plaintext: &[u8], iv: Iv) -> Result<Vec<u8>, Error> {
        Ok(secretbox::seal(
            plaintext,
            &secretbox::Nonce(iv),
            &self.encrypt,
        ))
    }

    /// Encrypts bytestring `plaintext` using authenticated symmetric encryption.
    ///
    /// With authenticated encryption the recipient will be able to confirm that the message
    /// is untampered with.
    ///
    /// Returns ciphertext in case of success.
    /// Can return an `Error` in case of a serialisation error.
    pub fn encrypt_bytes(&self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let nonce = secretbox::gen_nonce();
        let ciphertext = self.encrypt_bytes_iv(plaintext, nonce.0)?;
        Ok(serialise(&CipherText {
            nonce: nonce.0,
            ciphertext,
        })?)
    }

    /// Decrypts serialised `ciphertext` encrypted using authenticated symmetric encryption.
    ///
    /// With authenticated encryption we will be able to tell that the message hasn't been
    /// tampered with.
    ///
    /// Returns deserialised type `T` in case of success.
    /// Can return `Error` in case of a deserialisation error, if the ciphertext
    /// is not valid, or if it can not be decrypted.
    pub fn decrypt<T>(&self, ciphertext: &[u8]) -> Result<T, Error>
    where
        T: DeserializeOwned + Serialize,
    {
        Ok(deserialise(&self.decrypt_bytes(ciphertext)?)?)
    }

    /// Decrypts bytestring `ciphertext` using a provided initialisation vector `iv`.
    ///
    /// Returns plaintext in case of success.
    /// Can return `Error` if the ciphertext is not valid or if it can not be decrypted.
    pub fn decrypt_bytes_iv(&self, ciphertext: &[u8], iv: Iv) -> Result<Vec<u8>, Error> {
        Ok(secretbox::open(
            &ciphertext,
            &secretbox::Nonce(iv),
            &self.encrypt,
        )?)
    }

    /// Decrypts bytestring `ciphertext` encrypted using authenticated symmetric encryption.
    /// This function uses the baked-in nonce as an initialisation vector.
    ///
    /// With authenticated encryption we will be able to tell that the message hasn't been
    /// tampered with.
    ///
    /// Returns plaintext in case of success.
    /// Can return `Error` in case of a deserialisation error, if the ciphertext
    /// is not valid, or if it can not be decrypted.
    pub fn decrypt_bytes(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let CipherText { nonce, ciphertext } = deserialise(ciphertext)?;
        self.decrypt_bytes_iv(&ciphertext, nonce)
    }
}

impl Default for SymmetricKey {
    fn default() -> Self {
        Self::new()
    }
}

impl Serialize for SymmetricKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Serialize::serialize(&self.encrypt.0, serializer)
    }
}

impl<'de> Deserialize<'de> for SymmetricKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(SymmetricKey::from_bytes(Deserialize::deserialize(
            deserializer,
        )?))
    }
}

impl fmt::Display for PublicKeys {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for b in &self.sign[..] {
            write!(f, "{:02x}", b)?;
        }
        for b in &self.encrypt[..] {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

quick_error! {
    /// This error is returned if encryption or decryption fail.
    /// The encryption failure is rare and mostly connected to serialisation failures.
    /// Decryption can fail because of invalid keys, invalid data, or deserialisation failures.
    #[derive(Debug)]
    pub enum Error {
        /// Occurs when serialisation or deserialisation fails.
        Serialisation(e: SerialisationError) {
            description("error serialising or deserialising message")
            display("error serialising or deserialising message: {}", e)
            cause(e)
            from()
        }
        /// Occurs when we can't decrypt a message or verify the signature.
        DecryptVerify(_e: ()) {
            description("error decrypting/verifying message")
            from()
        }
        /// Occurs in case of an error during initialisation.
        InitError(e: i32) {
            description("error while initialising random generator")
            from()
        }
    }
}

#[cfg(test)]
mod tests {
    use self::rand::{OsRng, Rng};
    use super::*;
    use maidsafe_utilities::serialisation::{deserialise, serialise};

    #[test]
    fn anonymous_bytes_cipher() {
        let data = generate_random_bytes(50);
        let sk = SecretKeys::new();
        let sk2 = SecretKeys::new();
        let pk = sk.public_keys();

        let ciphertext = pk.encrypt_anonymous_bytes(&data);
        assert_ne!(&ciphertext, &data);

        let error_res = sk.decrypt_anonymous_bytes(&data);
        match error_res {
            Err(_e) => (),
            Ok(_) => {
                panic!("Unexpected result: we're using wrong data, it should have returned error")
            }
        }

        let error_res: Result<_, _> = sk2.decrypt_anonymous_bytes(&ciphertext);
        match error_res {
            Err(_e) => (),
            Ok(_) => {
                panic!("Unexpected result: we're using a wrong key, it should have returned error")
            }
        }

        let plaintext: Vec<u8> = unwrap!(
            sk.decrypt_anonymous_bytes(&ciphertext),
            "couldn't decrypt ciphertext"
        );
        assert_eq!(&plaintext, &data);
    }

    #[test]
    fn anonymous_cipher() {
        let mut os_rng = unwrap!(OsRng::new());
        let data: Vec<u64> = os_rng.gen_iter().take(32).collect();

        let sk = SecretKeys::new();
        let pk = sk.public_keys();

        let ciphertext = unwrap!(pk.encrypt_anonymous(&data), "couldn't encrypt base data");
        assert!(!ciphertext.is_empty());

        let plaintext: Vec<u64> = unwrap!(
            sk.decrypt_anonymous(&ciphertext),
            "couldn't decrypt ciphertext"
        );
        assert_eq!(plaintext, data);
    }

    #[test]
    fn authenticated_cipher() {
        let data = generate_random_bytes(50);

        let sk1 = SecretKeys::new();
        let pk1 = sk1.public_keys();

        let sk2 = SecretKeys::new();
        let pk2 = sk2.public_keys();

        let shared_sk1 = sk1.shared_secret(&pk2);
        let shared_sk2 = sk2.shared_secret(&pk1);

        let ciphertext = unwrap!(shared_sk1.encrypt_bytes(&data), "couldn't encrypt data");
        assert_ne!(&ciphertext, &data);

        let plaintext = unwrap!(
            shared_sk2.decrypt_bytes(&ciphertext),
            "couldn't decrypt data"
        );
        assert_eq!(&plaintext, &data);

        // Trying with wrong data
        let error_res: Result<_, _> = shared_sk2.decrypt_bytes(&plaintext);
        match error_res {
            Err(_e) => (),
            Ok(_) => panic!(
                "Unexpected result: we're using wrong data, it should have returned an error"
            ),
        }

        // Trying with a wrong key
        let sk3 = SecretKeys::new();
        let shared_sk3 = sk3.shared_secret(&pk2);

        let error_res = shared_sk3.decrypt_bytes(&ciphertext);
        match error_res {
            Err(_e) => (),
            Ok(_) => panic!(
                "Unexpected result: we're using a wrong key, it should have returned an error"
            ),
        }
    }

    #[test]
    fn signing() {
        let data1 = generate_random_bytes(50);
        let data2 = generate_random_bytes(50);

        let sk1 = SecretKeys::new();
        let pk1 = sk1.public_keys();

        let sk2 = SecretKeys::new();
        let pk2 = sk2.public_keys();

        let sig1 = sk1.sign_detached(&data1);
        let sig2 = sk2.sign_detached(&data2);

        assert!(pk1.verify_detached(&sig1, &data1));
        assert!(!pk1.verify_detached(&sig1, &data2));
        assert!(!pk1.verify_detached(&sig2, &data1));
        assert!(!pk1.verify_detached(&sig2, &data2));

        assert!(!pk2.verify_detached(&sig1, &data1));
        assert!(!pk2.verify_detached(&sig1, &data2));
        assert!(!pk2.verify_detached(&sig2, &data1));
        assert!(pk2.verify_detached(&sig2, &data2));
    }

    #[test]
    fn symmetric() {
        let data = generate_random_bytes(50);

        let sk1 = SymmetricKey::new();
        let sk2 = SymmetricKey::new();

        let ciphertext = unwrap!(sk1.encrypt_bytes(&data), "could not encrypt data");
        let plaintext = unwrap!(sk1.decrypt_bytes(&ciphertext), "could not decrypt data");

        assert_eq!(plaintext, data);

        // Try to decrypt the ciphertext with an incorrect key
        match sk2.decrypt_bytes(&ciphertext) {
            Err(_) => (),
            Ok(_) => panic!(
                "Unexpected result: we're using a wrong key, it should have returned an error"
            ),
        }

        // Try to use automatic serialisation/deserialisation
        let mut os_rng = unwrap!(OsRng::new());
        let data: Vec<u64> = os_rng.gen_iter().take(32).collect();

        let ciphertext = unwrap!(sk2.encrypt(&data), "could not encrypt data");
        let plaintext: Vec<u64> = unwrap!(sk2.decrypt(&ciphertext), "could not decrypt data");

        assert_eq!(plaintext, data);
    }

    #[cfg(feature = "mock")]
    #[test]
    fn name() {
        let sk1 = SecretKeys::new();
        let pk1 = sk1.public_keys();
        assert_eq!(
            &pk1.public_sign_key(),
            &[pk1.sign.0, pk1.sign.0, pk1.sign.0, pk1.sign.0].concat()[0..PUBLIC_SIGN_KEY_SIZE]
        );
    }

    #[test]
    fn hashes() {
        let mut data = generate_random_bytes(10);
        let data2 = generate_random_bytes(10);

        let h1 = hash(&data);

        assert_eq!(h1, hash(&data));
        assert_ne!(h1, hash(&data2));

        data.push(1);
        assert_ne!(h1, hash(&data));
    }

    #[test]
    fn symmetric_serialise() {
        let data = generate_random_bytes(50);

        let sk = SymmetricKey::new();
        let ciphertext = unwrap!(sk.encrypt_bytes(&data), "could not encrypt data");
        let serialised_sk = unwrap!(serialise(&sk), "could not serialise key");

        // Try to decrypt the ciphertext with an incorrect key
        let sk = SymmetricKey::new();

        match sk.decrypt_bytes(&ciphertext) {
            Err(_) => (),
            Ok(_) => panic!(
                "Unexpected result: we're using a wrong key, it should have returned an error"
            ),
        }

        // Deserialise key
        let sk: SymmetricKey = unwrap!(deserialise(&serialised_sk), "could not deserialise key");
        let plaintext = unwrap!(sk.decrypt_bytes(&ciphertext), "could not decrypt data");

        assert_eq!(plaintext, data);
    }

    fn generate_random_bytes(length: usize) -> Vec<u8> {
        let mut os_rng = unwrap!(OsRng::new());
        os_rng
            .gen_iter::<char>()
            .filter(|c| *c != '\u{0}')
            .take(length)
            .collect::<String>()
            .into_bytes()
    }
}
