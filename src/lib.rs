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
    exceeding_bitshifts,
    mutable_transmutes,
    no_mangle_const_items,
    unknown_crate_types,
    warnings
)]
#![deny(
    bad_style,
    deprecated,
    improper_ctypes,
    missing_docs,
    non_shorthand_field_patterns,
    overflowing_literals,
    plugin_as_library,
    private_no_mangle_fns,
    private_no_mangle_statics,
    stable_features,
    unconditional_recursion,
    unknown_lints,
    unsafe_code,
    unused,
    unused_allocation,
    unused_attributes,
    unused_comparisons,
    unused_features,
    unused_parens,
    while_true
)]
#![warn(
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results
)]
#![allow(
    box_pointers,
    missing_copy_implementations,
    missing_debug_implementations,
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
use serde::{de::DeserializeOwned, Serialize};
use std::fmt;
use std::sync::Arc;

const PUBLIC_ENCRYPT_KEY_BYTES: usize = box_::PUBLICKEYBYTES;
const SECRET_ENCRYPT_KEY_BYTES: usize = box_::SECRETKEYBYTES;
const PUBLIC_SIGN_KEY_BYTES: usize = sign::PUBLICKEYBYTES;
const SECRET_SIGN_KEY_BYTES: usize = sign::SECRETKEYBYTES;
const SHARED_SECRET_KEY_BYTES: usize = box_::PRECOMPUTEDKEYBYTES;
const SIGNATURE_BYTES: usize = sign::SIGNATUREBYTES;
const SYMMETRIC_KEY_BYTES: usize = secretbox::KEYBYTES;

quick_error! {
    /// This error is returned if encryption or decryption fails.
    /// The encryption failure is rare and mostly connected to serialisation failures.
    /// Decryption can fail because of invalid keys, invalid data, or deserialisation failures.
    #[derive(Debug)]
    pub enum Error {
        /// Occurs when serialisation or deserialisation fails.
        Serialisation(e: SerialisationError) {
            display("error serialising or deserialising message: {}", e)
            cause(e)
            from()
        }
        /// Occurs when we can't decrypt a message or verify the signature.
        DecryptVerify(_e: ()) {
            display("error decrypting/verifying message")
            from()
        }
        /// Occurs in case of an error during initialisation.
        InitError(e: i32) {
            display("error while initialising safe_crypto")
            from()
        }
        /// Occurs when we fail to derive encryption key from password.
        DeriveKey {
            display("error deriving encryption key from password")
        }
    }
}

/// Initialise safe_crypto including the random number generator for the key generation functions.
pub fn init() -> Result<(), Error> {
    crypto_impl::init().map_err(|_| Error::InitError(-1))
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

/// The public key used encrypt data that can only be decrypted by the corresponding secret key,
/// which is represented by `SecretEncryptKey`.
/// Use `gen_encrypt_keypair()` to generate a public and secret key pair.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Clone)]
pub struct PublicEncryptKey {
    encrypt: box_::PublicKey,
}

impl PublicEncryptKey {
    /// Construct public key from bytes. Useful when it was serialised before.
    pub fn from_bytes(public_key: [u8; PUBLIC_ENCRYPT_KEY_BYTES]) -> Self {
        Self {
            encrypt: box_::PublicKey(public_key),
        }
    }

    /// Convert the `PublicEncryptKey` into the raw underlying bytes.
    /// For anyone who wants to store the public key.
    pub fn into_bytes(self) -> [u8; PUBLIC_ENCRYPT_KEY_BYTES] {
        self.encrypt.0
    }

    /// Encrypts serialisable `plaintext` using anonymous encryption.
    ///
    /// Anonymous encryption will use an ephemeral public key, so the recipient won't
    /// be able to tell who sent the ciphertext.
    /// If you wish to encrypt bytestring plaintext, use `anonymously_encrypt_bytes`.
    /// To use authenticated encryption, use `SharedSecretKey`.
    ///
    /// Returns ciphertext in case of success.
    /// Can return an `Error` in case of a serialisation error.
    pub fn anonymously_encrypt<T>(&self, plaintext: &T) -> Result<Vec<u8>, Error>
    where
        T: Serialize,
    {
        Ok(self.anonymously_encrypt_bytes(&serialise(plaintext)?))
    }

    /// Encrypts bytestring `plaintext` using anonymous encryption.
    ///
    /// Anonymous encryption will use an ephemeral public key, so the recipient won't
    /// be able to tell who sent the ciphertext.
    /// To use authenticated encryption, use `SharedSecretKey`.
    ///
    /// Returns ciphertext in case of success.
    pub fn anonymously_encrypt_bytes(&self, plaintext: &[u8]) -> Vec<u8> {
        sealedbox::seal(plaintext, &self.encrypt)
    }
}

/// Reference counted secret encryption key used to decrypt data previously encrypted with
/// `PublicEncryptKey`.
/// Use `gen_encrypt_keypair()` to generate a public and secret key pair.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub struct SecretEncryptKey {
    inner: Arc<SecretEncryptKeyInner>,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct SecretEncryptKeyInner {
    encrypt: box_::SecretKey,
}

impl SecretEncryptKey {
    /// Construct secret key from given bytes. Useful when secret key was serialised before.
    pub fn from_bytes(secret_key: [u8; SECRET_ENCRYPT_KEY_BYTES]) -> Self {
        Self {
            inner: Arc::new(SecretEncryptKeyInner {
                encrypt: box_::SecretKey(secret_key),
            }),
        }
    }

    /// Computes a shared secret from our secret key and the recipient's public key.
    pub fn shared_secret(&self, their_pk: &PublicEncryptKey) -> SharedSecretKey {
        let precomputed = Arc::new(box_::precompute(&their_pk.encrypt, &self.inner.encrypt));
        SharedSecretKey { precomputed }
    }

    /// Get the inner secret key representation.
    pub fn into_bytes(self) -> [u8; SECRET_ENCRYPT_KEY_BYTES] {
        self.inner.encrypt.0
    }

    /// Decrypts serialised `ciphertext` encrypted using anonymous encryption.
    ///
    /// With anonymous encryption we won't be able to verify the sender and
    /// tell who sent the ciphertext.
    ///
    /// Returns deserialised type `T` in case of success.
    /// Can return `Error` in case of a deserialisation error, if the ciphertext is
    /// not valid, or if it can not be decrypted.
    pub fn anonymously_decrypt<T>(
        &self,
        ciphertext: &[u8],
        my_pk: &PublicEncryptKey,
    ) -> Result<T, Error>
    where
        T: Serialize + DeserializeOwned,
    {
        Ok(deserialise(
            &self.anonymously_decrypt_bytes(ciphertext, my_pk)?,
        )?)
    }

    /// Decrypts bytestring `ciphertext` encrypted using anonymous encryption.
    ///
    /// With anonymous encryption we won't be able to verify the sender and
    /// tell who sent the ciphertext.
    ///
    /// Returns plaintext in case of success.
    /// Can return `Error` if the ciphertext is not valid or if it can not be decrypted.
    pub fn anonymously_decrypt_bytes(
        &self,
        ciphertext: &[u8],
        my_pk: &PublicEncryptKey,
    ) -> Result<Vec<u8>, Error> {
        Ok(sealedbox::open(
            ciphertext,
            &my_pk.encrypt,
            &self.inner.encrypt,
        )?)
    }
}

/// Randomly generates a secret key and a corresponding public key.
pub fn gen_encrypt_keypair() -> (PublicEncryptKey, SecretEncryptKey) {
    let (encrypt_pk, encrypt_sk) = box_::gen_keypair();
    let pub_enc_key = PublicEncryptKey {
        encrypt: encrypt_pk,
    };
    let sec_enc_key = SecretEncryptKey {
        inner: Arc::new(SecretEncryptKeyInner {
            encrypt: encrypt_sk,
        }),
    };
    (pub_enc_key, sec_enc_key)
}

/// Public signing key used to verify that the signature appended to a message was actually issued
/// by the creator of the public key.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Clone)]
pub struct PublicSignKey {
    sign: sign::PublicKey,
}

impl PublicSignKey {
    /// Verifies the detached `signature`.
    ///
    /// Returns `true` if the signature is valid the `data` is verified.
    pub fn verify_detached(&self, signature: &Signature, data: &[u8]) -> bool {
        sign::verify_detached(&signature.signature, data, &self.sign)
    }

    /// Construct from bytes. Useful when it was serialised before.
    pub fn from_bytes(public_key: [u8; PUBLIC_SIGN_KEY_BYTES]) -> Self {
        Self {
            sign: sign::PublicKey(public_key),
        }
    }

    /// Convert the `PublicSignKey` into the raw underlying bytes.
    /// For anyone who wants to store the public signing key.
    pub fn into_bytes(self) -> [u8; PUBLIC_SIGN_KEY_BYTES] {
        self.sign.0
    }
}

/// Reference counted secret signing key used to verify signatures previously signed with
/// `PublicSignKey`.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub struct SecretSignKey {
    inner: Arc<SecretSignKeyInner>,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct SecretSignKeyInner {
    sign: sign::SecretKey,
}

impl SecretSignKey {
    /// Construct from bytes. Useful when it was serialised before.
    pub fn from_bytes(secret_key: [u8; SECRET_SIGN_KEY_BYTES]) -> Self {
        Self {
            inner: Arc::new(SecretSignKeyInner {
                sign: sign::SecretKey(secret_key),
            }),
        }
    }

    /// Get the inner secret key representation.
    pub fn into_bytes(self) -> [u8; SECRET_SIGN_KEY_BYTES] {
        self.inner.sign.0
    }

    /// Produces the detached signature from the `data`.
    ///
    /// Afterwards the returned `Signature` can be used to verify the authenticity of `data`.
    pub fn sign_detached(&self, data: &[u8]) -> Signature {
        Signature {
            signature: sign::sign_detached(data, &self.inner.sign),
        }
    }
}

/// Construct random public and secret signing key pair.
pub fn gen_sign_keypair() -> (PublicSignKey, SecretSignKey) {
    let (sign_pk, sign_sk) = sign::gen_keypair();
    let pub_sign_key = PublicSignKey { sign: sign_pk };
    let sec_sign_key = SecretSignKey {
        inner: Arc::new(SecretSignKeyInner { sign: sign_sk }),
    };
    (pub_sign_key, sec_sign_key)
}

/// Precomputed shared secret key.
///
/// Can be created from a pair of our secret key and the recipient's public key.
/// As a result, we'll get the same key as the recipient with their secret key and
/// our public key.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub struct SharedSecretKey {
    precomputed: Arc<box_::PrecomputedKey>,
}

impl SharedSecretKey {
    /// Construct shared secret key from bytes. Useful when it was serialised before.
    pub fn from_bytes(key: [u8; SHARED_SECRET_KEY_BYTES]) -> Self {
        Self {
            precomputed: Arc::new(box_::PrecomputedKey(key)),
        }
    }

    /// Convert the `SharedSecretKey` into the raw underlying bytes.
    /// For anyone who wants to store the shared secret key
    pub fn into_bytes(self) -> [u8; SHARED_SECRET_KEY_BYTES] {
        self.precomputed.0
    }

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

/// Detached signature.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Clone)]
pub struct Signature {
    signature: sign::Signature,
}

impl Signature {
    /// Construct the signature from bytes. Useful when it was serialised before.
    pub fn from_bytes(key: [u8; SIGNATURE_BYTES]) -> Self {
        Self {
            signature: sign::Signature(key),
        }
    }

    /// Return the signature as an array of bytes
    pub fn into_bytes(self) -> [u8; SIGNATURE_BYTES] {
        self.signature.0
    }
}

/// Secret key for authenticated symmetric encryption.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub struct SymmetricKey {
    encrypt: Arc<secretbox::Key>,
}

impl SymmetricKey {
    /// Generates a new symmetric key.
    pub fn new() -> Self {
        let sk = secretbox::gen_key();
        Self {
            encrypt: Arc::new(sk),
        }
    }

    /// Create a symmetric key from bytes. Useful when it has been serialised.
    pub fn from_bytes(key: [u8; SYMMETRIC_KEY_BYTES]) -> Self {
        Self {
            encrypt: Arc::new(secretbox::Key(key)),
        }
    }

    /// Convert the `SharedSecretKey` into the raw underlying bytes.
    /// For anyone who wants to store the symmetric key
    pub fn into_bytes(self) -> [u8; SYMMETRIC_KEY_BYTES] {
        self.encrypt.0
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

    /// Encrypts bytestring `plaintext` using authenticated symmetric encryption.
    ///
    /// With authenticated encryption the recipient will be able to confirm that the message
    /// is untampered with.
    ///
    /// Returns ciphertext in case of success.
    /// Can return an `Error` in case of a serialisation error.
    pub fn encrypt_bytes(&self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let nonce = secretbox::gen_nonce();
        let ciphertext = secretbox::seal(plaintext, &nonce, &self.encrypt);
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

    /// Decrypts bytestring `ciphertext` encrypted using authenticated symmetric encryption.
    ///
    /// With authenticated encryption we will be able to tell that the message hasn't been
    /// tampered with.
    ///
    /// Returns plaintext in case of success.
    /// Can return `Error` in case of a deserialisation error, if the ciphertext
    /// is not valid, or if it can not be decrypted.
    pub fn decrypt_bytes(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let CipherText { nonce, ciphertext } = deserialise(ciphertext)?;
        Ok(secretbox::open(
            &ciphertext,
            &secretbox::Nonce(nonce),
            &self.encrypt,
        )?)
    }
}

impl Default for SymmetricKey {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Serialize, Deserialize)]
struct CipherText {
    nonce: [u8; box_::NONCEBYTES],
    ciphertext: Vec<u8>,
}

impl fmt::Display for PublicEncryptKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:02x}{:02x}{:02x}..",
            &self.encrypt.0[0], &self.encrypt.0[1], &self.encrypt.0[2]
        )
    }
}

impl fmt::Display for PublicSignKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:02x}{:02x}{:02x}..",
            &self.sign.0[0], &self.sign.0[1], &self.sign.0[2]
        )
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:02x}{:02x}{:02x}..",
            &self.signature.0[0], &self.signature.0[1], &self.signature.0[2]
        )
    }
}

#[cfg(test)]
mod tests {
    use self::rand::{OsRng, Rng};
    use super::*;

    #[test]
    fn anonymous_bytes_cipher() {
        let data = generate_random_bytes(50);
        let (pk, sk) = gen_encrypt_keypair();
        let (pk2, sk2) = gen_encrypt_keypair();

        let ciphertext = pk.anonymously_encrypt_bytes(&data);
        assert_ne!(&ciphertext, &data);

        let error_res = sk.anonymously_decrypt_bytes(&data, &pk);
        match error_res {
            Err(_e) => (),
            Ok(_) => {
                panic!("Unexpected result: we're using wrong data, it should have returned error")
            }
        }

        let error_res: Result<_, _> = sk2.anonymously_decrypt_bytes(&ciphertext, &pk2);
        match error_res {
            Err(_e) => (),
            Ok(_) => {
                panic!("Unexpected result: we're using a wrong key, it should have returned error")
            }
        }

        let plaintext: Vec<u8> = unwrap!(
            sk.anonymously_decrypt_bytes(&ciphertext, &pk),
            "couldn't decrypt ciphertext"
        );
        assert_eq!(&plaintext, &data);
    }

    #[test]
    fn anonymous_cipher() {
        let mut os_rng = unwrap!(OsRng::new());
        let data: Vec<u64> = os_rng.gen_iter().take(32).collect();

        let (pk, sk) = gen_encrypt_keypair();

        let ciphertext = unwrap!(pk.anonymously_encrypt(&data), "couldn't encrypt base data");
        assert!(!ciphertext.is_empty());

        let plaintext: Vec<u64> = unwrap!(
            sk.anonymously_decrypt(&ciphertext, &pk),
            "couldn't decrypt ciphertext"
        );
        assert_eq!(plaintext, data);
    }

    #[test]
    fn authenticated_cipher() {
        let data = generate_random_bytes(50);

        let (pk1, sk1) = gen_encrypt_keypair();
        let (pk2, sk2) = gen_encrypt_keypair();

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
        let (_, sk3) = gen_encrypt_keypair();
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

        let (pk1, sk1) = gen_sign_keypair();
        let (pk2, sk2) = gen_sign_keypair();

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
