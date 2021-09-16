// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

//! Different MaidSafe tools need different crypto primitives. E.g. Crust only uses encryption
//! public/private keys, Routing uses encryption and signing public/private keys, etc.
//! Currently in some cases safe_crypto is unusable cause it doesn't expose some internal data like
//! private keys, etc.
//! One way to solve this and stay super flexible is to have 1-to-1 mappings with lower level
//! crypto types from rust_sodium, miscreant, etc.
//! This document attempts to catch safe_crypto design that would work for all our our cases.
//!
//! `PublicKeys` and `SecretKeys` currently contain both signing and encryption keys. In some
//! cases, we don't need signing key at all, e.g. in Crust. So this document proposes to split
//! `PublicKeys` and `SecretKeys` into corresponding types: `PublicEncryptKey, `SecretEncryptKey`,
//! `PublicSignKey` and `SecretSignKey`.

// whatever is defined in the underlying crypto library
const PUBLIC_ENCRYPT_KEY_BYTES: usize = rust_sodium::crypto::box_::PUBLICKEYBYTES;
const SECRET_ENCRYPT_KEY_BYTES: usize = rust_sodium::crypto::sign::SECRETKEYBYTES;
const PUBLIC_SIGN_KEY_BYTES: usize = rust_sodium::crypto::sign::PUBLICKEYBYTES;
const SECRET_SIGN_KEY_BYTES: usize = rust_sodium::crypto::sign::SECRETKEYBYTES;
const SHARED_SECRET_KEY_BYTES: usize = XXX;
const SIGNATURE_BYTES: usize = XXX;
const SYMMETRIC_KEY_BYTES: usize = XXX;

quick_error! {
    /// This error is returned if encryption or decryption fail.
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
            display("error while initialising random generator")
            from()
        }
        /// Occurs when we fail to derive encryption key from password.
        DeriveKey {
            display("error deriving encryption key from password")
        }
    }
}

/// Derives encryption key from plaintext password.
pub fn key_from_password(password: &[u8], salt: &[u8]) -> Result<SymmetricKey, Error>;

/// Use `encrypt_key_pair()` to generate public and private keys pair.
// Make it `Copy`able?
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Clone)]
pub struct PublicEncryptKey {
    encrypt: box_::PublicKey,
}

impl PublicEncryptKey {
    /// Construct public key from bytes. Useful when it was serialized before.
    pub fn from_bytes(public_key: [u8; PUBLIC_ENCRYPT_KEY_BYTES]) -> Self

    /// For anyone who wants to store public key.
    pub fn as_bytes(self) -> [u8; PUBLIC_ENCRYPT_KEY_BYTES]

    pub fn encrypt_anonymous<T: Serialize>(&self, plaintext: &T) -> Result<Vec<u8>, Error>

    pub fn encrypt_anonymous_bytes(&self, plaintext: &[u8]) -> Vec<u8> {
}

/// Store secret key in `Arc` to discourage cloning it. Makes it more secure by not duplicating
/// encryption keys in memory.
/// Use `encrypt_key_pair()` to generate public and private keys pair.
// NOTE, serde by default doesn't allow to serialize `Arc`. We have to enable this feature
// explicitly: `serde = { version = "~1.0.66", features = ["rc"] }`
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub struct SecretEncryptKey {
    inner: Arc<SecretEncryptKeyInner>,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct SecretEncryptKeyInner {
    encrypt: box_::SecretKey,
}

impl SecretEncryptKey {
    /// Construct secret key from given bytes. Useful when secret key was serialized before.
    pub fn from_bytes(secret_key: [u8; SECRET_ENCRYPT_KEY_BYTES]) -> Self

    /// Derive shared key for symmetric data encryption
    pub fn shared_secret(&self, their_pk: &PublicEncryptKey) -> SharedSecretKey

    /// For anyone who wants to store secret key.
    pub fn as_bytes(self) -> [u8; SECRET_ENCRYPT_KEY_BYTES]

    pub fn decrypt_anonymous<T: Serialize + DeserializeOwned>(&self, ciphertext: &[u8], my_pk: &PublicEncryptKey) -> Result<T, Error>

    pub fn decrypt_anonymous_bytes(&self, ciphertext: &[u8], my_pk: &PublicEncryptKey) -> Result<Vec<u8>, Error>
}

/// Randomly generates a secret key and a corresponding public key.<Paste>
pub fn encrypt_key_pair() -> (PublicEncryptKey, SecretEncryptKey)

#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Clone)]
pub struct PublicSignKey {
    sign: sign::PublicKey,
}

impl PublicSignKey {
    pub fn verify_detached(&self, signature: &Signature, data: &[u8]) -> bool {

    pub fn from_bytes(public_key: [u8; PUBLIC_SIGN_KEY_BYTES]) -> Self

    pub fn as_bytes(self) -> [u8; PUBLIC_SIGN_KEY_BYTES]
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub struct SecretSignKey {
    inner: Arc<SecretSignKeyInner>,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct SecretSignKeyInner {
    encrypt: sign::SecretKey,
}

impl SecretSignKey {
    pub fn from_bytes(secret_key: [u8; SECRET_SIGN_KEY_BYTES]) -> Self

    pub fn as_bytes(self) -> [u8; SECRET_SIGN_KEY_BYTES]

    pub fn sign_detached(&self, data: &[u8]) -> Signature {
}

/// Construct random public/private signing key pair.
pub fn sign_key_pair() -> (PublicSignKey, SecretSignKey)


//! Types that remain intact as in https://github.com/maidsafe/safe_crypto/blob/f214410/src/lib.rs:
//! SharedSecretKey
//! Signature
//! SymmetricKey
//!
//! except for `from_bytes()`/`as_bytes()` and `Serialize/Deserialize` implementations.

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub struct SharedSecretKey {
    precomputed: Arc<box_::PrecomputedKey>,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub struct SharedSecretKey {
    precomputed: Arc<box_::PrecomputedKey>,
}

impl SharedSecretKey {
    pub fn from_bytes(key: [u8; SHARED_SECRET_KEY_BYTES]) -> Self
    pub fn as_bytes(self) -> [u8; SHARED_SECRET_KEY_BYTES]
}

impl Signature {
    pub fn from_bytes(key: [u8; SIGNATURE_BYTES]) -> Self
    pub fn as_bytes(self) -> [u8; SIGNATURE_BYTES]
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub struct SymmetricKey {
    encrypt: Arc<secretbox::Key>,
}

impl SymmetricKey {
    pub fn from_bytes(key: [u8; SYMMETRIC_KEY_BYTES]) -> Self
    pub fn as_bytes(self) -> [u8; SYMMETRIC_KEY_BYTES]
}
