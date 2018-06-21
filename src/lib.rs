// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

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
// TODO - remove
#![allow(missing_docs)]

extern crate maidsafe_utilities;
extern crate rust_sodium;
extern crate serde;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate quick_error;

use maidsafe_utilities::serialisation::{deserialise, serialise, SerialisationError};
use rust_sodium::crypto::{box_, sealedbox, sign};
use serde::{de::DeserializeOwned, Serialize};
use std::sync::Arc;

#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Clone)]
pub struct PublicId {
    sign: sign::PublicKey,
    encrypt: box_::PublicKey,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SecretId {
    inner: Arc<SecretIdInner>,
    public: PublicId,
}

#[derive(Debug, PartialEq, Eq)]
struct SecretIdInner {
    sign: sign::SecretKey,
    encrypt: box_::SecretKey,
}

#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Clone)]
pub struct Signature {
    signature: sign::Signature,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SharedSecretKey {
    precomputed: Arc<box_::PrecomputedKey>,
}

#[derive(Serialize, Deserialize)]
struct PackedNonce {
    nonce: box_::Nonce,
    ciphertext: Vec<u8>,
}

impl PublicId {
    pub fn encrypt_anonymous<T>(&self, plaintext: &T) -> Result<Vec<u8>, EncryptError>
    where
        T: Serialize,
    {
        Ok(self.encrypt_anonymous_bytes(&serialise(plaintext)?))
    }

    pub fn encrypt_anonymous_bytes(&self, plaintext: &[u8]) -> Vec<u8> {
        sealedbox::seal(plaintext, &self.encrypt)
    }

    pub fn verify_detached(&self, signature: &Signature, data: &[u8]) -> bool {
        sign::verify_detached(&signature.signature, data, &self.sign)
    }
}

impl SecretId {
    pub fn new() -> SecretId {
        let (sign_pk, sign_sk) = sign::gen_keypair();
        let (encrypt_pk, encrypt_sk) = box_::gen_keypair();
        let public = PublicId {
            sign: sign_pk,
            encrypt: encrypt_pk,
        };
        SecretId {
            public,
            inner: Arc::new(SecretIdInner {
                sign: sign_sk,
                encrypt: encrypt_sk,
            }),
        }
    }

    pub fn public_id(&self) -> &PublicId {
        &self.public
    }

    pub fn decrypt_anonymous<T>(&self, cyphertext: &[u8]) -> Result<T, DecryptError>
    where
        T: Serialize + DeserializeOwned,
    {
        Ok(deserialise(&self.decrypt_anonymous_bytes(cyphertext)?)?)
    }

    pub fn decrypt_anonymous_bytes(&self, cyphertext: &[u8]) -> Result<Vec<u8>, DecryptBytesError> {
        Ok(sealedbox::open(
            cyphertext,
            &self.public.encrypt,
            &self.inner.encrypt,
        )?)
    }

    pub fn sign_detached(&self, data: &[u8]) -> Signature {
        Signature {
            signature: sign::sign_detached(data, &self.inner.sign),
        }
    }

    pub fn shared_key(&self, their_pk: &PublicId) -> SharedSecretKey {
        let precomputed = Arc::new(box_::precompute(&their_pk.encrypt, &self.inner.encrypt));
        SharedSecretKey { precomputed }
    }
}

impl Default for SecretId {
    fn default() -> Self {
        Self::new()
    }
}

impl SharedSecretKey {
    pub fn encrypt_bytes(&self, plaintext: &[u8]) -> Result<Vec<u8>, EncryptError> {
        let nonce = box_::gen_nonce();
        let ciphertext = box_::seal_precomputed(plaintext, &nonce, &self.precomputed);
        Ok(serialise(&PackedNonce { nonce, ciphertext })?)
    }

    pub fn encrypt<T>(&self, plaintext: &T) -> Result<Vec<u8>, EncryptError>
    where
        T: Serialize,
    {
        self.encrypt_bytes(&serialise(plaintext)?)
    }

    pub fn decrypt_bytes(&self, encoded: &[u8]) -> Result<Vec<u8>, DecryptBytesError> {
        let PackedNonce { nonce, ciphertext } = deserialise(encoded)?;
        Ok(box_::open_precomputed(
            &ciphertext,
            &nonce,
            &self.precomputed,
        )?)
    }

    pub fn decrypt<T>(&self, cyphertext: &[u8]) -> Result<T, DecryptError>
    where
        T: Serialize + DeserializeOwned,
    {
        Ok(deserialise(&self.decrypt_bytes(cyphertext)?)?)
    }
}

quick_error! {
    #[derive(Debug)]
    pub enum EncryptError {
        Serialisation(e: SerialisationError) {
            description("error serialising message")
            display("error serialising message: {}", e)
            cause(e)
            from()
        }
    }
}

quick_error! {
    #[derive(Debug)]
    pub enum DecryptError {
        DecryptVerify {
            description("error decrypting/verifying message")
        }
        Deserialisation(e: SerialisationError) {
            description("error deserialising decrypted message")
            display("error deserialising decrypted message: {}", e)
            cause(e)
            from()
        }
    }
}

quick_error! {
    #[derive(Debug)]
    pub enum DecryptBytesError {
        DecryptVerify(_e: ()) {
            description("error decrypting/verifying message")
            from()
        }
        Deserialisation(e: SerialisationError) {
            description("error deserialising decrypted message")
            display("error deserialising decrypted message: {}", e)
            cause(e)
            from()
        }
    }
}

impl From<DecryptBytesError> for DecryptError {
    fn from(error: DecryptBytesError) -> Self {
        match error {
            DecryptBytesError::DecryptVerify(_) => DecryptError::DecryptVerify,
            DecryptBytesError::Deserialisation(e) => DecryptError::Deserialisation(e),
        }
    }
}
