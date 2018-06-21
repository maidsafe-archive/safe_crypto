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
struct CipherText {
    nonce: box_::Nonce,
    ciphertext: Vec<u8>,
}

impl PublicId {
    pub fn encrypt_anonymous<T>(&self, plaintext: &T) -> Result<Vec<u8>, EncryptionError>
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

    pub fn decrypt_anonymous<T>(&self, cyphertext: &[u8]) -> Result<T, EncryptionError>
    where
        T: Serialize + DeserializeOwned,
    {
        Ok(deserialise(&self.decrypt_anonymous_bytes(cyphertext)?)?)
    }

    pub fn decrypt_anonymous_bytes(&self, cyphertext: &[u8]) -> Result<Vec<u8>, EncryptionError> {
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
    pub fn encrypt_bytes(&self, plaintext: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        let nonce = box_::gen_nonce();
        let ciphertext = box_::seal_precomputed(plaintext, &nonce, &self.precomputed);
        Ok(serialise(&CipherText { nonce, ciphertext })?)
    }

    pub fn encrypt<T>(&self, plaintext: &T) -> Result<Vec<u8>, EncryptionError>
    where
        T: Serialize,
    {
        self.encrypt_bytes(&serialise(plaintext)?)
    }

    pub fn decrypt_bytes(&self, encoded: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        let CipherText { nonce, ciphertext } = deserialise(encoded)?;
        Ok(box_::open_precomputed(
            &ciphertext,
            &nonce,
            &self.precomputed,
        )?)
    }

    pub fn decrypt<T>(&self, cyphertext: &[u8]) -> Result<T, EncryptionError>
    where
        T: Serialize + DeserializeOwned,
    {
        Ok(deserialise(&self.decrypt_bytes(cyphertext)?)?)
    }
}

quick_error! {
    #[derive(Debug)]
    pub enum EncryptionError {
        Serialisation(e: SerialisationError) {
            description("error serialising or deserialising message")
            display("error serialising or deserialising message: {}", e)
            cause(e)
            from()
        }
        DecryptVerify(_e: ()) {
            description("error decrypting/verifying message")
            from()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anonymous_bytes_cipher() {
        let data = b"Humpty Dumpty sat on a wall";
        let sk = SecretId::new();
        let sk2 = SecretId::new();
        let pk = sk.public_id();

        let ciphertext = pk.encrypt_anonymous_bytes(data);
        assert!(&ciphertext != data);

        let error_res: Result<_, _> = sk.decrypt_anonymous_bytes(data);
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

        let plaintext: Vec<u8> = sk
            .decrypt_anonymous_bytes(&ciphertext)
            .expect("couldn't decrypt ciphertext");
        assert!(&plaintext == data);
    }

    #[test]
    fn anonymous_cipher() {
        let data: Vec<u64> = vec![4, 5, 6];

        let sk = SecretId::new();
        let pk = sk.public_id();

        let ciphertext = pk
            .encrypt_anonymous(&data)
            .expect("couldn't encrypt base data");
        assert!(!ciphertext.is_empty());

        let plaintext: Vec<u64> = sk
            .decrypt_anonymous(&ciphertext)
            .expect("couldn't decrypt ciphertext");
        assert!(plaintext == data);
    }

    #[test]
    fn authenticated_cipher() {
        let data = b"Humpty Dumpty had a great fall.";

        let sk1 = SecretId::new();
        let pk1 = sk1.public_id();

        let sk2 = SecretId::new();
        let pk2 = sk2.public_id();

        let shared_key1 = sk1.shared_key(&pk2);
        let shared_key2 = sk2.shared_key(&pk1);

        let ciphertext = shared_key1
            .encrypt_bytes(data)
            .expect("couldn't encrypt data");
        assert!(&ciphertext != data);

        let plaintext = shared_key2
            .decrypt_bytes(&ciphertext)
            .expect("couldn't decrypt data");
        assert!(&plaintext == data);

        // Trying with wrong data
        let error_res: Result<_, _> = shared_key2.decrypt_bytes(&plaintext);
        match error_res {
            Err(_e) => (),
            Ok(_) => {
                panic!("Unexpected result: we're using wrong data, it should have returned error")
            }
        }

        // Trying with a wrong key
        let sk3 = SecretId::new();
        let shared_key3 = sk3.shared_key(&pk2);

        let error_res: Result<_, _> = shared_key3.decrypt_bytes(&ciphertext);
        match error_res {
            Err(_e) => (),
            Ok(_) => {
                panic!("Unexpected result: we're using a wrong key, it should have returned error")
            }
        }
    }

    #[test]
    fn signing() {
        let data1 = b"All the king's horses and all the king's men";
        let data2 = b"Couldn't put Humpty together again";

        let sk1 = SecretId::new();
        let pk1 = sk1.public_id();

        let sk2 = SecretId::new();
        let pk2 = sk2.public_id();

        let sig1 = sk1.sign_detached(data1);
        let sig2 = sk2.sign_detached(data2);

        assert_eq!(pk1.verify_detached(&sig1, data1), true);
        assert_eq!(pk1.verify_detached(&sig1, data2), false);
        assert_eq!(pk1.verify_detached(&sig2, data1), false);
        assert_eq!(pk1.verify_detached(&sig2, data2), false);

        assert_eq!(pk2.verify_detached(&sig1, data1), false);
        assert_eq!(pk2.verify_detached(&sig1, data2), false);
        assert_eq!(pk2.verify_detached(&sig2, data1), false);
        assert_eq!(pk2.verify_detached(&sig2, data2), true);
    }
}
