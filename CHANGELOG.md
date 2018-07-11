# safe_crypto - Change Log

## [0.2.0]
- Rename publicly exported structures and functions to better represent their intended use:
  * `PublicId` -> `PublicKeys`, `PublicId::name()` -> `PublicKeys::public_sign_key()`.
  * `SecretId` -> `SecretKeys`, `SecretId::public_id()` -> `SecretId::public_keys()`.
  * `EncryptionError` -> `Error`.
- Rename feature `use-mock-crypto` to `mock`.
- Add the hashing function `hash` to the public API (along with a mock version).
- Add fast pseudo-random generator `SeededRng` to be used along with the mock crypto.

## [0.1.0]
- Initial implementation
- Implement the basic encryption features for asymmetric anonymous and authenticated encryption.
- Implement the detached signature and verification functions.
- Implement the symmetric encryption functions.
- Implement the mock-crypto version of the library for testing purposes.
