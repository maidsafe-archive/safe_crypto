# safe_crypto - Change Log

## [0.3.0]
- Use rust 1.28.0 stable / 2018-07-07 nightly
- rustfmt 0.99.2 and clippy-0.0.212
- Split types to map 1-to-1 with low libraries to make it more versatile and
  better suit downstream dependants.
  * `PublicSignKey`
  * `SecretSignKey`
  * `PublicEncryptKey`
  * `SecretEncryptKey`
  * `SymmetricKey`
  * `Signature`
- Implement `Display` for public keys.
- Add more `into_bytes` and `from_bytes` functions.

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
