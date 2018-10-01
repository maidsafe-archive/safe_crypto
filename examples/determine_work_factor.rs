// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

//! Displays the average amount of time required for key derivation on the current machine, using
//! work factor log(N) ranging from 0 to 25. Must be run in Release mode for an accurate gauge.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
    html_favicon_url = "https://maidsafe.net/img/favicon.ico",
    test(attr(forbid(warnings))),
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

extern crate safe_crypto;

use std::time::Instant;

fn main() -> Result<(), safe_crypto::Error> {
    const WORK_FACTOR_MAX: u8 = 22;
    const NUM_ITERATIONS: usize = 5;

    for log_n in 0..WORK_FACTOR_MAX + 1 {
        let start = Instant::now();

        for _ in 0..NUM_ITERATIONS {
            let password = b"typicalpassword";
            let salt = b"typicalsalt";
            let mut output = [0; safe_crypto::SYMMETRIC_KEY_BYTES];

            safe_crypto::derive_key_from_pw(password, salt, Some(log_n), &mut output)?;
        }

        let average = start.elapsed() / NUM_ITERATIONS as u32;

        println!(
            "{}: {} secs",
            log_n,
            average.as_secs() as f64 + f64::from(average.subsec_millis()) * 1e-3
        );
    }

    Ok(())
}
