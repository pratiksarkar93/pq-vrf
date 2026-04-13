//! VRF-oriented witness helpers. Core [`crate::witness`] is unchanged.
//!
//! - [`aes_extendedwitness192_vrf`]: **one** OWF192-length extended witness: same key schedule and
//!   prefix as [`crate::witness::aes_extendedwitness`] for OWF192, but the two AES traces encrypt
//!   **`owf_input`** and **`vrf_input`** (not `owf_input` with `input[0] ^= 1` as in stock OWF192).
//!
//! - [`aes_extendedwitness_vrf`]: **concatenates** two full `aes_extendedwitness` outputs (length
//!   `2 * O::LBytes`). Outputs are checked against [`OWFParameters::evaluate_owf`] in debug builds.
//!
//! VRF Quicksilver wiring lives in [`crate::zk_constraints_vrf`] and [`crate::prover_vrf`].
//!
//! ## Structure (see [`crate::witness::aes_extendedwitness`])
//!
//! Non-EM OWF: first **`LambdaBytes`** bytes are raw AES key, then key-schedule non-linear bits, then
//! **`round_with_save`** for each of `Beta` plaintexts. For [`aes_extendedwitness192_vrf`], `Beta = 2`
//! with plaintexts `owf_input` and `vrf_input`.
#![allow(private_bounds, private_interfaces)]

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, vec::Vec};
#[cfg(feature = "std")]
use std::vec::Vec;

use generic_array::{
    GenericArray,
    typenum::{U16, U24, U312, Unsigned},
};

use crate::fields::GF192;
use crate::parameter::{OWF192, OWFParameters};
use crate::witness::{aes_extendedwitness, aes_extendedwitness_two_plaintexts};

/// OWF192 extended witness with **two** AES-192 evaluations on the same `owf_key`: first plaintext
/// `owf_input`, second plaintext `vrf_input` (same layout length as [`crate::witness::aes_extendedwitness`]
/// for [`OWF192`], i.e. [`U312`] bytes — **not** double length).
///
/// This mirrors [`crate::witness::aes_extendedwitness`] for OWF192, except the second block uses
/// `vrf_input` instead of flipping the first byte of `owf_input`.
pub fn aes_extendedwitness192_vrf(
    owf_key: &GenericArray<u8, U24>,
    owf_input: &GenericArray<u8, U16>,
    vrf_input: &GenericArray<u8, U16>,
) -> Box<GenericArray<u8, U312>> {
    aes_extendedwitness_two_plaintexts::<OWF192<GF192>>(owf_key, owf_input, vrf_input)
}

/// Test / harness: checks that [`aes_extendedwitness192_vrf`] output equals `expected_w`.
///
/// Slices must be **`owf_key` 24 B**, **`owf_input` 16 B**, **`second_plaintext` 16 B**,
/// **`expected_w` 312 B** (OWF192 `LBytes`). Returns `false` on length mismatch.
pub fn extend_witness_test_vrf(
    owf_key: &[u8],
    owf_input: &[u8],
    second_plaintext: &[u8],
    expected_w: &[u8],
) -> bool {
    if owf_key.len() != U24::USIZE
        || owf_input.len() != U16::USIZE
        || second_plaintext.len() != U16::USIZE
        || expected_w.len() != U312::USIZE
    {
        return false;
    }
    let wit = aes_extendedwitness192_vrf(
        GenericArray::from_slice(owf_key),
        GenericArray::from_slice(owf_input),
        GenericArray::from_slice(second_plaintext),
    );
    wit.as_slice() == expected_w
}

/// Two concatenated extended witnesses: `aes_extendedwitness(owf_key, owf_input)` then
/// `aes_extendedwitness(owf_key, vrf_input)`.
///
/// In debug builds, `owf_output` and `vrf_output` must match [`OWFParameters::evaluate_owf`] for
/// `(owf_key, owf_input)` and `(owf_key, vrf_input)` respectively.
///
/// Return value length is `2 * O::LBytes::USIZE` bytes.
pub fn aes_extendedwitness_vrf<O>(
    owf_key: &GenericArray<u8, O::LambdaBytes>,
    owf_input: &GenericArray<u8, O::InputSize>,
    owf_output: &GenericArray<u8, O::OutputSize>,
    vrf_input: &GenericArray<u8, O::InputSize>,
    vrf_output: &GenericArray<u8, O::OutputSize>,
) -> Box<[u8]>
where
    O: OWFParameters,
{
    let mut tmp = GenericArray::<u8, O::OutputSize>::default();
    O::evaluate_owf(owf_key.as_slice(), owf_input.as_slice(), tmp.as_mut_slice());
    debug_assert_eq!(tmp.as_slice(), owf_output.as_slice());
    O::evaluate_owf(owf_key.as_slice(), vrf_input.as_slice(), tmp.as_mut_slice());
    debug_assert_eq!(tmp.as_slice(), vrf_output.as_slice());

    let w_owf = aes_extendedwitness::<O>(owf_key, owf_input);
    let w_vrf = aes_extendedwitness::<O>(owf_key, vrf_input);

    let lb = O::LBytes::USIZE;
    let mut out = Vec::with_capacity(2 * lb);
    out.extend_from_slice(w_owf.as_slice());
    out.extend_from_slice(w_vrf.as_slice());
    debug_assert_eq!(out.len(), 2 * lb);
    out.into_boxed_slice()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        fields::GF192,
        parameter::OWF192,
        utils::test::read_test_data,
    };
    use generic_array::GenericArray;
    use serde::Deserialize;

    /// Optional JSON rows: `key`, `input`, `secondInput`, `w` (see `tests/data/AesExtendedWitnessVrf.json`).
    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct AesExtendedWitnessVrfRow {
        key: Vec<u8>,
        input: Vec<u8>,
        second_input: Vec<u8>,
        w: Vec<u8>,
    }

    impl AesExtendedWitnessVrfRow {
        fn extend_witness_test_vrf(&self) -> bool {
            super::extend_witness_test_vrf(
                &self.key,
                &self.input,
                &self.second_input,
                &self.w,
            )
        }
    }

    /// When the second plaintext is `owf_input` with `input[0] ^= 1`, VRF two-plaintext witness
    /// matches stock FAEST OWF192 [`crate::witness::aes_extendedwitness`].
    #[test]
    fn aes_extended_witness_test_vrf_matches_stock_tweak() {
        let key = GenericArray::from_slice(&[
            0x42u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        ]);
        let input = GenericArray::from_slice(&[0xabu8; 16]);
        let mut second = *input;
        second[0] ^= 1;

        let stock = OWF192::<GF192>::extendwitness(key, input);
        assert!(extend_witness_test_vrf(
            key.as_slice(),
            input.as_slice(),
            second.as_slice(),
            stock.as_slice(),
        ));
    }

    #[test]
    fn aes_extended_witness_test_vrf_json() {
        let database: Vec<AesExtendedWitnessVrfRow> =
            read_test_data("AesExtendedWitnessVrf.json");
        for row in database {
            assert!(
                row.extend_witness_test_vrf(),
                "AesExtendedWitnessVrf row failed: {row:?}"
            );
        }
    }
}
