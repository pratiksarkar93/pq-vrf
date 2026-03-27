//! VRF-oriented witness helpers. Core [`crate::witness`] is unchanged.
//!
//! [`aes_extendedwitness_vrf`] appends two FAEST AES extended witnesses: one for
//! (`owf_key`, `owf_input`) and one for (`owf_key`, `vrf_input`). Outputs are checked against
//! [`OWFParameters::evaluate_owf`] in debug builds.
//!
//! The returned slice has length `2 * O::LBytes::USIZE`.
//!
//! VRF Quicksilver wiring lives in [`crate::zk_constraints_vrf`] and [`crate::prover_vrf`]: two AES
//! circuits on the same `owf_key`, using a single **`witness_compressed`** (shared 56-byte prefix).
//!
//! ## Structure of each extended witness (see [`crate::witness::aes_extendedwitness`])
//!
//! Non-EM OWF (e.g. OWF128): first **`LambdaBytes`** bytes are raw AES key (`save_key_bits`), then
//! key-schedule non-linear bits (`save_non_lin_bits`), then **`round_with_save`** for `Beta` rounds
//! starting from the relevant plaintext (`owf_input` or `vrf_input`). The key-derived prefix is
//! **identical** in both concatenated witnesses when `owf_key` is the same; only the tail (data-path
//! trace) differs.
#![allow(private_bounds, private_interfaces)]

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, vec::Vec};
#[cfg(feature = "std")]
use std::vec::Vec;

use generic_array::{
    GenericArray,
    typenum::Unsigned,
};

use crate::parameter::OWFParameters;
use crate::witness::aes_extendedwitness;

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
