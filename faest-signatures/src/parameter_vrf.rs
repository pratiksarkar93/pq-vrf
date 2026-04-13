//! VRF extension trait layered on [`OWFParameters`]. Original `parameter.rs` / `OWFParameters` are unchanged.
//!
//! Use [`OWFParametersVrf`] when you need `extendwitness_vrf` / `witness_vrf` without forking core FAEST.
//!
//! For **OWF192** tests with an explicit second plaintext (two AES traces on the same key), use
//! [`crate::extend_witness_test_vrf`] and [`crate::aes_extendedwitness192_vrf`] (see `witness_vrf.rs`).
#![allow(private_bounds, private_interfaces)]

#[path = "lib_vrf.rs"]
mod lib_vrf;
pub use lib_vrf::{
    compress_faest128f_vrf_extendedwitness, decompress_faest128f_vrf_extendedwitness,
    faest128f_aes_extendedwitness_vrf, FAEST128F_EXTENDED_WITNESS_BYTES,
    FAEST128F_VRF_WITNESS_COMPRESSED_LEN, FAEST128F_WITNESS_KEY_PREFIX_BYTES,
};

#[cfg(not(feature = "std"))]
use alloc::boxed::Box;

use generic_array::GenericArray;

use crate::parameter::OWFParameters;
use crate::witness_vrf::aes_extendedwitness_vrf;

/// Extension of [`OWFParameters`] with VRF-style witness: two concatenated AES extended witnesses
/// (OWF + VRF plaintext); see [`aes_extendedwitness_vrf`]. Witness byte length is `2 * LBytes::USIZE`.
///
/// For FAEST-128f, [`FAEST128F_WITNESS_KEY_PREFIX_BYTES`] bytes at the start of each half match
/// (key + key-schedule material); see `witness.rs` / `witness_vrf.rs` docs.
///
/// Implemented for every type that implements [`OWFParameters`] via a blanket impl. Override by
/// wrapping your OWF type in a newtype and implementing this trait manually if needed.
pub trait OWFParametersVrf: OWFParameters {
    /// Extended witness from `owf_key`, public `owf_input` / `owf_output`, and VRF `vrf_input` /
    /// `vrf_output`.
    fn extendwitness_vrf(
        owf_key: &GenericArray<u8, Self::LambdaBytes>,
        owf_input: &GenericArray<u8, Self::InputSize>,
        owf_output: &GenericArray<u8, Self::OutputSize>,
        vrf_input: &GenericArray<u8, Self::InputSize>,
        vrf_output: &GenericArray<u8, Self::OutputSize>,
    ) -> Box<[u8]> {
        aes_extendedwitness_vrf::<Self>(owf_key, owf_input, owf_output, vrf_input, vrf_output)
    }
}

impl<T: OWFParameters> OWFParametersVrf for T {}
