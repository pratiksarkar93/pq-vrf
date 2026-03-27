//! VRF-specific entry points layered on [`crate::witness_vrf`] and [`crate::parameter_vrf`].
//! Keeps the main `lib.rs` free of FAEST-128f witness glue.
#![allow(missing_docs)]

#[cfg(not(feature = "std"))]
use alloc::boxed::Box;

use generic_array::GenericArray;
use signature::Keypair;

use crate::ByteEncoding;
use crate::parameter::{FAEST128fParameters, FAESTParameters, OWFParameters};
use crate::witness_vrf::aes_extendedwitness_vrf;
use crate::FAEST128fSigningKey;

/// `O::LBytes` for FAEST-128f / `OWF128`: one full AES extended witness (`witness::aes_extendedwitness`).
pub const FAEST128F_EXTENDED_WITNESS_BYTES: usize = 160;

/// Key-dependent prefix length **within each** extended witness for OWF128 (non-EM).
///
/// Matches the bytes written by `save_key_bits` (16 = `LambdaBytes`) plus `save_non_lin_bits`
/// (40 for this parameter set) in [`crate::witness::aes_extendedwitness`], before `round_with_save`.
/// The same prefix appears in both halves of [`crate::witness_vrf::aes_extendedwitness_vrf`] and can
/// be stored once when compressing.
pub const FAEST128F_WITNESS_KEY_PREFIX_BYTES: usize = 56;

/// FAEST-128f only: builds the VRF extended witness (two concatenated AES extended witnesses).
///
/// Uses `owf_key` / `owf_input` / `owf_output` from the signing and verification keys, and
/// `vrf_input` with `vrf_output` derived via [`crate::parameter::OWFParameters::evaluate_owf`].
///
/// ## `ByteEncoding` layout (FAEST-128f)
///
/// - **Signing key** [`FAEST128fSigningKey::to_bytes`](ByteEncoding::to_bytes): `SK = 32` bytes
///   `owf_input ‖ owf_key` (each 16 bytes). Same order as [`crate::internal_keys::SecretKey`].
/// - **Verification key** [`FAEST128fVerificationKey::to_bytes`](ByteEncoding::to_bytes): `PK = 32` bytes
///   `owf_input ‖ owf_output` (AES block each).
///
/// This function slices those encodings to build the inputs to [`aes_extendedwitness_vrf`].
pub fn faest128f_aes_extendedwitness_vrf(
    signing_key: &FAEST128fSigningKey,
    vrf_input: &[u8; 16],
) -> Box<[u8]> {
    type Owf = <FAEST128fParameters as FAESTParameters>::OWF;
    // `ByteEncoding::to_bytes` for FAEST-128f signing key: [0..16) = owf_input, [16..32) = owf_key.
    let sk = signing_key.to_bytes();
    // Verification key bytes: [0..16) = owf_input (matches sk), [16..32) = owf_output (public ciphertext).
    let vk = signing_key.verifying_key().to_bytes();
    let owf_key = GenericArray::from_slice(&sk[16..32]);
    let owf_input = GenericArray::from_slice(&sk[..16]);
    let owf_output = GenericArray::from_slice(&vk[16..32]);
    let vrf_input_ga = GenericArray::from_slice(vrf_input.as_slice());
    let mut vrf_output = GenericArray::default();
    Owf::evaluate_owf(
        owf_key.as_slice(),
        vrf_input_ga.as_slice(),
        vrf_output.as_mut_slice(),
    );
    aes_extendedwitness_vrf::<Owf>(
        owf_key,
        owf_input,
        owf_output,
        &vrf_input_ga,
        &vrf_output,
    )
}
