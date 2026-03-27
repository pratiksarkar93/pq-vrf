//! VRF-oriented witness helpers. Core [`crate::witness`] is unchanged.
//!
//! [`aes_extendedwitness_vrf`] is a separate entry point you can evolve (e.g. second AES trace)
//! without modifying the original FAEST witness code.
#![allow(private_bounds, private_interfaces)]

#[cfg(not(feature = "std"))]
use alloc::boxed::Box;

use generic_array::GenericArray;

use crate::parameter::OWFParameters;
use crate::witness::aes_extendedwitness;

/// Extended witness with an extra `vrf_input` block (e.g. VRF message-derived block).
///
/// **Current behavior:** delegates to [`aes_extendedwitness`] and ignores `vrf_input`, so witness
/// size matches standard FAEST. Replace this body when you introduce a larger witness layout.
pub fn aes_extendedwitness_vrf<O>(
    owf_secret: &GenericArray<u8, O::LambdaBytes>,
    owf_input: &GenericArray<u8, O::InputSize>,
    _vrf_input: &GenericArray<u8, O::InputSize>,
) -> Box<GenericArray<u8, O::LBytes>>
where
    O: OWFParameters,
{
    aes_extendedwitness::<O>(owf_secret, owf_input)
}
