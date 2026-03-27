//! VRF extension trait layered on [`OWFParameters`]. Original `parameter.rs` / `OWFParameters` are unchanged.
//!
//! Use [`OWFParametersVrf`] when you need `extendwitness_vrf` / `witness_vrf` without forking core FAEST.
#![allow(private_bounds, private_interfaces)]

#[cfg(not(feature = "std"))]
use alloc::boxed::Box;

use generic_array::GenericArray;

use crate::internal_keys::SecretKey;
use crate::parameter::OWFParameters;
use crate::witness_vrf::aes_extendedwitness_vrf;

/// Extension of [`OWFParameters`] with VRF-style witness generation (third AES block input).
///
/// Implemented for every type that implements [`OWFParameters`] via a blanket impl. Override by
/// wrapping your OWF type in a newtype and implementing this trait manually if needed.
pub trait OWFParametersVrf: OWFParameters {
    /// Extended witness from `owf_key`, FAEST public `owf_input`, and `vrf_input`.
    fn extendwitness_vrf(
        owf_key: &GenericArray<u8, Self::LambdaBytes>,
        owf_input: &GenericArray<u8, Self::InputSize>,
        vrf_input: &GenericArray<u8, Self::InputSize>,
    ) -> Box<GenericArray<u8, Self::LBytes>> {
        aes_extendedwitness_vrf::<Self>(owf_key, owf_input, vrf_input)
    }

    /// Like [`OWFParameters::witness`] but threads `vrf_input` into [`extendwitness_vrf`].
    fn witness_vrf(
        sk: &SecretKey<Self>,
        vrf_input: &GenericArray<u8, Self::InputSize>,
    ) -> Box<GenericArray<u8, Self::LBytes>> {
        Self::extendwitness_vrf(&sk.owf_key, &sk.pk.owf_input, vrf_input)
    }
}

impl<T: OWFParameters> OWFParametersVrf for T {}
