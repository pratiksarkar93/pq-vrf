//! Dual-AES `owf_constraints` for VRF (fork of [`crate::prover::owf_constraints`]).
//!
//! The upstream [`crate::prover::owf_constraints::owf_constraints`] builds Quicksilver constraints
//! for a **single** AES evaluation with witness `w: ByteCommitsRef<_, O::LBytes>`.
//!
//! For VRF, the same **secret key schedule** is used for two encryptions. The **byte** witness is
//! stored in compressed form (`witness_compressed`): shared prefix `P` + tail for OWF + tail for VRF.
//! The VOLE commitment must expose that **one** key-schedule witness is reused; the encryption
//! traces are **two** `enc_cstrnts` blocks (different plaintext / ciphertext).
//!
//! ## Implementation sketch (not yet coded)
//!
//! 1. Map `ByteCommitsRef` slices to the shared prefix once (as in non-EM branch of
//!    `owf_constraints` for key expansion).
//! 2. Call `enc_cstrnts` (see `prover/encryption.rs`) for `owf_input` / `owf_output`.
//! 3. Call `enc_cstrnts` again for `vrf_input` / `vrf_output` with the same round keys.
//!
//! Copy the control flow from `owf_constraints.rs` `if !O::IS_EM` branch, then duplicate the
//! `Beta` loop body for the second plaintext with a second public key pair.

use crate::{
    fields::Field,
    internal_keys::PublicKey,
    parameter::{OWFField, OWFParameters},
    universal_hashing::ZKProofHasher,
};

/// Placeholder: will mirror [`crate::prover::owf_constraints::owf_constraints`] for two AES paths.
#[allow(dead_code)]
pub(crate) fn owf_constraints_vrf<O>(
    _zk_hasher: &mut ZKProofHasher<OWFField<O>>,
    _pk_owf: &PublicKey<O>,
    _pk_vrf: &PublicKey<O>,
) where
    O: OWFParameters,
    OWFField<O>: Field,
{
    todo!("VRF: dual enc_cstrnts sharing key_exp_cstrnts; see module docs")
}
