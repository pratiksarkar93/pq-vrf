#![allow(missing_docs)]
//! VRF prover: fork of [`crate::prover`] for **two** AES circuits under one key.
//!
//! Implement [`owf_constraints_vrf`] by adapting [`crate::prover::owf_constraints::owf_constraints`]:
//! - **Shared**: key schedule / `ByteCommitsRef` for the first `LKeBytes` bytes of the extended
//!   witness (the same prefix as the first `P` bytes of `witness_compressed` in wire form).
//! - **Twice**: `enc_cstrnts` (or equivalent) for plaintext `owf_input` and for `vrf_input`, with
//!   public outputs `owf_output` and `vrf_output` respectively.

pub(crate) mod owf_constraints_vrf;
