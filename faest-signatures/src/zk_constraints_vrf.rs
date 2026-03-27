#![allow(missing_docs)]
//! Quicksilver / ZK layer for the **VRF** setting: **two** AES-128 circuits under the same `owf_key`:
//! - `(owf_key, owf_input, owf_output)` — FAEST public OWF
//! - `(owf_key, vrf_input, vrf_output)` — VRF message-derived block
//!
//! The prover holds a single **`witness_compressed`** blob (see [`crate::witness_vrf`] and
//! [`crate::lib_vrf`]): length `2 * LBytes - P` where `P = FAEST128F_WITNESS_KEY_PREFIX_BYTES`
//! (56 for FAEST-128f). The first **`P`** bytes are the **shared** key + key-schedule extended
//! witness; the remainder is two plaintext-dependent tails (OWF trace, then VRF trace).
//!
//! This module is a **fork** of [`crate::zk_constraints`]: stock [`crate::zk_constraints::aes_prove`]
//! is wired to **one** `O::LBytes` witness. VRF proving must run Quicksilver over **both** AES
//! evaluation paths while committing to the shared prefix **once** (see [`crate::prover_vrf`]).
//!
//! Implementations should mirror `aes_prove` / `aes_verify` in `zk_constraints.rs`, but take
//! `witness_compressed` (or split views below) and invoke `prover_vrf::owf_constraints_vrf` once
//! that module is filled in.

use crate::{
    FAEST128F_EXTENDED_WITNESS_BYTES, FAEST128F_WITNESS_KEY_PREFIX_BYTES,
};

/// Length of `witness_compressed` for FAEST-128f (264 bytes): one shared prefix, two tails.
pub const VRF128F_WITNESS_COMPRESSED_LEN: usize =
    2 * FAEST128F_EXTENDED_WITNESS_BYTES - FAEST128F_WITNESS_KEY_PREFIX_BYTES;

/// Splits `witness_compressed` into shared prefix, OWF encryption trace, VRF encryption trace.
///
/// Layout: `[prefix P][tail_owf L-P][tail_vrf L-P]` with `P` = [`FAEST128F_WITNESS_KEY_PREFIX_BYTES`],
/// `L` = [`FAEST128F_EXTENDED_WITNESS_BYTES`].
pub fn vrf128f_split_witness_compressed(w: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
    const L: usize = FAEST128F_EXTENDED_WITNESS_BYTES;
    const P: usize = FAEST128F_WITNESS_KEY_PREFIX_BYTES;
    if w.len() != VRF128F_WITNESS_COMPRESSED_LEN {
        return None;
    }
    Some((&w[..P], &w[P..L], &w[L..]))
}

/// Placeholder for the VRF Quicksilver prover step (two AES circuits, one shared prefix).
///
/// Wire VOLE masks and `CstrntsVal` like [`crate::zk_constraints::aes_prove`], but hash constraints
/// for **both** AES traces via [`crate::prover_vrf::owf_constraints_vrf`].
#[allow(dead_code)]
pub(crate) fn aes_prove_vrf_128f() {
    todo!("Implement: Quicksilver prove for witness_compressed + shared 56-byte prefix")
}

/// Placeholder for the VRF Quicksilver verifier step.
#[allow(dead_code)]
pub(crate) fn aes_verify_vrf_128f() {
    todo!("Implement: Quicksilver verify matching aes_prove_vrf_128f")
}
