#![allow(missing_docs, dead_code)]
//! Quicksilver / ZK layer for the **VRF** setting: **two** AES-128 circuits under the same `owf_key`:
//! - `(owf_key, owf_input, owf_output)` — FAEST public OWF
//! - `(owf_key, vrf_input, vrf_output)` — VRF message-derived block
//!
//! The prover holds a single **`witness_compressed`** blob (see [`crate::witness_vrf`] and
//! [`crate::lib_vrf`]): length `2 * LBytes - P` where `P = FAEST128F_WITNESS_KEY_PREFIX_BYTES`
//! (56 for FAEST-128f). The first **`P`** bytes are the **shared** key + key-schedule extended
//! witness; the remainder is two plaintext-dependent tails (OWF trace, then VRF trace).
//!
//! **Before** Quicksilver over this witness (same order as stock FAEST [`crate::faest::sign`]):
//! 1. **Message binding:** `μ` hashes `(owf_input, owf_output, vrf_input)` — the FAEST message is the
//!    16-byte VRF block `vrf_input`, not a separate arbitrary-length message.
//! 2. **VOLE randomness:** `r` and `iv` come from `ρ` via `hash_r_iv` and `hash_iv`, driving the VOLE
//!    PRG seed (`volecommit`). Use [`FAEST128fSigningKey::mu_r_iv_vrf`] with that `vrf_input` and `ρ`.
//!
//! This module is a **fork** of [`crate::zk_constraints`]: stock [`crate::zk_constraints::aes_prove`]
//! is wired to **one** `O::LBytes` witness. VRF proving runs Quicksilver over **both** AES paths with
//! one key expansion and two encryptions ([`crate::prover_vrf::owf_constraints_vrf::owf_constraints_vrf`]).
//!
//! ## VOLE width
//!
//! [`reshape_and_to_field_vrf`] consumes `2 * LBytes + Λ` bytes of each VOLE row (same layout as
//! [`crate::zk_constraints::aes_prove`] but with a doubled witness prefix). For FAEST-128f this is
//! **352** columns, while stock `LHatBytes` is **210**, so **full** integration requires a VRF VOLE
//! transcript with a wider commitment matrix than stock FAEST.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use generic_array::{
    GenericArray,
    typenum::{Prod, U16, U2, Unsigned},
};

use crate::{
    fields::BigGaloisField,
    internal_keys::PublicKey,
    parameter::{BaseParameters, OWFField, OWF128, OWFParameters, QSProof},
    prover::byte_commitments::ByteCommitsRef,
    prover_vrf::owf_constraints_vrf::owf_constraints_vrf,
    universal_hashing::ZKHasherInit,
    utils::get_bit,
    zk_constraints::CstrntsVal,
};

use crate::parameter_vrf::decompress_faest128f_vrf_extendedwitness;

use crate::{
    FAEST128F_EXTENDED_WITNESS_BYTES, FAEST128F_VRF_WITNESS_COMPRESSED_LEN,
    FAEST128F_WITNESS_KEY_PREFIX_BYTES,
};

/// Length of `witness_compressed` for FAEST-128f (264 bytes): one shared prefix, two tails.
pub const VRF128F_WITNESS_COMPRESSED_LEN: usize = FAEST128F_VRF_WITNESS_COMPRESSED_LEN;

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

/// Maps VOLE constraint rows to field elements for the **dual** extended witness (`2 * LBytes`
/// witness bytes + `Λ` bytes of `u`), mirroring [`crate::zk_constraints::reshape_and_to_field`].
///
/// **Requires** `LHatBytes::USIZE ≥ 2 * LBytes + Λ` for the chosen `O` (not satisfied by stock
/// FAEST-128f `LHatBytes = 210` until the VRF VOLE layer is widened).
pub(crate) fn reshape_and_to_field_vrf<O: OWFParameters>(m: CstrntsVal<O>) -> Vec<OWFField<O>> {
    let cols = 2 * O::LBytes::USIZE + O::LambdaBytesTimes2::USIZE;
    assert!(
        cols <= O::LHatBytes::USIZE,
        "reshape_and_to_field_vrf: need LHatBytes >= {} (dual witness + u); got {}",
        cols,
        O::LHatBytes::USIZE
    );
    (0..cols)
        .flat_map(|col| {
            let mut ret = vec![GenericArray::<u8, O::LambdaBytes>::default(); 8];
            for row in 0..O::Lambda::USIZE {
                for (i, ret_i) in ret.iter_mut().enumerate() {
                    ret_i[row / 8] |= get_bit(&[m[row][col]], i) << (row % 8);
                }
            }
            ret.into_iter()
                .map(|r_i| OWFField::<O>::from(r_i.as_slice()))
        })
        .collect()
}

/// Quicksilver **prove** for two AES-128 evaluations sharing one key (same structure as
/// [`crate::zk_constraints::aes_prove`], but witness length `2 * LBytes` and
/// [`owf_constraints_vrf`]).
///
/// `w` is the **decompressed** dual extended witness (`2 * LBytes` bytes). For
/// [`FAEST128F_VRF_WITNESS_COMPRESSED_LEN`] storage, use [`aes_prove_vrf_128f_from_compressed`].
pub(crate) fn aes_prove_vrf_128f<F>(
    w: &GenericArray<u8, Prod<<OWF128<F> as OWFParameters>::LBytes, U2>>,
    u: &GenericArray<u8, <OWF128<F> as OWFParameters>::LambdaBytesTimes2>,
    v: CstrntsVal<'_, OWF128<F>>,
    pk: &PublicKey<OWF128<F>>,
    chall_2: &GenericArray<
        u8,
        <<OWF128<F> as OWFParameters>::BaseParams as BaseParameters>::Chall,
    >,
    vrf_input: &GenericArray<u8, <OWF128<F> as OWFParameters>::InputSize>,
    vrf_output: &GenericArray<u8, <OWF128<F> as OWFParameters>::OutputSize>,
) -> QSProof<OWF128<F>>
where
    F: BigGaloisField<Length = U16>,
{
    let v = reshape_and_to_field_vrf::<OWF128<F>>(v);

    let mut zk_hasher =
        <<OWF128<F> as OWFParameters>::BaseParams as BaseParameters>::ZKHasher::new_zk_proof_hasher(
            chall_2,
        );

    let u0_star =
        OWFField::<OWF128<F>>::sum_poly_bits(&u[..<OWF128<F> as OWFParameters>::LambdaBytes::USIZE]);
    let u1_star = OWFField::<OWF128<F>>::sum_poly_bits(
        &u[<OWF128<F> as OWFParameters>::LambdaBytes::USIZE..],
    );

    let v0_star = OWFField::<OWF128<F>>::sum_poly(
        &v[2 * <OWF128<F> as OWFParameters>::L::USIZE
            ..2 * <OWF128<F> as OWFParameters>::L::USIZE
                + <OWF128<F> as OWFParameters>::Lambda::USIZE],
    );
    let v1_star = OWFField::<OWF128<F>>::sum_poly(
        &v[2 * <OWF128<F> as OWFParameters>::L::USIZE
            + <OWF128<F> as OWFParameters>::Lambda::USIZE..],
    );

    owf_constraints_vrf::<F>(
        &mut zk_hasher,
        ByteCommitsRef::<
            OWFField<OWF128<F>>,
            Prod<<OWF128<F> as OWFParameters>::LBytes, U2>,
        >::from_slices(w.as_slice(), &v[..2 * <OWF128<F> as OWFParameters>::L::USIZE]),
        pk,
        vrf_input,
        vrf_output,
    );

    zk_hasher.finalize(&v0_star, &(u0_star + v1_star), &u1_star)
}

/// Same as [`aes_prove_vrf_128f`], but decodes [`crate::parameter_vrf::compress_faest128f_vrf_extendedwitness`]
/// output into the full `2 * LBytes` witness first.
pub(crate) fn aes_prove_vrf_128f_from_compressed<F>(
    witness_compressed: &[u8],
    u: &GenericArray<u8, <OWF128<F> as OWFParameters>::LambdaBytesTimes2>,
    v: CstrntsVal<'_, OWF128<F>>,
    pk: &PublicKey<OWF128<F>>,
    chall_2: &GenericArray<
        u8,
        <<OWF128<F> as OWFParameters>::BaseParams as BaseParameters>::Chall,
    >,
    vrf_input: &GenericArray<u8, <OWF128<F> as OWFParameters>::InputSize>,
    vrf_output: &GenericArray<u8, <OWF128<F> as OWFParameters>::OutputSize>,
) -> QSProof<OWF128<F>>
where
    F: BigGaloisField<Length = U16>,
{
    let full = decompress_faest128f_vrf_extendedwitness(witness_compressed);
    assert_eq!(full.len(), 2 * <OWF128<F> as OWFParameters>::LBytes::USIZE);
    let w = GenericArray::<
        u8,
        Prod<<OWF128<F> as OWFParameters>::LBytes, U2>,
    >::from_slice(&full);
    aes_prove_vrf_128f::<F>(&w, u, v, pk, chall_2, vrf_input, vrf_output)
}

/// **TODO:** Quicksilver **verify** for the dual-AES VRF circuit (mirror [`aes_prove_vrf_128f`]).
///
/// A full **sound** VRF verifier that checks `y = AES_k(vrf_input)` without the witness must
/// combine this with the FAEST VOLE path: reconstruct `q` from `chall3` + partial opening,
/// recompute `chall2`, then verify the polynomial identity against the public key (same structure as
/// [`crate::zk_constraints::aes_verify`] but with [`crate::verifier`] constraints wired for two AES
/// paths — see [`crate::prover_vrf::owf_constraints_vrf::owf_constraints_vrf`] (prover side).
///
/// When implemented, include the same **key-schedule equality** checks as the prover (opened
/// `⟨a⟩ − ⟨b⟩` constraints), plus dual `enc` / key-exp verification.
#[allow(dead_code)]
pub(crate) fn aes_verify_vrf_128f() {
    todo!("Implement: Quicksilver verify matching aes_prove_vrf_128f")
}
