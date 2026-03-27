//! Dual-AES `owf_constraints` for VRF (fork of [`crate::prover::owf_constraints`]).
//!
//! One key expansion ([`key_exp_cstrnts`]) on the **first** `LKeBytes` of the concatenated extended
//! witness, then two [`enc_cstrnts`] calls sharing the same round keys: OWF block (`pk`) and VRF
//! block (`vrf_input` / `vrf_output`). The witness must be two back-to-back AES extended witnesses
//! for the same `owf_key` (see [`crate::witness_vrf::aes_extendedwitness_vrf`]).
//!
//! **Key-schedule binding:** before key expansion, we enforce that each byte commitment in the
//! first `LKeBytes` matches the corresponding byte in the second half (`w[LBytes + i]` for
//! `i < LKeBytes`), so a malicious prover cannot use inconsistent key material across the two AES
//! paths while reusing round keys from a single expansion.

use generic_array::{
    GenericArray,
    typenum::{Prod, U16, U2, Unsigned},
};

use crate::{
    fields::{BigGaloisField, Square},
    internal_keys::PublicKey,
    parameter::{OWFField, OWF128, OWFParameters},
    prover::{
        ByteCommitsRef,
        encryption::enc_cstrnts,
        field_commitment::{FieldCommitDegOne, FieldCommitDegThree},
        key_expansion::key_exp_cstrnts,
    },
    universal_hashing::ZKProofHasher,
};

/// Constrain two byte commitments to open to the same value (`a` ≡ `b` in Quicksilver).
///
/// Uses the degree-3 polynomial `⟨d⟩·⟨d²⟩` where `⟨d⟩ = ⟨a⟩ − ⟨b⟩`, matching the style of
/// [`crate::prover::encryption::enc_cstrnts_even`].
fn enforce_equal_byte_commit<F>(
    zk_hasher: &mut ZKProofHasher<OWFField<OWF128<F>>>,
    a: &FieldCommitDegOne<OWFField<OWF128<F>>>,
    b: &FieldCommitDegOne<OWFField<OWF128<F>>>,
) where
    F: BigGaloisField<Length = U16>,
{
    let diff = FieldCommitDegOne::new(a.key - b.key, a.tag[0] - b.tag[0]);
    let diff_sq = (&diff).square();
    let cnstr = diff * &diff_sq;
    zk_hasher.update(&cnstr);
}

/// Quicksilver constraints for two AES-128 evaluations that share the same secret key schedule.
///
/// `w` is `2 * O::LBytes` bytes: first half is the OWF extended witness, second half is the VRF
/// extended witness (same key material in the first `P` bytes of each half when honestly
/// generated).
pub(crate) fn owf_constraints_vrf<F>(
    zk_hasher: &mut ZKProofHasher<OWFField<OWF128<F>>>,
    w: ByteCommitsRef<OWFField<OWF128<F>>, Prod<<OWF128<F> as OWFParameters>::LBytes, U2>>,
    pk_owf: &PublicKey<OWF128<F>>,
    vrf_input: &GenericArray<u8, <OWF128<F> as OWFParameters>::InputSize>,
    vrf_output: &GenericArray<u8, <OWF128<F> as OWFParameters>::OutputSize>,
) where
    F: BigGaloisField<Length = U16>,
{
    assert!(
        !<OWF128<F> as OWFParameters>::IS_EM,
        "owf_constraints_vrf: EM OWF not supported for dual AES"
    );

    let PublicKey {
        owf_input: x,
        owf_output: y,
    } = pk_owf;

    // ::5 (same as single-path `owf_constraints`)
    {
        let (k_0, k_1) = ((w.keys[0] & 0b1), (w.keys[0] & 0b10) >> 1);
        zk_hasher.update(&FieldCommitDegThree {
            key: OWFField::<OWF128<F>>::from_bit(k_0 & k_1),
            tag: [
                OWFField::<OWF128<F>>::ZERO,
                w.tags[0] * w.tags[1],
                w.tags[0] * k_1 + w.tags[1] * k_0,
            ],
        });
    }

    // Bind the second extended witness's key-schedule bytes to the first: same commitments for
    // `w[0..LKeBytes]` and `w[LBytes..LBytes+LKeBytes]`.
    for i in 0..<OWF128<F> as OWFParameters>::LKeBytes::USIZE {
        let left = w.get_field_commit(i);
        let right = w.get_field_commit(<OWF128<F> as OWFParameters>::LBytes::USIZE + i);
        enforce_equal_byte_commit(zk_hasher, &left, &right);
    }

    let owf_input = GenericArray::from_slice(x).to_owned();

    let k = key_exp_cstrnts::<OWF128<F>>(
        zk_hasher,
        w.get_commits_ref::<<OWF128<F> as OWFParameters>::LKeBytes>(0),
    );
    let extended_key: Vec<_> = (0..=<OWF128<F> as OWFParameters>::R::USIZE)
        .map(|i| {
            k.get_commits_ref::<<OWF128<F> as OWFParameters>::NStBytes>(
                i * <OWF128<F> as OWFParameters>::NStBytes::USIZE,
            )
        })
        .collect();

    // First AES: public OWF input/output.
    let w_tilde_owf = w.get_commits_ref::<<OWF128<F> as OWFParameters>::LEncBytes>(
        <OWF128<F> as OWFParameters>::LKeBytes::USIZE,
    );
    let owf_output = GenericArray::from_slice(&y[..<OWF128<F> as OWFParameters>::InputSize::USIZE]);
    enc_cstrnts::<OWF128<F>, _, _>(
        zk_hasher,
        &owf_input,
        owf_output,
        w_tilde_owf,
        extended_key.as_slice(),
    );

    // Second AES: VRF plaintext/ciphertext; same round keys as first block.
    let vrf_input_owned = vrf_input.to_owned();
    let w_tilde_vrf = w.get_commits_ref::<<OWF128<F> as OWFParameters>::LEncBytes>(
        <OWF128<F> as OWFParameters>::LBytes::USIZE + <OWF128<F> as OWFParameters>::LKeBytes::USIZE,
    );
    let vrf_out = GenericArray::from_slice(vrf_output.as_slice());
    enc_cstrnts::<OWF128<F>, _, _>(
        zk_hasher,
        &vrf_input_owned,
        vrf_out,
        w_tilde_vrf,
        extended_key.as_slice(),
    );
}
