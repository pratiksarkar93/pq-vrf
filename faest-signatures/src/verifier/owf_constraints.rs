use core::array;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use generic_array::{GenericArray, typenum::Unsigned};

use super::{
    encryption,
    key_expansion::key_exp_cstrnts,
    vole_commitments::{VoleCommits, VoleCommitsRef},
};

use crate::{
    aes::AddRoundKey,
    fields::{BigGaloisField, GF192},
    internal_keys::PublicKey,
    parameter::{OWF192, OWFField, OWFParameters},
    rijndael_32::rijndael_key_schedule_unbitsliced,
    universal_hashing::ZKVerifyHasher,
};

use generic_array::typenum::U16;

pub(crate) fn owf_constraints<O>(
    zk_hasher: &mut ZKVerifyHasher<OWFField<O>>,
    w: VoleCommitsRef<'_, OWFField<O>, O::L>,
    delta: &OWFField<O>,
    pk: &PublicKey<O>,
) where
    O: OWFParameters,
{
    // ::1
    let PublicKey {
        owf_input: x,
        owf_output: y,
    } = pk;

    // ::5
    zk_hasher.mul_and_update(&w.scalars[0], &w.scalars[1]);

    // ::7
    if O::IS_EM {
        // ::8-9
        let extended_key = key_schedule_bytes::<O>(x, delta);
        // ::10
        let owf_input = w.get_commits_ref::<O::NStBits>(0);
        // ::11
        let owf_output = owf_input.add_round_key(GenericArray::<u8, O::NStBytes>::from_slice(y));
        // ::19 - EM = true
        let w_tilde = w.get_commits_ref::<O::LEnc>(O::LKe::USIZE);
        // ::21 - EM = true
        encryption::enc_cstrnts::<O, _>(
            zk_hasher,
            owf_input,
            owf_output.to_ref(),
            w_tilde,
            extended_key.as_slice(),
        );
    } else {
        // ::13
        let mut owf_input: VoleCommits<_, O::NStBits> = VoleCommits::from_constant(
            GenericArray::<u8, O::NStBytes>::from_slice(x.as_slice()),
            delta,
        );

        // ::16
        let k = key_exp_cstrnts::<O>(zk_hasher, w.get_commits_ref::<O::LKe>(0));
        let extended_key: Vec<_> = (0..=O::R::USIZE)
            .map(|i| k.get_commits_ref::<O::NStBits>(i * O::NStBits::USIZE))
            .collect();

        // ::18-22
        for b in 0..O::Beta::USIZE {
            // ::19 - EM = false
            let w_tilde = w.get_commits_ref::<O::LEnc>(O::LKe::USIZE + b * O::LEnc::USIZE);
            let owf_output = GenericArray::<u8, O::NStBytes>::from_slice(
                &y[O::InputSize::USIZE * b..O::InputSize::USIZE * (b + 1)],
            );
            let owf_output = VoleCommits::from_constant(owf_output, delta);
            // ::21 - EM = false
            encryption::enc_cstrnts::<O, _>(
                zk_hasher,
                owf_input.to_ref(),
                owf_output.to_ref(),
                w_tilde,
                extended_key.as_slice(),
            );
            // ::20
            owf_input.scalars[0] += delta;
        }
    }
}

/// Quicksilver **verifier** constraints for VRF-style OWF192: same as [`owf_constraints`] for the
/// first block, but the second AES plaintext is **`vrf_input`**, not stock’s toggled-`x` second block
/// (see [`crate::witness_vrf::aes_extendedwitness192_vrf`]).
///
/// `w` is the VOLE-opened witness; `pk.owf_output` is 32 B = `E_k(x) ‖ E_k(vrf_input)` for public `x` and
/// `vrf_input`. Two `enc_cstrnts` calls (see `verifier::encryption`) share the same `extended_key` from
/// one `key_exp_cstrnts`.
pub(crate) fn owf_constraints_owf192_vrf(
    zk_hasher: &mut ZKVerifyHasher<OWFField<OWF192<GF192>>>,
    w: VoleCommitsRef<'_, OWFField<OWF192<GF192>>, <OWF192<GF192> as OWFParameters>::L>,
    delta: &OWFField<OWF192<GF192>>,
    pk: &PublicKey<OWF192<GF192>>,
    vrf_input: &GenericArray<u8, U16>,
) {
    type O192 = OWF192<GF192>;

    let PublicKey {
        owf_input: x,
        owf_output: y,
    } = pk;

    // ::5 — first witness-byte gate (same as non-EM branch of `owf_constraints`).
    zk_hasher.mul_and_update(&w.scalars[0], &w.scalars[1]);

    // Public plaintext for AES block 1 = `pk.owf_input` (`x`).
    let block0_plain: VoleCommits<'_, _, <O192 as OWFParameters>::NStBits> =
        VoleCommits::from_constant(x, delta);

    // One key schedule from the committed key bytes; round keys used for *both* encryptions.
    let k = key_exp_cstrnts::<O192>(zk_hasher, w.get_commits_ref::<<O192 as OWFParameters>::LKe>(0));
    let extended_key: Vec<_> = (0..=<O192 as OWFParameters>::R::USIZE)
        .map(|i| {
            k.get_commits_ref::<<O192 as OWFParameters>::NStBits>(
                i * <O192 as OWFParameters>::NStBits::USIZE,
            )
        })
        .collect();

    // First AES: trace `w_tilde0`, plaintext opens to `x`, ciphertext is `y[0..16]`.
    let w_tilde0 =
        w.get_commits_ref::<<O192 as OWFParameters>::LEnc>(<O192 as OWFParameters>::LKe::USIZE);
    let y0 = GenericArray::<u8, <O192 as OWFParameters>::NStBytes>::from_slice(
        &y[0..<O192 as OWFParameters>::InputSize::USIZE],
    );
    let out0 = VoleCommits::from_constant(y0, delta);
    encryption::enc_cstrnts::<O192, _>(
        zk_hasher,
        block0_plain.to_ref(),
        out0.to_ref(),
        w_tilde0,
        extended_key.as_slice(),
    );

    // Second AES: plaintext opens to `vrf_input` (not `x` with a bit flip); ciphertext `y[16..32]`.
    let block1_plain = VoleCommits::from_constant(vrf_input, delta);
    let w_tilde1 = w.get_commits_ref::<<O192 as OWFParameters>::LEnc>(
        <O192 as OWFParameters>::LKe::USIZE + <O192 as OWFParameters>::LEnc::USIZE,
    );
    let y1 = GenericArray::<u8, <O192 as OWFParameters>::NStBytes>::from_slice(
        &y[<O192 as OWFParameters>::InputSize::USIZE
            ..<O192 as OWFParameters>::InputSize::USIZE * 2],
    );
    let out1 = VoleCommits::from_constant(y1, delta);
    encryption::enc_cstrnts::<O192, _>(
        zk_hasher,
        block1_plain.to_ref(),
        out1.to_ref(),
        w_tilde1,
        extended_key.as_slice(),
    );
}

#[inline]
fn byte_to_field<F>(byte: u8, delta: F) -> [F; 8]
where
    F: BigGaloisField,
{
    array::from_fn(|i| delta * ((byte >> i) & 1))
}

#[inline]
fn key_schedule_bytes<'a, O>(
    key: &GenericArray<u8, O::InputSize>,
    delta: &'a OWFField<O>,
) -> Vec<VoleCommits<'a, OWFField<O>, O::NStBits>>
where
    O: OWFParameters,
{
    rijndael_key_schedule_unbitsliced::<O::NSt, O::NK, O::R>(key, O::SKe::USIZE)
        .chunks_exact(32)
        .take(O::R::USIZE + 1)
        .map(|chunk| {
            let scalars = chunk[..O::NStBytes::USIZE]
                .iter()
                .flat_map(|&byte| byte_to_field(byte, *delta))
                .collect();
            VoleCommits { scalars, delta }
        })
        .collect()
}
