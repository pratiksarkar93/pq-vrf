use generic_array::{GenericArray, typenum::Unsigned};

#[cfg(not(feature = "std"))]
use alloc::{borrow::ToOwned, vec::Vec};

use super::{
    ByteCommitsRef, FieldCommitDegThree, encryption::enc_cstrnts, key_expansion::key_exp_cstrnts,
};
use crate::{
    fields::{Field, FromBit, GF192},
    internal_keys::PublicKey,
    parameter::{OWF192, OWFField, OWFParameters},
    rijndael_32::rijndael_key_schedule_unbitsliced,
    universal_hashing::ZKProofHasher,
    utils::xor_arrays,
};

use generic_array::typenum::U16;

pub(crate) fn owf_constraints<O>(
    zk_hasher: &mut ZKProofHasher<OWFField<O>>,
    w: ByteCommitsRef<OWFField<O>, O::LBytes>,
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
    {
        let (k_0, k_1) = ((w.keys[0] & 0b1), (w.keys[0] & 0b10) >> 1);
        zk_hasher.update(&FieldCommitDegThree {
            key: OWFField::<O>::from_bit(k_0 & k_1),
            tag: [
                OWFField::<O>::ZERO,
                w.tags[0] * w.tags[1],
                w.tags[0] * k_1 + w.tags[1] * k_0,
            ],
        });
    }

    // ::7
    if O::IS_EM {
        // ::8-9
        let ext_key = key_schedule_bytes::<O>(x);
        // ::10
        let owf_input = w.get_commits_ref::<O::NStBytes>(0);
        // ::11
        let owf_output_keys: GenericArray<u8, O::NStBytes> =
            xor_arrays(owf_input.keys.as_slice(), y.as_slice()).collect();
        let owf_output = ByteCommitsRef::from_slices(&owf_output_keys, owf_input.tags);
        // ::19 - EM = true
        let w_tilde = w.get_commits_ref::<O::LEncBytes>(O::LKeBytes::USIZE);
        // ::21 - EM = true
        enc_cstrnts::<O, _, _>(
            zk_hasher,
            owf_input,
            owf_output,
            w_tilde,
            ext_key.as_slice(),
        );
    } else {
        // ::13
        let mut owf_input = GenericArray::from_slice(x).to_owned();

        // ::16
        let k = key_exp_cstrnts::<O>(zk_hasher, w.get_commits_ref::<O::LKeBytes>(0));
        // Get references to the R+1 key commitments
        let extended_key: Vec<_> = (0..=O::R::USIZE)
            .map(|i| k.get_commits_ref::<O::NStBytes>(i * O::NStBytes::USIZE))
            .collect();

        // ::18-22
        for b in 0..O::Beta::USIZE {
            // ::19 - EM = false
            let w_tilde =
                w.get_commits_ref::<O::LEncBytes>(O::LKeBytes::USIZE + b * O::LEncBytes::USIZE);

            let owf_output = GenericArray::from_slice(
                &y[O::InputSize::USIZE * b..O::InputSize::USIZE * (b + 1)],
            );

            // ::21 - EM = false
            enc_cstrnts::<O, _, _>(
                zk_hasher,
                &owf_input,
                owf_output,
                w_tilde,
                extended_key.as_slice(),
            );

            // ::20
            owf_input[0] ^= 1;
        }
    }
}

/// Prover-side dual of [`crate::verifier::owf_constraints::owf_constraints_owf192_vrf`]: two AES
/// blocks on **`owf_input`** and **`vrf_input`**, same extended witness as
/// [`crate::witness_vrf::aes_extendedwitness192_vrf`]. Stock `owf_constraints` for OWF192 would XOR the
/// first byte of the plaintext between blocks; here the second block uses **`vrf_input`**.
pub(crate) fn owf_constraints_owf192_vrf(
    zk_hasher: &mut ZKProofHasher<OWFField<OWF192<GF192>>>,
    w: ByteCommitsRef<OWFField<OWF192<GF192>>, <OWF192<GF192> as OWFParameters>::LBytes>,
    pk: &PublicKey<OWF192<GF192>>,
    vrf_input: &GenericArray<u8, U16>,
) {
    type O192 = OWF192<GF192>;

    let PublicKey {
        owf_input: x,
        owf_output: y,
    } = pk;

    // ::5 — first witness-byte commitment (mirrors `owf_constraints` non-EM prologue).
    {
        let (k_0, k_1) = ((w.keys[0] & 0b1), (w.keys[0] & 0b10) >> 1);
        zk_hasher.update(&FieldCommitDegThree {
            key: OWFField::<O192>::from_bit(k_0 & k_1),
            tag: [
                OWFField::<O192>::ZERO,
                w.tags[0] * w.tags[1],
                w.tags[0] * k_1 + w.tags[1] * k_0,
            ],
        });
    }

    // Plaintext for the first block = public `x` = `pk.owf_input`.
    let owf_plain = GenericArray::from_slice(x).to_owned();

    // One key expansion; `extended_key` is shared by both `enc_cstrnts` calls.
    let k = key_exp_cstrnts::<O192>(zk_hasher, w.get_commits_ref::<<O192 as OWFParameters>::LKeBytes>(0));
    let extended_key: Vec<_> = (0..=<O192 as OWFParameters>::R::USIZE)
        .map(|i| {
            k.get_commits_ref::<<O192 as OWFParameters>::NStBytes>(
                i * <O192 as OWFParameters>::NStBytes::USIZE,
            )
        })
        .collect();

    // First AES path: `enc_k(x) = y[0..16]`.
    let w_tilde0 =
        w.get_commits_ref::<<O192 as OWFParameters>::LEncBytes>(<O192 as OWFParameters>::LKeBytes::USIZE);
    let y0 = GenericArray::from_slice(
        &y[0..<O192 as OWFParameters>::InputSize::USIZE],
    );
    enc_cstrnts::<O192, _, _>(
        zk_hasher,
        &owf_plain,
        y0,
        w_tilde0,
        extended_key.as_slice(),
    );

    // Second AES path: `enc_k(vrf_input) = y[16..32]`.
    let w_tilde1 = w.get_commits_ref::<<O192 as OWFParameters>::LEncBytes>(
        <O192 as OWFParameters>::LKeBytes::USIZE + <O192 as OWFParameters>::LEncBytes::USIZE,
    );
    let y1 = GenericArray::from_slice(
        &y[<O192 as OWFParameters>::InputSize::USIZE
            ..<O192 as OWFParameters>::InputSize::USIZE * 2],
    );
    enc_cstrnts::<O192, _, _>(zk_hasher, vrf_input, y1, w_tilde1, extended_key.as_slice());
}

#[inline]
fn key_schedule_bytes<O>(key: &GenericArray<u8, O::InputSize>) -> Vec<GenericArray<u8, O::NStBytes>>
where
    O: OWFParameters,
{
    rijndael_key_schedule_unbitsliced::<O::NSt, O::NK, O::R>(key, O::SKe::USIZE)
        .chunks_exact(32)
        .take(O::R::USIZE + 1)
        .map(|chunk| {
            chunk
                .iter()
                .copied()
                .take(O::NStBytes::USIZE)
                .collect::<GenericArray<u8, O::NStBytes>>()
        })
        .collect()
}
