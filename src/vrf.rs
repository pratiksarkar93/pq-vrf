//! VRF-oriented key material: OWF public image is **one** AES-192 block
//! `E_{owf_key}(owf_input)`, not FAEST’s full OWF192 (two AES evaluations).
//!
//! FAEST defines VRF helpers in `faest-signatures` (e.g. [`faest::aes_extendedwitness192_vrf`],
//! [`faest::extend_witness_test_vrf`], `parameter_vrf`, `witness_vrf`, `zk_constraints_vrf`).

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes192Enc;
use faest::{aes_extendedwitness192_vrf, FAEST192sSignature, Error as FaestError};
use generic_array::GenericArray;
use generic_array::typenum::{U16, U24};
use generic_array_1::GenericArray as Ga1;
use rand_core::RngCore;

/// FAEST-shaped **secret** bytes with a **single-block** OWF output (16 B), not `faest`’s 32-byte
/// OWF192 image inside [`faest::FAEST192sSigningKey`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VrfFaest192sKeypair {
    pub owf_input: [u8; 16],
    pub owf_key: [u8; 24],
    /// `E_{owf_key}(owf_input)` — the only OWF output carried in this keypair.
    pub owf_output: [u8; 16],
}

impl VrfFaest192sKeypair {
    /// Secret encoding: **`owf_input` ‖ `owf_key`** (40 B; same slice layout as FAEST-192s secret bytes).
    pub fn to_bytes(&self) -> [u8; 40] {
        let mut b = [0u8; 40];
        b[..16].copy_from_slice(&self.owf_input);
        b[16..].copy_from_slice(&self.owf_key);
        b
    }
}

/// One AES-192 block: **`E_{owf_key}(owf_input)`**.
pub fn aes_single_block_owf192(owf_key: &[u8; 24], owf_input: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let aes = Aes192Enc::new(GenericArray::from_slice(owf_key));
    aes.encrypt_block_b2b(
        GenericArray::from_slice(owf_input),
        GenericArray::from_mut_slice(&mut out),
    );
    out
}

/// Key generation (same RNG pattern as FAEST OWF192 keygen): sample `owf_key` until
/// `owf_key[0] & 0b11 != 0b11`, sample `owf_input`, set **`owf_output = E_{owf_key}(owf_input)`**
/// (single AES only).
pub fn vrf_keygen_with_rng(mut rng: impl RngCore) -> VrfFaest192sKeypair {
    let mut owf_key: GenericArray<u8, U24> = GenericArray::default();

    loop {
        rng.fill_bytes(&mut owf_key);
        if owf_key[0] & 0b11 != 0b11 {
            break;
        }
    }

    let mut owf_input: GenericArray<u8, U16> = GenericArray::default();
    rng.fill_bytes(&mut owf_input);

    let mut owf_input_arr = [0u8; 16];
    owf_input_arr.copy_from_slice(owf_input.as_slice());
    let mut owf_key_arr = [0u8; 24];
    owf_key_arr.copy_from_slice(owf_key.as_slice());
    let owf_output = aes_single_block_owf192(&owf_key_arr, &owf_input_arr);

    VrfFaest192sKeypair {
        owf_input: owf_input_arr,
        owf_key: owf_key_arr,
        owf_output,
    }
}

/// A FAEST-192s VRF proof is a standard FAEST-192s **signature** (11 260 B), same byte layout as
/// [`faest::faest192s_pack_signature`] and stock `FAEST192sSigningKey::sign`.
///
/// The verifier supplies **`vrf_input`** and **`vrf_output`** (and the 32 B public image
/// `owf_output ‖ vrf_output` for **μ**); they are not carried in the signature bytes.
pub type VrfFaest192sProof = FAEST192sSignature;

/// AES-PRF evaluation under this keypair’s `owf_key` (same as one OWF AES block on `input`).
pub fn aes_evaluate_owf(kp: &VrfFaest192sKeypair, input: &[u8]) -> [u8; 16] {
    debug_assert_eq!(input.len(), 16);
    let mut block = [0u8; 16];
    block.copy_from_slice(input);
    aes_single_block_owf192(&kp.owf_key, &block)
}

/// Build the same transcript as internal [`faest::faest_sign`], with the VRF extended witness (two
/// AES-192 evals) and a 32 B public image **`owf_output ‖ vrf_output`**. Returns a proof identical to
/// a **FAEST-192s signature**; `vrf_input` / `vrf_output` are **not** included (the verifier has them
/// when re-deriving μ and checking the VRF).
///
/// `r` / **IV (post-H₄)** for VOLE match stock signing: `iv_pre` from [`faest::faest192s_hash_r_iv`]
/// is **copied** before [`faest::faest192s_hash_iv`], so the packed **`iv_pre`** field matches the
/// serial signature. `vrf_output` is only used locally to form `pk_image` for `hash_mu`.
pub fn vrf_evaluate_proof(
    keypair: &VrfFaest192sKeypair,
    vrf_input: [u8; 16],
    vrf_output: [u8; 16],
    msg: &[u8],
    rho: &[u8],
) -> Result<VrfFaest192sProof, FaestError> {
    let owf_key = Ga1::from_slice(&keypair.owf_key);
    let owf_input = Ga1::from_slice(&keypair.owf_input);
    let vrf_in = Ga1::from_slice(&vrf_input);
    let witness = aes_extendedwitness192_vrf(owf_key, owf_input, vrf_in);

    let mut pk_image = [0u8; 32];
    pk_image[..16].copy_from_slice(&keypair.owf_output);
    pk_image[16..].copy_from_slice(&vrf_output);

    // ::3
    let mut mu = [0u8; faest::FAEST192S_HASH_MU_OUTPUT_BYTES];
    faest::faest192s_hash_mu(&mut mu, &keypair.owf_input, &pk_image, msg);

    // ::4: keep pre-H₄ IV for the serial signature; ::5: post-H₄ IV for VOLE (cf. `faest_sign`)
    let mut r = [0u8; faest::FAEST192S_HASH_R_OUTPUT_BYTES];
    let mut iv_pre_for_sig = [0u8; faest::FAEST192S_IV_BYTES];
    faest::faest192s_hash_r_iv(&mut r, &mut iv_pre_for_sig, &keypair.owf_key, &mu, rho);
    let mut iv_post = iv_pre_for_sig;
    let iv = faest::faest192s_hash_iv(&mut iv_post);

    // ::7
    let mut cs = [0u8; faest::FAEST192S_VOLE_CS_BYTES];
    let vole = faest::faest192s_volecommit(&mut cs, &r, &iv_post);

    // ::8
    let mut chall1 = [0u8; faest::FAEST192S_HASH_CHALLENGE_1_OUTPUT_BYTES];
    faest::faest192s_hash_challenge_1(&mut chall1, &mu, vole.com(), &cs, iv.as_slice());

    // ::10
    let mut u_tilde = [0u8; faest::FAEST192S_U_TILDE_BYTES];
    faest::faest192s_hash_u_vector(&mut u_tilde, &vole, &chall1);

    // ::11
    let h2_hasher = faest::faest192s_hash_challenge_2_v_matrix(&chall1, &u_tilde, &vole);

    // ::13
    let mut d = [0u8; faest::FAEST192S_L_BYTES];
    faest::faest192s_mask_witness_d(&mut d, witness.as_slice(), &vole);

    // ::14
    let mut chall2 = [0u8; faest::FAEST192S_HASH_CHALLENGE_2_OUTPUT_BYTES];
    faest::faest192s_hash_challenge_2_finalize(
        h2_hasher,
        d.as_ref(),
        &mut chall2,
    );

    // ::18
    let qs = faest::faest192s_prove(
        witness.as_ref(),
        &vole,
        &keypair.owf_input,
        &pk_image,
        &chall2,
    );
    let a0_tilde = qs.a0_tilde;
    let a1_tilde = qs.a1_tilde;
    let a2_tilde = qs.a2_tilde;

    // ::19–::26
    let h3_hasher = faest::faest192s_hash_challenge_3_init(
        &chall2,
        &a0_tilde,
        &a1_tilde,
        &a2_tilde,
    );
    let chall3_grind = faest::faest192s_grind_chall3(&h3_hasher, &vole);

    let raw = faest::faest192s_pack_signature(
        &cs,
        &u_tilde,
        &d,
        &a1_tilde,
        &a2_tilde,
        &chall3_grind.decom_i,
        &chall3_grind.chall3,
        &iv_pre_for_sig,
        chall3_grind.grind_ctr,
    );
    FAEST192sSignature::try_from(raw.as_slice())
}
