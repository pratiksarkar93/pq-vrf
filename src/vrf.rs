//! VRF-oriented key material: OWF public image is **one** AES-192 block
//! `E_{owf_key}(owf_input)`, not FAEST’s full OWF192 (two AES evaluations).
//!
//! FAEST defines VRF helpers in `faest-signatures` (e.g. [`faest::aes_extendedwitness192_vrf`],
//! [`faest::extend_witness_test_vrf`], `parameter_vrf`, `witness_vrf`, `zk_constraints_vrf`).

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes192Enc;
use generic_array::GenericArray;
use generic_array::typenum::{U16, U24};
use faest::aes_extendedwitness192_vrf;
use generic_array_1::{GenericArray as Ga1, typenum::U312};
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

/// Transcript for the FAEST-192s VRF path through Quicksilver **`a{0,1,2}_tilde`** (after step 18 + the
/// same `a1`/`a2` layout as `save_zk_constraints` in full signing).
#[allow(dead_code)] // bundle for callers; not every field is used in the demo `main`
#[derive(Debug)]
pub struct VrfFaest192sProofMaterial {
    pub witness: Box<Ga1<u8, U312>>,
    /// `owf_output ‖ vrf_output` (32 B) fed into H_μ.
    pub pk_image: [u8; 32],
    /// `::3`
    pub mu: [u8; faest::FAEST192S_HASH_MU_OUTPUT_BYTES],
    /// `::4` (H₃ output).
    pub r: [u8; faest::FAEST192S_HASH_R_OUTPUT_BYTES],
    /// Final IV after H₄; same as the buffer passed to VOLE with `r`.
    pub iv: [u8; faest::FAEST192S_IV_BYTES],
    /// `::7` — VOLE batch `c` slots (analogous to `signature.cs`).
    pub cs: [u8; faest::FAEST192S_VOLE_CS_BYTES],
    pub vole: faest::Faest192sVoleCommitProof,
    /// `::8`
    pub chall1: [u8; faest::FAEST192S_HASH_CHALLENGE_1_OUTPUT_BYTES],
    /// `::10` — compressed `u` (same as `signature.u_tilde`).
    pub u_tilde: [u8; faest::FAEST192S_U_TILDE_BYTES],
    /// `::13` — masked witness `d = w ⊕ u` on the first `L` bytes.
    pub d: [u8; faest::FAEST192S_L_BYTES],
    /// `::14` — second challenge (H₂⁽²⁾ with `d` fed after step 11).
    pub chall2: [u8; faest::FAEST192S_HASH_CHALLENGE_2_OUTPUT_BYTES],
    /// `::18` / `a0` — first Quicksilver field (fed into H₂⁽³⁾ init in full signing; not in `a1`/`a2` slots).
    pub a0_tilde: [u8; faest::FAEST192S_LAMBDA_BYTES],
    /// Same as `signature.a1_tilde` after `save_zk_constraints` in [`faest_sign`].
    pub a1_tilde: [u8; faest::FAEST192S_LAMBDA_BYTES],
    /// Same as `signature.a2_tilde` after `save_zk_constraints`.
    pub a2_tilde: [u8; faest::FAEST192S_LAMBDA_BYTES],
    /// `::19` — H₂⁽³⁾ hasher (chall2 + `a{0,1,2}_tilde`); for grinding / `chall3` in full signing.
    pub h3_hasher: faest::Faest192sChallenge3Hasher,
    /// `::20`–`::26` — grinded `chall3`, winning `ctr`, and BAVC `decom_i` (see [`faest::faest192s_grind_chall3`], matching stock FAEST-192s signing after step 19).
    pub chall3_grind: faest::Faest192sChall3GrindResult,
}

/// AES-PRF evaluation under this keypair’s `owf_key` (same as one OWF AES block on `input`).
pub fn aes_evaluate_owf(kp: &VrfFaest192sKeypair, input: &[u8]) -> [u8; 16] {
    debug_assert_eq!(input.len(), 16);
    let mut block = [0u8; 16];
    block.copy_from_slice(input);
    aes_single_block_owf192(&kp.owf_key, &block)
}

/// Extended witness for **two** AES-192 evaluations on the same key: `(owf_input, owf_key)` and
/// `(vrf_input, owf_key)` — delegates to [`faest::aes_extendedwitness192_vrf`].
///
/// Also computes FAEST-192s **μ** via [`faest::faest192s_hash_mu`], then the same **4–5, 7–8, 10–11,
/// 13–14, 18** as [`faest_sign`]: r/iv, VOLE, [`faest::faest192s_hash_challenge_1`], `ũ`, H₂⁽²⁾+`v`,
/// [`faest::faest192s_mask_witness_d`], [`faest::faest192s_hash_challenge_2_finalize`], and
/// [`faest::faest192s_prove`] (see its doc for VRF vs stock witness).
/// `owf_output ‖ vrf_output` is the 32-byte public image (stock OWF192 length). Use the same `msg` and
/// `rho` as in a full signature when wiring VOLE. Steps **20–26** (grind `chall3` + BAVC `open`) are
/// run via [`faest::faest192s_grind_chall3`], matching stock signing after H₂⁽³⁾ init.
pub fn vrf_evaluate_proof(
    keypair: &VrfFaest192sKeypair,
    vrf_input: [u8; 16],
    vrf_output: [u8; 16],
    msg: &[u8],
    rho: &[u8],
) -> VrfFaest192sProofMaterial {
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

    // ::4–5 (match `faest_sign`: H₃ then H₄)
    let mut r = [0u8; faest::FAEST192S_HASH_R_OUTPUT_BYTES];
    let mut iv_pre = [0u8; faest::FAEST192S_IV_BYTES];
    faest::faest192s_hash_r_iv(&mut r, &mut iv_pre, &keypair.owf_key, &mu, rho);
    let iv = faest::faest192s_hash_iv(&mut iv_pre);

    // ::7 (same as `faest_sign`: VOLE + BAVC; `cs` is the `signature.cs` buffer)
    let mut cs = [0u8; faest::FAEST192S_VOLE_CS_BYTES];
    let vole = faest::faest192s_volecommit(&mut cs, &r, &iv_pre);

    // ::8
    let mut chall1 = [0u8; faest::FAEST192S_HASH_CHALLENGE_1_OUTPUT_BYTES];
    faest::faest192s_hash_challenge_1(&mut chall1, &mu, vole.com(), &cs, iv.as_slice());

    let mut iv_bytes = [0u8; faest::FAEST192S_IV_BYTES];
    iv_bytes.copy_from_slice(iv.as_slice());

    // ::10 (same as `faest_sign`: hash `u` into `u_tilde`)
    let mut u_tilde = [0u8; faest::FAEST192S_U_TILDE_BYTES];
    faest::faest192s_hash_u_vector(&mut u_tilde, &vole, &chall1);

    // ::11: H₂⁽²⁾ init, hash `v` row-wise
    let h2_hasher = faest::faest192s_hash_challenge_2_v_matrix(&chall1, &u_tilde, &vole);

    // ::13 (same as `faest_sign`: d ← witness ⊕ u on L bytes)
    let mut d = [0u8; faest::FAEST192S_L_BYTES];
    faest::faest192s_mask_witness_d(&mut d, witness.as_slice(), &vole);

    // ::14: chall2 from H₂⁽²⁾ with `d`
    let mut chall2 = [0u8; faest::FAEST192S_HASH_CHALLENGE_2_OUTPUT_BYTES];
    faest::faest192s_hash_challenge_2_finalize(
        h2_hasher,
        d.as_ref(),
        &mut chall2,
    );

    // ::18 (Quicksilver prove — same as `faest_sign`; `pk` is `owf_input ‖` full 32-byte `owf_output`)
    let qs = faest::faest192s_prove(
        witness.as_ref(),
        &vole,
        &keypair.owf_input,
        &pk_image,
        &chall2,
    );
    // Same as `save_zk_constraints` in `faest_sign` (a1, a2 written to the signature; a0 only for chall3)
    let a0_tilde = qs.a0_tilde;
    let a1_tilde = qs.a1_tilde;
    let a2_tilde = qs.a2_tilde;

    // ::19 (H₂⁽³⁾ init — same as `faest_sign` before the chall3 / grinding loop)
    let h3_hasher = faest::faest192s_hash_challenge_3_init(
        &chall2,
        &a0_tilde,
        &a1_tilde,
        &a2_tilde,
    );
    let chall3_grind = faest::faest192s_grind_chall3(&h3_hasher, &vole);

    VrfFaest192sProofMaterial {
        witness,
        pk_image,
        mu,
        r,
        iv: iv_bytes,
        cs,
        vole,
        chall1,
        u_tilde,
        d,
        chall2,
        a0_tilde,
        a1_tilde,
        a2_tilde,
        h3_hasher,
        chall3_grind,
    }
}
