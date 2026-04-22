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

/// Transcript for the FAEST-192s VRF path through **chall2** (after steps 13–14): same *logical* pieces
/// as a [`faest::SignatureRefMut`] through masked witness `d` and H₂⁽²⁾, but as owned buffers.
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
/// 13–14** as [`faest_sign`]: r/iv, VOLE, [`faest::faest192s_hash_challenge_1`], `ũ`, H₂⁽²⁾+`v`,
/// [`faest::faest192s_mask_witness_d`], and [`faest::faest192s_hash_challenge_2_finalize`].
/// `owf_output ‖ vrf_output` is the 32-byte public image (stock OWF192 length). Use the same `msg` and
/// `rho` as in a full signature when wiring VOLE.
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
    }
}
