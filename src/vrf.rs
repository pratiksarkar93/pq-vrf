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
    /// `E_{owf_key}(owf_input)` from keygen: one AES-192 block encrypt of the sampled
    /// `owf_input` (see [`vrf_keygen_with_rng`], [`aes_single_block_owf192`]).
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

    /// Public verification material: fixed OWF block **`owf_input`** and its one-block image
    /// **`owf_output = E_{owf_key}(owf_input)`** (32 B, same as the first half of the FAEST-192s
    /// public-key / **μ** prefix for the single-block VRF).
    pub fn compute_verification_key(&self) -> VrfVerificationKey {
        VrfVerificationKey {
            owf_input: self.owf_input,
            owf_output: self.owf_output,
        }
    }
}

/// Public (non-secret) data for the fixed single-block OWF: the plaintext and its 16 B image
/// `E_{owf_key}(owf_input)`.
///
/// The first argument to **μ** in this VRF path is `owf_input` (as in stock FAEST); the 32 B block
/// concatenated in [`vrf_evaluate_proof`] is **`owf_output` ‖ `vrf_output`**, not this struct’s
/// fields concatenated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VrfVerificationKey {
    /// Fixed 16-byte input to the single-block OWF / AES-PRF.
    pub owf_input: [u8; 16],
    /// `E_{owf_key}(owf_input)` — the first 16 B of the 32 B “public image” half that shares **μ** with
    /// a VRF result block (see `pk_image` in [`vrf_evaluate_proof`]).
    pub owf_output: [u8; 16],
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
/// `owf_key[0] & 0b11 != 0b11`, sample random `owf_input`, then compute
/// **`owf_output = aes_single_block_owf192(owf_key, owf_input)`** — a single AES-192 block
/// encryption of the 16-byte `owf_input` under `owf_key` (16-byte ciphertext; same primitive as
/// [`aes_evaluate_owf`] with `vrf_input` replaced by the keygen `owf_input`).
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

/// H₂⁽¹⁾ — same inputs as [`vrf_evaluate_proof`] step ::8 (and internal `verify` ::10).
fn vrf_faest192s_chall1(
    mu: &[u8],
    com: &[u8],
    cs: &[u8],
    iv: &[u8],
) -> [u8; faest::FAEST192S_HASH_CHALLENGE_1_OUTPUT_BYTES] {
    let mut chall1 = [0u8; faest::FAEST192S_HASH_CHALLENGE_1_OUTPUT_BYTES];
    faest::faest192s_hash_challenge_1(&mut chall1, mu, com, cs, iv);
    chall1
}

/// H₂⁽²⁾ → **chall2** (steps ::14 / ::15), shared by prove ([`vrf_evaluate_proof`]) and verify.
fn vrf_faest192s_chall2_from_hasher(
    h2: faest::Faest192sChallenge2Hasher,
    d: &[u8; faest::FAEST192S_L_BYTES],
) -> [u8; faest::FAEST192S_HASH_CHALLENGE_2_OUTPUT_BYTES] {
    let mut chall2 = [0u8; faest::FAEST192S_HASH_CHALLENGE_2_OUTPUT_BYTES];
    faest::faest192s_hash_challenge_2_finalize(h2, d.as_ref(), &mut chall2);
    chall2
}

/// Build the same transcript as internal [`faest::faest_sign`], with the VRF extended witness (two
/// AES-192 evals) and a 32 B public image **`owf_output ‖ vrf_output`**. Returns a proof identical to
/// a **FAEST-192s signature**; `vrf_input` / `vrf_output` are **not** included (the verifier has them
/// when re-deriving μ and checking the VRF).
///
/// `r` / **IV (post-H₄)** for VOLE match stock signing: `iv_pre` from [`faest::faest192s_hash_r_iv`]
/// is **copied** before [`faest::faest192s_hash_iv`], so the packed **`iv_pre`** field matches the
/// serial signature. `vrf_output` is only used locally to form `pk_image` for `hash_mu`.
///
/// **Steps** (numbering matches comments in this file / `faest_sign` in `faest-signatures`):
/// 1. Build extended witness `w` = [`aes_extendedwitness192_vrf`], and 32 B `pk_image` = `owf_output ‖
///    vrf_output` (binds **μ** and the Quicksilver public key `pk.owf_output`).
/// 2. `::3` — **μ** ← H₂⁽⁰⁾(`owf_input ‖ pk_image ‖ msg`).
/// 3. `::4`–`::5` — **r**, **iv_pre** for VOLE seed; **iv** ← H₄(`iv_pre`) in place for the commitment
///    layer (keep a copy **iv_pre** for the packed signature).
/// 4. `::7` — VOLE+ BAVC: **cs** and commitment state (`vole`).
/// 5. `::8` — **chall1** ← H₂⁽¹⁾(μ ‖ com ‖ cs ‖ iv).
/// 6. `::10` — **ũ** from VOLE and **chall1**.
/// 7. `::11` — H₂⁽²⁾ hasher, **v** side (proves path).
/// 8. `::13` — **d** ← mask the witness with VOLE.
/// 9. `::14` — **chall2** ← H₂⁽²⁾ finalize (append **d**).
/// 10. `::18` — Quicksilver: [`faest::faest192s_prove_vrf`] (VRF OWF192 constraints; not stock
///     [`faest::faest192s_prove`]).
/// 11. `::19`–`::26` — H₂⁽³⁾ init, grind **chall3** + BAVC open, [`faest::faest192s_pack_signature`].
pub fn vrf_evaluate_proof(
    keypair: &VrfFaest192sKeypair,
    vrf_input: [u8; 16],
    vrf_output: [u8; 16],
    msg: &[u8],
    rho: &[u8],
) -> Result<VrfFaest192sProof, FaestError> {
    // (1) Witness + public 32 B OWF image for μ and for Quicksilver `PublicKey.owf_output`.
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
    let chall1 = vrf_faest192s_chall1(&mu, vole.com(), &cs, iv.as_slice());

    // ::10
    let mut u_tilde = [0u8; faest::FAEST192S_U_TILDE_BYTES];
    faest::faest192s_hash_u_vector(&mut u_tilde, &vole, &chall1);

    // ::11
    let h2_hasher = faest::faest192s_hash_challenge_2_v_matrix(&chall1, &u_tilde, &vole);

    // ::13
    let mut d = [0u8; faest::FAEST192S_L_BYTES];
    faest::faest192s_mask_witness_d(&mut d, witness.as_slice(), &vole);

    // ::14
    let chall2 = vrf_faest192s_chall2_from_hasher(h2_hasher, &d);

    // ::18
    let qs = faest::faest192s_prove_vrf(
        witness.as_ref(),
        &vole,
        &keypair.owf_input,
        &pk_image,
        &chall2,
        &vrf_input,
    );
    let a0_tilde = qs.a0_tilde;
    let a1_tilde = qs.a1_tilde;
    let a2_tilde = qs.a2_tilde;

    // ::19–::26 — H₂⁽³⁾(chall2 ‖ a0 ‖ a1 ‖ a2), grind `chall3` until BAVC opens, then pack.
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

/// Verifies a VRF proof (FAEST-192s packed signature). `msg` must match what was passed to
/// [`vrf_evaluate_proof`] (same as stock FAEST verify’s message input to **μ**).
///
/// **Steps** (parallel to internal `verify` in `faest-signatures` / `faest.rs`):
/// 1. `::2` — Recompute **μ** from `owf_input`, **pk_image** = `owf_output ‖ vrf_output`, and `msg`.
/// 2. `::3` — **iv** ← H₄(`iv_pre`); `iv_pre` is read from the signature (pre-H₄ slot).
/// 3. `::7`–`::8` — **volereconstruct**: open BAVC with **chall3** ‖ decommitment ‖ **cs**; get **com** and
///    VOLE matrix **q** (verifier does not have **v**).
/// 4. `::10` — **chall1** ← H₂⁽¹⁾(μ ‖ com ‖ cs ‖ iv); read **ũ** from the signature.
/// 5. `::11`–`::15` — H₂⁽²⁾: init with **ũ**, then feed **q**-rows (`hash_challenge_2_q_matrix`); read
///    **d** and **chall3** from the signature; finalize → **chall2**.
/// 6. Read **a1_tilde**, **a2_tilde** and `ctr` from the packed blob.
/// 7. [`faest::faest192s_vrf_verify`]: Quicksilver **::17** (`aes_verify_owf192_vrf` + VRF
///    `owf_constraints_owf192_vrf`) and H₂⁽³⁾ consistency **::18**–`::19` vs packed **chall3** / `ctr`.
pub fn vrf_proof_verify(
    verifying_key: &VrfVerificationKey,
    vrf_input: [u8; 16],
    vrf_output: [u8; 16],
    msg: &[u8],
    proof: &VrfFaest192sProof,
) -> Result<(), FaestError> {
    // ::2 — same **μ** as internal `verify` / [`vrf_evaluate_proof`]: H₂⁽⁰⁾(owf_input ‖ pk_image ‖ msg)
    let mut mu = [0u8; faest::FAEST192S_HASH_MU_OUTPUT_BYTES];
    let mut pk_image = [0u8; 32];
    pk_image[..16].copy_from_slice(&verifying_key.owf_output);
    pk_image[16..].copy_from_slice(&vrf_output);
    faest::faest192s_hash_mu(&mut mu, &verifying_key.owf_input, &pk_image, msg);

    // ::3 — **iv** ← H₄(iv_pre); `iv_pre` is packed pre-H₄ (same as [`vrf_evaluate_proof`] `iv_pre_for_sig` + [`faest192s_hash_iv`]).
    let mut iv_pre = faest::faest192s_parse_signature_iv_pre(proof.as_ref())?;
    let iv = faest::faest192s_hash_iv(&mut iv_pre);

    // ::7–8 — BAVC open + VOLE `q` from `chall3` ‖ `decom_i` ‖ `cs` (same as internal [`faest::verify`])
    let vole = faest::faest192s_volereconstruct(proof.as_ref(), &iv)?;

    // ::10 — same **chall1** as prove (H₂⁽¹⁾(μ ‖ com ‖ cs ‖ iv))
    let sigb: &[u8] = proof.as_ref();
    let cs = &sigb[0..faest::FAEST192S_VOLE_CS_BYTES];
    let chall1 = vrf_faest192s_chall1(&mu, vole.com(), cs, iv.as_slice());
    // **ũ** from the packed signature (produced by `faest192s_hash_u_vector` in proving)
    let u_tilde: &[u8; faest::FAEST192S_U_TILDE_BYTES] = <&[u8; faest::FAEST192S_U_TILDE_BYTES]>::try_from(
        &sigb[faest::FAEST192S_VOLE_CS_BYTES
            ..faest::FAEST192S_VOLE_CS_BYTES + faest::FAEST192S_U_TILDE_BYTES],
    )
    .map_err(|_| FaestError::new())?;
    // ::11–::15 verify path: H₂⁽²⁾ with **`q`** rows (not `v`; see internal [`faest::verify`])
    let h2 = faest::faest192s_hash_challenge_2_init(&chall1, u_tilde);
    // `d` and `chall3` follow `cs` ‖ `ũ` in [`faest::faest192s_pack_signature`]
    let d_off = faest::FAEST192S_VOLE_CS_BYTES + faest::FAEST192S_U_TILDE_BYTES;
    let chall3_off =
        d_off + faest::FAEST192S_L_BYTES + 2 * faest::FAEST192S_LAMBDA_BYTES + faest::FAEST192S_DECOM_I_BYTES;
    let chall3: &[u8; faest::FAEST192S_CHALL3_BYTES] = <&[u8; faest::FAEST192S_CHALL3_BYTES]>::try_from(
        &sigb[chall3_off..chall3_off + faest::FAEST192S_CHALL3_BYTES],
    )
    .map_err(|_| FaestError::new())?;
    let h2 = faest::faest192s_hash_challenge_2_q_matrix(
        h2, &vole, u_tilde, &chall1, chall3,
    );
    let d: &[u8; faest::FAEST192S_L_BYTES] = <&[u8; faest::FAEST192S_L_BYTES]>::try_from(
        &sigb[d_off..d_off + faest::FAEST192S_L_BYTES],
    )
    .map_err(|_| FaestError::new())?;
    let chall2: [u8; faest::FAEST192S_HASH_CHALLENGE_2_OUTPUT_BYTES] =
        vrf_faest192s_chall2_from_hasher(h2, d);

    // a1, a2 (Quicksilver proof coefficients); signature layout matches `faest192s_pack_signature`.
    let a1_off = d_off + faest::FAEST192S_L_BYTES;
    let a2_off = a1_off + faest::FAEST192S_LAMBDA_BYTES;
    let a1_tilde: &[u8; faest::FAEST192S_LAMBDA_BYTES] = <&[u8; faest::FAEST192S_LAMBDA_BYTES]>::try_from(
        &sigb[a1_off..a1_off + faest::FAEST192S_LAMBDA_BYTES],
    )
    .map_err(|_| FaestError::new())?;
    let a2_tilde: &[u8; faest::FAEST192S_LAMBDA_BYTES] = <&[u8; faest::FAEST192S_LAMBDA_BYTES]>::try_from(
        &sigb[a2_off..a2_off + faest::FAEST192S_LAMBDA_BYTES],
    )
    .map_err(|_| FaestError::new())?;

    // ::17–::19 — Quicksilver verify (VRF OWF192) + H₂⁽³⁾(chall2 ‖ a0 ‖ a1 ‖ a2 ‖ ctr) == chall3
    let ctr = faest::faest192s_parse_signature_ctr(proof.as_ref())?;
    faest::faest192s_vrf_verify(
        &vole,
        d,
        &verifying_key.owf_input,
        &pk_image,
        &chall2,
        chall3,
        a1_tilde,
        a2_tilde,
        &vrf_input,
        ctr,
    )?;
    Ok(())
}