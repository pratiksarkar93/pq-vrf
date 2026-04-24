mod vrf;

use faest::{KeypairGenerator, *};
use sha3::{Digest, Sha3_256};
use rand::RngCore;
use rand_chacha::ChaCha8Rng;
use rand_chacha::rand_core::SeedableRng;
use signature::{Signer, Verifier};
use std::mem;
use std::time::Instant;

const MESSAGE: &str = "Hello, world!";

// VRF Quicksilver: implement `faest_signatures::zk_constraints_vrf` + `prover_vrf` (two AES
// circuits, shared 56-byte prefix in `witness_compressed`). Standard `FAEST128fSigningKey::sign`
// still uses stock `zk_constraints::aes_prove` (single OWF).
//
// OWF192 two-plaintext extended witness (same key, `owf_input` + second plaintext): see
// `faest::aes_extendedwitness192_vrf` and `faest::extend_witness_test_vrf` in `faest-signatures`.

struct VRF {
    seed: u128,
    /// Single-block OWF keypair (`owf_output = E_k(owf_input)`); not a stock [`FAEST192sSigningKey`].
    evaluation_key: vrf::VrfFaest192sKeypair,
    /// Public: fixed [`vrf::VrfFaest192sKeypair::owf_input`] and [`vrf::VrfFaest192sKeypair::owf_output`].
    verification_key: vrf::VrfVerificationKey,
}

/// Returns a random 128-bit seed. Use [`rng_from_seed`] to regenerate the same randomness.
fn random_seed() -> u128 {
    let mut rng = rand::thread_rng();
    (rng.next_u64() as u128) | ((rng.next_u64() as u128) << 64)
}

/// Creates an RNG that produces the same sequence for a given seed.
fn rng_from_seed(seed: u128) -> ChaCha8Rng {
    let mut seed_bytes = [0u8; 32];
    seed_bytes[..16].copy_from_slice(&seed.to_le_bytes());
    ChaCha8Rng::from_seed(seed_bytes)
}
 
fn vrf_keygen() -> VRF {
    let seed = random_seed();
    let mut rng = rng_from_seed(seed);
    let keypair = vrf::vrf_keygen_with_rng(&mut rng);
    let verification_key = keypair.compute_verification_key();
    VRF {
        seed,
        evaluation_key: keypair,
        verification_key,
    }
}

fn vrf_keygen_with_seed(seed: u128) -> VRF {
    let mut rng = rng_from_seed(seed);
    let keypair = vrf::vrf_keygen_with_rng(&mut rng);
    let verification_key = keypair.compute_verification_key();
    VRF {
        seed,
        evaluation_key: keypair,
        verification_key,
    }
}

// FAEST-192s VRF (`Faest192sVrfProofPublic`, `proof_vrf_public`, etc.) is not exposed in `faest`
// yet — only FAEST-128f VRF types exist. Uncomment when 192s VRF is implemented.

/// VRF input block = first 16 bytes of SHA3-256(message) (same as prove/verify and [`vrf_evaluate`]).
fn vrf_input_from_message(message: &[u8]) -> [u8; 16] {
    Sha3_256::digest(message)[..16]
        .try_into()
        .expect("32-byte digest")
}

/// Full VRF: PRF + FAEST-192s proof (VOLE, Quicksilver, grind; expensive).
fn vrf_evaluate(
    keypair: &vrf::VrfFaest192sKeypair,
    message: &[u8],
) -> ([u8; 16], vrf::VrfFaest192sProof) {
    let vrf_input = vrf_input_from_message(message);
    let vrf_output = vrf::aes_evaluate_owf(keypair, &vrf_input);
    println!("vrf_input: {vrf_input:?}");
    println!("vrf_output: {vrf_output:?}");
    let vrf_proof = vrf::vrf_evaluate_proof(keypair, vrf_input, vrf_output, message, &[])
        .expect("vrf signature packing");
    (vrf_output, vrf_proof)
}
/*

/// Prints [`Faest128fVrfProofPublic`] (VOLE `com` + `cs` + challenges; no full `u`/`v`/BAVC decommitment).
fn print_vrf_proof_public(prep: &Faest192sVrfProofPublic) {
    println!("--- VRF public proof (Faest192sVrfProofPublic) ---");
    println!(
        "  total payload: {} B (constant {} B)",
        prep.total_bytes(),
        FAEST192S_VRF_PROOF_PUBLIC_BYTES
    );
    println!("  mu (32 B):     {:02x?}", prep.mu.as_slice());
    println!("  iv (16 B):     {:02x?}", prep.iv.as_slice());
    println!("  vole_cs len:   {} B", prep.vole_cs.len());
    println!("  vole_com:      {:02x?}", prep.vole_com.as_slice());
    println!("  chall1:        {:02x?}", prep.chall1.as_slice());
    println!("  u_tilde:       {:02x?}", prep.u_tilde.as_slice());
    println!(
        "  d (masked w):  {} B, first 24 B {:02x?}",
        prep.d.len(),
        &prep.d[..24.min(prep.d.len())]
    );
    println!("  chall2:        {:02x?}", prep.chall2.as_slice());
    println!("  vrf_output y:  {:02x?}", prep.vrf_output.as_slice());
    println!(
        "  vrf_witness_compressed: {} B, first 24 B {:02x?}",
        prep.vrf_witness_compressed.len(),
        &prep.vrf_witness_compressed[..24.min(prep.vrf_witness_compressed.len())]
    );
    println!("--- end VRF public proof ---");
}
    */




/// Recomputes `vrf_input` from `message` (same as [`vrf_evaluate`]) and runs [`vrf::vrf_proof_verify`].
fn vrf_proof_verify(
    verifying_key: &vrf::VrfVerificationKey,
    message: &[u8],
    vrf_output: &[u8; 16],
    proof: &vrf::VrfFaest192sProof,
) -> Result<(), faest::Error> {
    let vrf_input = vrf_input_from_message(message);
    vrf::vrf_proof_verify(verifying_key, vrf_input, *vrf_output, message, proof)
}


fn main() {
    // Get a random seed once (e.g., save this to disk/DB to reproduce later)

    let vrf1 = vrf_keygen();

    let vrf2 = vrf_keygen_with_seed(vrf1.seed);

    assert_eq!(vrf1.evaluation_key.to_bytes(), vrf2.evaluation_key.to_bytes(), "Same seed => same keypair");
    assert_eq!(vrf1.verification_key, vrf2.verification_key, "Same seed => same keypair");
    let vrf3 = vrf_keygen();
    assert_ne!(vrf1.evaluation_key.to_bytes(), vrf3.evaluation_key.to_bytes(), "Different seed => different keypair");
    assert_ne!(vrf1.verification_key, vrf3.verification_key, "Different seed => different keypair");

    // --- Sizes (see also `VrfFaest192sProof` = FAEST-192s packed signature) ---
    const VRF_IO_BYTES: usize = 16;
    println!("\n--- VRF type sizes (bytes) ---");
    println!(
        "  vrf verification_key:  {}  (VrfVerificationKey: owf_input + owf_output)",
        mem::size_of::<vrf::VrfVerificationKey>()
    );
    println!("  vrf_input:            {VRF_IO_BYTES}  (AES block, derived from message)");
    println!("  vrf_output:            {VRF_IO_BYTES}  (AES-PRF output)");
    println!(
        "  vrf_proof:            {}  (FAEST192S_SIGNATURE_BYTES; same as VrfFaest192sProof)",
        FAEST192S_SIGNATURE_BYTES
    );

    // --- PRF only (hash + one AES) ---
    let t0 = Instant::now();
    let vrf_input_1 = vrf_input_from_message(MESSAGE.as_bytes());
    let vrf1_output1 = vrf::aes_evaluate_owf(&vrf1.evaluation_key, &vrf_input_1);
    let vrf_eval_time = t0.elapsed();
    println!("\n--- VRF PRF (hash + AES) ---");
    println!("  {:?}  (vrf_input → vrf_output, no ZK proof)", vrf_eval_time);
    println!("  vrf_input:  {vrf_input_1:02x?}");
    println!("  vrf_output: {vrf1_output1:02x?}");
    assert_eq!(
        vrf1.verification_key.owf_output,
        vrf1.evaluation_key.owf_output,
        "vk carries the keypair OWF image"
    );

    // --- Prove (FAEST-192s-style signature / VRF proof) ---
    let t1 = Instant::now();
    let vrf1_proof = vrf::vrf_evaluate_proof(
        &vrf1.evaluation_key,
        vrf_input_1,
        vrf1_output1,
        MESSAGE.as_bytes(),
        &[],
    )
    .expect("vrf signature packing");
    let vrf_prove_time = t1.elapsed();
    assert_eq!(vrf1_proof.as_ref().len(), FAEST192S_SIGNATURE_BYTES);
    println!("\n--- VRF prove (vrf_evaluate_proof) ---");
    println!("  {vrf_prove_time:?}  (VOLE, Quicksilver, grind chall3, pack)");

    // --- Verify ---
    let t2 = Instant::now();
    vrf_proof_verify(
        &vrf1.verification_key,
        MESSAGE.as_bytes(),
        &vrf1_output1,
        &vrf1_proof,
    )
    .expect("VRF proof verifies (owf_input, pk_image, VRF Quicksilver)");
    let vrf_verify_time = t2.elapsed();
    println!("\n--- VRF verify (vrf_proof_verify) ---");
    println!("  {vrf_verify_time:?}  (reconstruct q, H₂, Quicksilver+chall3 check)");

    // --- Stock FAEST-192s on the same message (sign / verify) — comparable proof size, standard OWF192 ---
    let mut sk_faest = rand::thread_rng();
    let faest_sk = FAEST192sSigningKey::generate(&mut sk_faest);
    let faest_vk = faest_sk.verifying_key();

    let t_fs = Instant::now();
    let faest_sig: FAEST192sSignature = faest_sk.sign(MESSAGE.as_bytes());
    let faest_sign_time = t_fs.elapsed();

    let t_fv = Instant::now();
    assert!(faest_vk
        .verify(MESSAGE.as_bytes(), &faest_sig)
        .is_ok());
    let faest_verify_time = t_fv.elapsed();

    println!("\n--- Stock FAEST-192s (same message) ---");
    println!(
        "  sign:   {faest_sign_time:?}  (witness + VOLE + stock Quicksilver + grind; {} B sig)",
        faest_sig.as_ref().len()
    );
    println!("  verify: {faest_verify_time:?}  (standard FAEST-192s verify path)");

    println!("\n--- VRF vs FAEST-192s (wall time) ---");
    println!("  VRF PRF only (hash + AES):     {vrf_eval_time:?}");
    println!("  VRF prove (vrf_evaluate_proof): {vrf_prove_time:?}  |  FAEST sign: {faest_sign_time:?}");
    println!("  VRF verify:                     {vrf_verify_time:?}  |  FAEST verify: {faest_verify_time:?}");

    // Same VRF input/output (AES-PRF is deterministic).
    assert_eq!(
        vrf1_output1,
        vrf::aes_evaluate_owf(&vrf1.evaluation_key, &vrf_input_from_message(MESSAGE.as_bytes())),
        "Same message => same VRF output"
    );
    // let (vrf2_output1, _) = vrf_evaluate(&vrf2.evaluation_key, MESSAGE.as_bytes());
    // let (vrf2_output2, _) = vrf_evaluate(&vrf2.evaluation_key, MESSAGE.as_bytes());

    let (_vrf3_output1, _vrf3_proof) = vrf_evaluate(&vrf3.evaluation_key, MESSAGE.as_bytes());
    // let (vrf3_output2, _) = vrf_evaluate(&vrf3.evaluation_key, MESSAGE.as_bytes());

    // assert_eq!(vrf1_output1, vrf1_output2, "Same message => same VRF output");
    // assert_eq!(vrf2_output1, vrf2_output2, "Same message => same VRF output");
    // assert_eq!(vrf1_output1, vrf2_output1, "Same seed => same VRF output on same message");

    // assert_eq!(vrf3_output1, vrf3_output2, "Same seed => same VRF output on same message");

    // assert_ne!(vrf1_output1, vrf3_output1, "Different Key message => Different VRF output");

    println!("Seed: {} (save this to regenerate the same keypair)", vrf1.seed);

    // Regenerate the same randomness multiple times
    assert_eq!(vrf1.evaluation_key.to_bytes(), vrf2.evaluation_key.to_bytes(), "Same seed => same keypair");

    assert_eq!(vrf1.verification_key, vrf2.verification_key, "Same seed => same keypair");
}
