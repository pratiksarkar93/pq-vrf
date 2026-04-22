mod vrf;

use faest::{KeypairGenerator, *};
use sha3::{Digest, Sha3_256};
use rand::RngCore;
use rand_chacha::ChaCha8Rng;
use rand_chacha::rand_core::SeedableRng;
use signature::Signer;

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
    /// Same as [`vrf::VrfFaest192sKeypair::owf_output`] for the fixed `owf_input`.
    verification_key: [u8; 16],
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
    let sk = keypair.to_bytes();
    let verification_key: [u8; 16] = vrf::aes_evaluate_owf(&keypair, &sk[..16]);
    println!("keypair: {:?}", keypair);
    println!("verification_key: {:?}", verification_key);
    VRF {
        seed,
        evaluation_key: keypair,
        verification_key,
    }
}

fn vrf_keygen_with_seed(seed: u128) -> VRF {
    let mut rng = rng_from_seed(seed);
    let keypair = vrf::vrf_keygen_with_rng(&mut rng);
    let sk = keypair.to_bytes();
    let verification_key: [u8; 16] = vrf::aes_evaluate_owf(&keypair, &sk[..16]);
    println!("keypair: {:?}", keypair);
    println!("verification_key: {:?}", verification_key);
    VRF {
        seed,
        evaluation_key: keypair,
        verification_key,
    }
}

// FAEST-192s VRF (`Faest192sVrfProofPublic`, `proof_vrf_public`, etc.) is not exposed in `faest`
// yet — only FAEST-128f VRF types exist. Uncomment when 192s VRF is implemented.

fn vrf_evaluate(
    keypair: &vrf::VrfFaest192sKeypair,
    message: &[u8],
) -> ([u8; 16], vrf::VrfFaest192sProofMaterial) {
    // Hash message to 16 bytes for AES block input
    let vrf_input: [u8; 16] = Sha3_256::digest(message)[..16]
        .try_into()
        .unwrap();

    let vrf_output: [u8; 16] = vrf::aes_evaluate_owf(keypair, &vrf_input);
    println!("vrf_input: {:?}", vrf_input);
    println!("vrf_output: {:?}", vrf_output);
    let vrf_proof = vrf::vrf_evaluate_proof(keypair, vrf_input, vrf_output, message, &[]);
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



/*
/// Recomputes `vrf_input` from `message` (same as [`vrf_evaluate`]) and checks μ + `chall1` on
/// [`Faest192sVrfProofPublic`] (see [`FAEST192sVerificationKey::vrf_proof_verify`]).
fn vrf_proof_verify(
    verifying_key: &FAEST192sVerificationKey,
    message: &[u8],
    proof: &Faest192sVrfProofPublic,
) -> Result<(), faest::Error> {
    let vrf_input: [u8; 16] = Sha3_256::digest(message)[..16]
        .try_into()
        .unwrap();
    verifying_key.vrf_proof_verify(&vrf_input, proof)
}
*/

fn main() {
    // Get a random seed once (e.g., save this to disk/DB to reproduce later)

    let vrf1 = vrf_keygen();

    let vrf2 = vrf_keygen_with_seed(vrf1.seed);

    assert_eq!(vrf1.evaluation_key.to_bytes(), vrf2.evaluation_key.to_bytes(), "Same seed => same keypair");
    assert_eq!(vrf1.verification_key, vrf2.verification_key, "Same seed => same keypair");
    let vrf3 = vrf_keygen();
    assert_ne!(vrf1.evaluation_key.to_bytes(), vrf3.evaluation_key.to_bytes(), "Different seed => different keypair");
    assert_ne!(vrf1.verification_key, vrf3.verification_key, "Different seed => different keypair");

    let (vrf1_output1, _) = vrf_evaluate(&vrf1.evaluation_key, MESSAGE.as_bytes());
    let (vrf1_output2, _) = vrf_evaluate(&vrf1.evaluation_key, MESSAGE.as_bytes());
    assert_eq!(vrf1_output1, vrf1_output2, "Same message => same VRF output");
    // vrf_proof_verify(&vrf1.verification_key, MESSAGE.as_bytes(), &vrf1_proof).expect("VRF public proof");
    // let (vrf2_output1, _) = vrf_evaluate(&vrf2.evaluation_key, MESSAGE.as_bytes());
    // let (vrf2_output2, _) = vrf_evaluate(&vrf2.evaluation_key, MESSAGE.as_bytes());

    let (_vrf3_output1, _) = vrf_evaluate(&vrf3.evaluation_key, MESSAGE.as_bytes());
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

    // Stock FAEST signing requires [`FAEST192sSigningKey`] with full OWF192; single-block keys above do not.
    let mut sk_faest = rand::thread_rng();
    let faest_sk = FAEST192sSigningKey::generate(&mut sk_faest);
    let signature: FAEST192sSignature = faest_sk.sign(MESSAGE.as_bytes());
    assert!(faest_sk
        .verifying_key()
        .verify(MESSAGE.as_bytes(), &signature)
        .is_ok());
}
