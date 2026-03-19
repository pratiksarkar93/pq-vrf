use faest::*;
use rand::RngCore;
use rand_chacha::ChaCha8Rng;
use rand_chacha::rand_core::SeedableRng;
use signature::Signer;

const MESSAGE: &str = "Hello, world!";


struct VRF {
    seed: u128,
    evaluation_key: FAEST128fSigningKey,
    verification_key: FAEST128fVerificationKey,
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
    let keypair = FAEST128fSigningKey::generate(&mut rng);
    let verifying_key = keypair.verifying_key();
    VRF{seed, evaluation_key: keypair, verification_key: verifying_key}
}

fn vrf_keygen_with_seed(seed: u128) -> VRF {
    let mut rng = rng_from_seed(seed);
    let keypair = FAEST128fSigningKey::generate(&mut rng);
    let verifying_key = keypair.verifying_key();
    VRF{seed, evaluation_key: keypair, verification_key: verifying_key}
}

fn vrf_evaluate(keypair: &FAEST128fSigningKey, message: &[u8]) {
    
}

fn vrf_verify(verifying_key: &FAEST128fVerificationKey, message: &[u8], signature: &FAEST128fSignature) {
   
}

fn main() {
    // Get a random seed once (e.g., save this to disk/DB to reproduce later)

    let vrf1 = vrf_keygen();

    let vrf2 = vrf_keygen_with_seed(vrf1.seed);

    println!("Seed: {} (save this to regenerate the same keypair)", vrf1.seed);

    // Regenerate the same randomness multiple times
    assert_eq!(vrf1.evaluation_key.to_bytes(), vrf2.evaluation_key.to_bytes(), "Same seed => same keypair");

    assert_eq!(vrf1.verification_key.to_bytes(), vrf2.verification_key.to_bytes(), "Same seed => same keypair");

    let signature: FAEST128fSignature = vrf1.evaluation_key.sign(MESSAGE.as_bytes());
    let signature2: FAEST128fSignature = vrf2.evaluation_key.sign(MESSAGE.as_bytes());

    assert!(vrf1.verification_key.verify(MESSAGE.as_bytes(), &signature).is_ok());
    assert!(vrf2.verification_key.verify(MESSAGE.as_bytes(), &signature2).is_ok());
}
