use aes::cipher::{BlockEncrypt, KeyInit};
use faest::*;
use generic_array::GenericArray;
use generic_array::typenum::U16;
use sha3::{Digest, Sha3_256};
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
    // Currently the vrf_key is generated on a random input owf_input in internal_keys.rs. Set it to be 0 string. 
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

fn vrf_evaluate(keypair: &FAEST128fSigningKey, message: &[u8]) -> ([u8; 16], [u8; 16]) {
    // Secret key format: [owf_input (16 bytes), owf_key (16 bytes)]
    let sk_bytes = keypair.to_bytes();
    let owf_key = GenericArray::from_slice(&sk_bytes[16..32]);

    // Hash message to 16 bytes for AES block input
    let vrf_input: [u8; 16] = Sha3_256::digest(message)[..16]
        .try_into()
        .unwrap();

    let mut vrf_output = [0u8; 16];
    let aes = aes::Aes128Enc::new(owf_key.into());
    aes.encrypt_block_b2b(
        GenericArray::from_slice(&vrf_input).into(),
        GenericArray::from_mut_slice(&mut vrf_output).into(),
    );
    println!("vrf_output: {:?}", vrf_output);
    let vrf_proof = vrf_evaluate_proof(&keypair, vrf_input, vrf_output);
    return (vrf_output, vrf_proof);
}

fn vrf_evaluate_proof(
    keypair: &FAEST128fSigningKey,
    vrf_input: [u8; 16],
    mut vrf_output: [u8; 16],
) -> [u8; 16] {
    let sk_bytes = keypair.to_bytes();
    let _owf_input = GenericArray::<u8, U16>::from_slice(&sk_bytes[..16]);
    let owf_key = GenericArray::<u8, U16>::from_slice(&sk_bytes[16..32]);
    let aes = aes::Aes128Enc::new(owf_key.into());
    aes.encrypt_block_b2b(
        GenericArray::<u8, U16>::from_slice(&vrf_input).into(),
        GenericArray::from_mut_slice(&mut vrf_output).into(),
    );
    vrf_output
}

#[allow(dead_code)]
fn vrf_verify(
    _verifying_key: &FAEST128fVerificationKey,
    _message: &[u8],
    _signature: &FAEST128fSignature,
) {
    // Prove that the prover knows a secret k s.t. F(0)=verification_key and F(m)= VRF output
}

fn main() {
    // Get a random seed once (e.g., save this to disk/DB to reproduce later)

    let vrf1 = vrf_keygen();

    let vrf2 = vrf_keygen_with_seed(vrf1.seed);

    let vrf3 = vrf_keygen();

    let vrf1_output1 = vrf_evaluate(&vrf1.evaluation_key, MESSAGE.as_bytes());
    let vrf1_output2 = vrf_evaluate(&vrf1.evaluation_key, MESSAGE.as_bytes());
    let vrf2_output1 = vrf_evaluate(&vrf2.evaluation_key, MESSAGE.as_bytes());
    let vrf2_output2 = vrf_evaluate(&vrf2.evaluation_key, MESSAGE.as_bytes());

    let vrf3_output1 = vrf_evaluate(&vrf3.evaluation_key, MESSAGE.as_bytes());
    let vrf3_output2 = vrf_evaluate(&vrf3.evaluation_key, MESSAGE.as_bytes());


    assert_eq!(vrf1_output1, vrf1_output2, "Same message => same VRF output");
    assert_eq!(vrf2_output1, vrf2_output2, "Same message => same VRF output");
    assert_eq!(vrf1_output1, vrf2_output1, "Same seed => same VRF output on same message");

    assert_eq!(vrf3_output1, vrf3_output2, "Same seed => same VRF output on same message");

    assert_ne!(vrf1_output1, vrf3_output1, "Different Key message => Different VRF output");

    println!("Seed: {} (save this to regenerate the same keypair)", vrf1.seed);

    // Regenerate the same randomness multiple times
    assert_eq!(vrf1.evaluation_key.to_bytes(), vrf2.evaluation_key.to_bytes(), "Same seed => same keypair");

    assert_eq!(vrf1.verification_key.to_bytes(), vrf2.verification_key.to_bytes(), "Same seed => same keypair");

    let signature: FAEST128fSignature = vrf1.evaluation_key.sign(MESSAGE.as_bytes());
    let signature2: FAEST128fSignature = vrf2.evaluation_key.sign(MESSAGE.as_bytes());

    assert!(vrf1.verification_key.verify(MESSAGE.as_bytes(), &signature).is_ok());
    assert!(vrf2.verification_key.verify(MESSAGE.as_bytes(), &signature2).is_ok());
}
