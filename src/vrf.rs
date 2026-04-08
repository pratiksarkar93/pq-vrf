//! VRF-oriented public material from a FAEST-192s key (single AES block), distinct from FAEST’s
//! full OWF192 public key (two ciphertext blocks).

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes192Enc;
use faest::{ByteEncoding, FAEST192sSigningKey};
use generic_array::GenericArray;

/// Public bytes for “one-block” OWF: **`owf_input` ‖ `E_{owf_key}(owf_input)`** (16 + 16 = 32 B).
///
/// This uses only the **first** AES-192 encryption from the OWF192 definition (same as the first
/// half of [`faest`’s internal `OWF192::evaluate_owf`]). It does **not** include the second block
/// produced with the related plaintext (`owf_input[0] ⊕ …`).
///
/// For **FAEST signatures**, verification still requires the standard
/// [`FAEST192sSigningKey::verifying_key`] (48 B: two-block OWF output). Use this type only when you
/// intentionally want single-block public material (e.g. VRF-style exposure).
pub fn vrf_verification_key_single_block_owf(sk: &FAEST192sSigningKey) -> [u8; 32] {
    let b = sk.to_bytes();
    // `SecretKey` encoding: `owf_input` ‖ `owf_key` (16 + 24 B for OWF192).
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&b[..16]);
    let aes = Aes192Enc::new(GenericArray::from_slice(&b[16..40]));
    aes.encrypt_block_b2b(
        GenericArray::from_slice(&b[..16]),
        GenericArray::from_mut_slice(&mut out[16..]),
    );
    out
}
