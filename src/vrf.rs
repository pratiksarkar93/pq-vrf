//! VRF-oriented key material: OWF public image is **one** AES-192 block
//! `E_{owf_key}(owf_input)`, not FAEST’s full OWF192 (two AES evaluations).

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes192Enc;
use generic_array::GenericArray;
use generic_array::typenum::{U16, U24};
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

/// AES-PRF evaluation under this keypair’s `owf_key` (same as one OWF AES block on `input`).
pub fn aes_evaluate_owf(kp: &VrfFaest192sKeypair, input: &[u8]) -> [u8; 16] {
    debug_assert_eq!(input.len(), 16);
    let mut block = [0u8; 16];
    block.copy_from_slice(input);
    aes_single_block_owf192(&kp.owf_key, &block)
}
