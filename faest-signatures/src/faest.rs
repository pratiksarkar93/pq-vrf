use core::marker::PhantomData;

#[cfg(not(feature = "std"))]
use alloc::{borrow::ToOwned, boxed::Box, vec::Vec};

use generic_array::{
    GenericArray,
    typenum::{Prod, U2, U16, U32, Unsigned},
};
use rand_core::CryptoRngCore;
use sha3::{Digest, Sha3_256};

use crate::{
    Error, UnpackedSecretKey,
    bavc::{BatchVectorCommitment, BavcOpenResult},
    fields::Field,
    internal_keys::{PublicKey, SecretKey},
    parameter::{BaseParameters, FAEST128fParameters, FAESTParameters, OWFParameters, TauParameters, Witness},
    prg::{IV, IVSize},
    random_oracles::{Hasher, RandomOracle},
    utils::{Reader, decode_all_chall_3, xor_arrays_into},
    vole::{
        VoleCommitResult, VoleCommitmentCRef, VoleCommitmentCRefMut, VoleReconstructResult,
        volecommit, volereconstruct,
    },
    parameter_vrf::{
        compress_faest128f_vrf_extendedwitness, FAEST128F_VRF_WITNESS_COMPRESSED_LEN,
    },
    witness_vrf::aes_extendedwitness_vrf,
};

type RO<P> =
    <<<P as FAESTParameters>::OWF as OWFParameters>::BaseParams as BaseParameters>::RandomOracle;

/// VOLE commitment result for FAEST-128f: `u` (long VOLE vector), `v` (constraint rows, same shape as
/// Quicksilver `CstrntsVal`: Λ rows × `LHatBytes` bytes per row), batch `com`, and BAVC `decom`.
#[allow(private_interfaces)]
pub type Faest128fVoleCommitResult = VoleCommitResult<
    <<FAEST128fParameters as FAESTParameters>::BAVC as BatchVectorCommitment>::LambdaBytes,
    <<FAEST128fParameters as FAESTParameters>::BAVC as BatchVectorCommitment>::NLeafCommit,
    <<FAEST128fParameters as FAESTParameters>::OWF as OWFParameters>::LHatBytes,
>;

type Faest128fOwf = <FAEST128fParameters as FAESTParameters>::OWF;
type Faest128fBP = <Faest128fOwf as OWFParameters>::BaseParams;

#[allow(private_interfaces)]
type Faest128fVoleComLen = Prod<
    <<FAEST128fParameters as FAESTParameters>::BAVC as BatchVectorCommitment>::LambdaBytes,
    U2,
>;

/// BAVC VOLE commitment `com` for FAEST-128f (2 × λ bytes).
#[allow(private_interfaces)]
pub type Faest128fVoleCom = GenericArray<u8, Faest128fVoleComLen>;

/// Total byte length of [`Faest128fVrfProofPublic`] (fixed for FAEST-128f).
pub const FAEST128F_VRF_PROOF_PUBLIC_BYTES: usize = <Faest128fOwf as OWFParameters>::LambdaBytesTimes2::USIZE
    + IVSize::USIZE
    + <<Faest128fOwf as OWFParameters>::LHatBytes as Unsigned>::USIZE
        * (<<FAEST128fParameters as FAESTParameters>::Tau as TauParameters>::Tau::USIZE - 1)
    + Faest128fVoleComLen::USIZE
    + <Faest128fBP as BaseParameters>::Chall1::USIZE
    + <Faest128fBP as BaseParameters>::VoleHasherOutputLength::USIZE
    + FAEST128F_VRF_WITNESS_COMPRESSED_LEN
    + <Faest128fBP as BaseParameters>::Chall::USIZE
    + FAEST128F_VRF_WITNESS_COMPRESSED_LEN
    + <Faest128fOwf as OWFParameters>::OutputSize::USIZE;

/// Wraps the prover's signature.
///
/// It is used by [`sign`] to write the signature into a byte-array.
struct SignatureRefMut<'a, P, O>
where
    P: FAESTParameters<OWF = O>,
    O: OWFParameters,
{
    cs: &'a mut [u8],
    u_tilde: &'a mut [u8],
    d: &'a mut [u8],
    a1_tilde: &'a mut [u8],
    a2_tilde: &'a mut [u8],
    decom_i: &'a mut [u8],
    chall3: &'a mut [u8],
    iv_pre: &'a mut [u8],
    ctr: &'a mut [u8],
    pd: PhantomData<(P, O)>,
}

impl<'a, P, O> From<&'a mut GenericArray<u8, P::SignatureSize>> for SignatureRefMut<'a, P, O>
where
    P: FAESTParameters<OWF = O>,
    O: OWFParameters,
{
    fn from(value: &'a mut GenericArray<u8, P::SignatureSize>) -> Self {
        let (cs, value) =
            value.split_at_mut(O::LHatBytes::USIZE * (<P::Tau as TauParameters>::Tau::USIZE - 1));
        let (u_tilde, value) =
            value.split_at_mut(<O::BaseParams as BaseParameters>::VoleHasherOutputLength::USIZE);
        let (d, value) = value.split_at_mut(O::LBytes::USIZE);
        let (a1_tilde, value) = value.split_at_mut(O::LambdaBytes::USIZE);
        let (a2_tilde, value) = value.split_at_mut(O::LambdaBytes::USIZE);
        let (decom_i, value) = value.split_at_mut(P::get_decom_size());
        let (chall3, value) = value.split_at_mut(O::LambdaBytes::USIZE);
        let (iv_pre, ctr) = value.split_at_mut(IVSize::USIZE);

        Self {
            cs,
            u_tilde,
            d,
            a1_tilde,
            a2_tilde,
            decom_i,
            chall3,
            iv_pre,
            ctr,
            pd: PhantomData,
        }
    }
}

impl<P, O> SignatureRefMut<'_, P, O>
where
    P: FAESTParameters<OWF = O>,
    O: OWFParameters,
{
    fn save_zk_constraints(&mut self, a1_tilde: &[u8], a2_tilde: &[u8]) {
        self.a1_tilde.copy_from_slice(a1_tilde);
        self.a2_tilde.copy_from_slice(a2_tilde);
    }

    fn mask_witness(&mut self, w: &[u8], u: &[u8]) {
        xor_arrays_into(self.d, w, u);
    }

    fn save_decom_and_ctr(&mut self, decom_i: &BavcOpenResult, ctr: u32) {
        let BavcOpenResult { coms, nodes } = decom_i;

        // Save decom_i
        let mut offset = 0;
        for slice in coms.iter().chain(nodes) {
            self.decom_i[offset..offset + slice.len()].copy_from_slice(slice);
            offset += slice.len();
        }

        // Add 0-padding to decommitment buffer
        self.decom_i[offset..].fill(0);

        // Save ctr
        self.ctr.copy_from_slice(&ctr.to_le_bytes());
    }
}

/// Wraps the signature received by the verifier.
///
/// It is used by [`verify`] to verify the byte array containing the prover's signature.
struct SignatureRef<'a, P, O>
where
    P: FAESTParameters<OWF = O>,
    O: OWFParameters,
{
    cs: &'a [u8],
    u_tilde: &'a [u8],
    d: &'a [u8],
    a1_tilde: &'a [u8],
    a2_tilde: &'a [u8],
    decom_i: &'a [u8],
    chall3: &'a [u8],
    iv_pre: &'a [u8],
    ctr: &'a [u8],
    pd: PhantomData<(P, O)>,
}

impl<'a, P, O> TryFrom<&'a GenericArray<u8, P::SignatureSize>> for SignatureRef<'a, P, O>
where
    P: FAESTParameters<OWF = O>,
    O: OWFParameters,
{
    type Error = Error;

    fn try_from(value: &'a GenericArray<u8, P::SignatureSize>) -> Result<Self, Self::Error> {
        let (cs, value) =
            value.split_at(O::LHatBytes::USIZE * (<P::Tau as TauParameters>::Tau::USIZE - 1));
        let (u_tilde, value) =
            value.split_at(<O::BaseParams as BaseParameters>::VoleHasherOutputLength::USIZE);
        let (d, value) = value.split_at(O::LBytes::USIZE);
        let (a1_tilde, value) = value.split_at(O::LambdaBytes::USIZE);
        let (a2_tilde, value) = value.split_at(O::LambdaBytes::USIZE);
        let (decom_i, value) = value.split_at(P::get_decom_size());
        let (chall3, value) = value.split_at(O::LambdaBytes::USIZE);
        let (iv_pre, ctr) = value.split_at(IVSize::USIZE);

        // ::4
        if !check_challenge_3::<P, O>(chall3) {
            return Err(Error::new());
        }

        Ok(Self {
            cs,
            u_tilde,
            d,
            a1_tilde,
            a2_tilde,
            decom_i,
            chall3,
            iv_pre,
            ctr,
            pd: PhantomData,
        })
    }
}

impl<'a, P, O> SignatureRef<'a, P, O>
where
    P: FAESTParameters<OWF = O>,
    O: OWFParameters,
{
    fn parse_decom(&self) -> BavcOpenResult<'a> {
        let node_size = O::LambdaBytes::USIZE;
        let n_coms = <P::Tau as TauParameters>::Tau::USIZE;
        let com_size = O::NLeafCommit::USIZE * O::LambdaBytes::USIZE;

        let (commits, nodes) = self.decom_i.split_at(n_coms * com_size);
        let coms = commits.chunks_exact(com_size).collect();
        let nodes = nodes.chunks_exact(node_size).collect();

        BavcOpenResult { coms, nodes }
    }

    fn parse_ctr(&self) -> u32 {
        u32::from_le_bytes(self.ctr.try_into().unwrap())
    }
}

/// Hashes required for FAEST implementation
trait FaestHash: RandomOracle {
    /// Generate `µ`
    fn hash_mu(mu: &mut [u8], input: &[u8], output: &[u8], msg: &[u8]);
    /// Generate `r` and `iv_pre`
    fn hash_r_iv(r: &mut [u8], iv_pre: &mut IV, key: &[u8], mu: &[u8], rho: &[u8]);
    /// Generate `iv`
    fn hash_iv(iv: &mut IV);
    /// Generate first challenge
    fn hash_challenge_1(chall1: &mut [u8], mu: &[u8], hcom: &[u8], c: &[u8], iv: &[u8]);
    /// Generate second challenge in an init-update-finalize style
    fn hash_challenge_2_init(chall1: &[u8], u_t: &[u8]) -> <Self as RandomOracle>::Hasher<10>;
    fn hash_challenge_2_finalize(
        hasher: <Self as RandomOracle>::Hasher<10>,
        chall2: &mut [u8],
        d: &[u8],
    );
    /// Generate third challenge
    fn hash_challenge_3(
        chall3: &mut [u8],
        chall2: &[u8],
        a0_t: &[u8],
        a1_t: &[u8],
        a2_t: &[u8],
        ctr: u32,
    );
    /// Generate third challenge in an init-finalize style
    fn hash_challenge_3_init(
        chall2: &[u8],
        a0_t: &[u8],
        a1_t: &[u8],
        a2_t: &[u8],
    ) -> <Self as RandomOracle>::Hasher<11>;
    fn hash_challenge_3_finalize(
        hasher: &<Self as RandomOracle>::Hasher<11>,
        chall3: &mut [u8],
        ctr: u32,
    );
}

impl<RO> FaestHash for RO
where
    RO: RandomOracle,
{
    fn hash_mu(mu: &mut [u8], input: &[u8], output: &[u8], msg: &[u8]) {
        // Step 3
        let mut h2_hasher = Self::h2_0_init();
        h2_hasher.update(input);
        h2_hasher.update(output);
        h2_hasher.update(msg);
        h2_hasher.finish().read(mu);
    }

    fn hash_r_iv(r: &mut [u8], iv: &mut IV, key: &[u8], mu: &[u8], rho: &[u8]) {
        // Step 4
        let mut h3_hasher = Self::h3_init();
        h3_hasher.update(key);
        h3_hasher.update(mu);
        h3_hasher.update(rho);

        let mut h3_reader = h3_hasher.finish();
        h3_reader.read(r);
        h3_reader.read(iv);
    }

    fn hash_iv(iv_pre: &mut IV) {
        // Step 5
        let mut h4_hasher = Self::h4_init();
        h4_hasher.update(iv_pre);

        let h4_reader = h4_hasher.finish();
        *iv_pre = h4_reader.read_into();
    }

    fn hash_challenge_1(chall1: &mut [u8], mu: &[u8], hcom: &[u8], c: &[u8], iv: &[u8]) {
        let mut h2_hasher = Self::h2_1_init();
        h2_hasher.update(mu);
        h2_hasher.update(hcom);
        h2_hasher.update(c);
        h2_hasher.update(iv);
        h2_hasher.finish().read(chall1);
    }

    fn hash_challenge_2_init(chall1: &[u8], u_t: &[u8]) -> Self::Hasher<10> {
        let mut h2_hasher = Self::h2_2_init();
        h2_hasher.update(chall1);
        h2_hasher.update(u_t);
        h2_hasher
    }

    fn hash_challenge_2_finalize(
        mut hasher: <Self as RandomOracle>::Hasher<10>,
        chall2: &mut [u8],
        d: &[u8],
    ) {
        hasher.update(d);
        hasher.finish().read(chall2);
    }

    fn hash_challenge_3_init(
        chall2: &[u8],
        a0_t: &[u8],
        a1_t: &[u8],
        a2_t: &[u8],
    ) -> <Self as RandomOracle>::Hasher<11> {
        let mut h2_hasher = Self::h2_3_init();
        h2_hasher.update(chall2);
        h2_hasher.update(a0_t);
        h2_hasher.update(a1_t);
        h2_hasher.update(a2_t);
        h2_hasher
    }

    fn hash_challenge_3_finalize(
        hasher: &<Self as RandomOracle>::Hasher<11>,
        chall3: &mut [u8],
        ctr: u32,
    ) {
        let mut hasher = hasher.to_owned();
        hasher.update(&ctr.to_le_bytes());
        hasher.finish().read(chall3);
    }

    fn hash_challenge_3(
        chall3: &mut [u8],
        chall2: &[u8],
        a0_t: &[u8],
        a1_t: &[u8],
        a2_t: &[u8],
        ctr: u32,
    ) {
        let mut h2_hasher = Self::h2_3_init();
        h2_hasher.update(chall2);
        h2_hasher.update(a0_t);
        h2_hasher.update(a1_t);
        h2_hasher.update(a2_t);
        h2_hasher.update(&ctr.to_le_bytes());
        h2_hasher.finish().read(chall3)
    }
}

#[inline]
pub(crate) fn faest_keygen<O, R>(rng: R) -> SecretKey<O>
where
    O: OWFParameters,
    R: CryptoRngCore,
{
    O::keygen_with_rng(rng)
}

fn check_challenge_3<P, O>(chall3: &[u8]) -> bool
where
    P: FAESTParameters,
    O: OWFParameters,
{
    let start_byte = (O::Lambda::USIZE - P::WGRIND::USIZE) / 8;

    // Discard all bits before position "lambda - w_grind"
    let start_byte_0s = chall3[start_byte] >> ((O::Lambda::USIZE - P::WGRIND::USIZE) % 8);
    if start_byte_0s != 0 {
        return false;
    }

    // Check that all the following bytes are 0s
    chall3.iter().skip(start_byte + 1).all(|b| *b == 0)
}

#[inline]
pub(crate) fn faest_sign<P>(
    msg: &[u8],
    sk: &SecretKey<P::OWF>,
    rho: &[u8],
    signature: &mut GenericArray<u8, P::SignatureSize>,
) -> Result<(), Error>
where
    P: FAESTParameters,
{
    // ::0
    let signature = SignatureRefMut::<P, P::OWF>::from(signature);
    // ::12
    let w = P::OWF::witness(sk);

    sign(msg, sk, &w, rho, signature)
}

#[inline]
pub(crate) fn faest_unpacked_sign<P>(
    msg: &[u8],
    sk_unpacked: &UnpackedSecretKey<P::OWF>,
    rho: &[u8],
    signature: &mut GenericArray<u8, P::SignatureSize>,
) -> Result<(), Error>
where
    P: FAESTParameters,
{
    // ::0
    let signature = SignatureRefMut::<P, P::OWF>::from(signature);
    sign(msg, &sk_unpacked.sk, &sk_unpacked.wit, rho, signature)
}

fn sign<P, O>(
    msg: &[u8],
    sk: &SecretKey<O>,
    witness: &Witness<O>,
    rho: &[u8],
    mut signature: SignatureRefMut<P, O>,
) -> Result<(), Error>
where
    P: FAESTParameters<OWF = O>,
    O: OWFParameters,
{
    // ::3
    let mut mu = GenericArray::<u8, O::LambdaBytesTimes2>::default();
    RO::<P>::hash_mu(&mut mu, &sk.pk.owf_input, &sk.pk.owf_output, msg);

    // ::4
    let mut r = GenericArray::<u8, O::LambdaBytes>::default();
    let iv_pre = GenericArray::from_mut_slice(signature.iv_pre);
    RO::<P>::hash_r_iv(&mut r, iv_pre, &sk.owf_key, &mu, rho);

    // ::5
    let mut iv = GenericArray::from_slice(iv_pre).to_owned();
    RO::<P>::hash_iv(&mut iv);

    // ::7
    let VoleCommitResult { com, decom, u, v } =
        volecommit::<P::BAVC, O::LHatBytes>(VoleCommitmentCRefMut::new(signature.cs), &r, &iv);

    // ::8
    //Contrarly to specification, faest-ref uses iv instead of iv_pre
    let mut chall1 = GenericArray::default();
    RO::<P>::hash_challenge_1(&mut chall1, &mu, &com, signature.cs, iv.as_slice());

    // ::10
    // hash u and write the result (i.e., u_tilde) into signature
    O::BaseParams::hash_u_vector(signature.u_tilde, &u, &chall1);

    // ::11
    // hash v row by row and update h2_hasher with the row hashes
    let mut h2_hasher = RO::<P>::hash_challenge_2_init(chall1.as_slice(), signature.u_tilde);
    O::BaseParams::hash_v_matrix(&mut h2_hasher, v.as_slice(), &chall1);

    // ::13
    // compute and write masked witness 'd' in signature
    signature.mask_witness(witness, &u[..<O as OWFParameters>::LBytes::USIZE]);

    // ::14
    let mut chall2 = GenericArray::default();
    RO::<P>::hash_challenge_2_finalize(h2_hasher, &mut chall2, signature.d);
    // ::18
    let (a0_tilde, a1_tilde, a2_tilde) = P::OWF::prove(
        witness,
        // ::16
        GenericArray::from_slice(
            &u[O::LBytes::USIZE..O::LBytes::USIZE + O::LambdaBytesTimes2::USIZE],
        ),
        &v,
        &sk.pk,
        &chall2,
    );

    // Save a1_tilde, a2_tilde in signature
    signature.save_zk_constraints(&a1_tilde.as_bytes(), &a2_tilde.as_bytes());

    // ::19
    let hasher = RO::<P>::hash_challenge_3_init(
        &chall2,
        &a0_tilde.as_bytes(),
        signature.a1_tilde,
        signature.a2_tilde,
    );

    for ctr in 0u32.. {
        // ::20
        RO::<P>::hash_challenge_3_finalize(&hasher, signature.chall3, ctr);
        // ::21
        if check_challenge_3::<P, O>(signature.chall3) {
            // ::24
            let i_delta = decode_all_chall_3::<P::Tau>(signature.chall3);

            // ::26
            if let Some(decom_i) = <P as FAESTParameters>::BAVC::open(&decom, &i_delta) {
                // Save decom_i and ctr bits
                signature.save_decom_and_ctr(&decom_i, ctr);
                return Ok(());
            }
        }
    }

    Err(Error::new())
}

/// Message binding `μ` and VOLE PRG inputs `r`, `iv` as in [`sign`] (steps 3–5), **before** ZK / witness masking.
///
/// `μ` hashes `(owf_input, owf_output, msg)`. `r` and the IV pre-state come from the FAEST `hash_r_iv` step on
/// `(owf_key, μ, ρ)`; `iv` is `hash_iv` of that pre-state. These drive `volecommit` in [`sign`].
///
/// With `ρ = []` this matches deterministic signing ([`crate::Signer::sign`] default randomness).

pub(crate) fn mu_r_iv_vrf<P>(
    msg: &[u8],
    sk: &SecretKey<P::OWF>,
    rho: &[u8],
) -> (
    GenericArray<u8, <P::OWF as OWFParameters>::LambdaBytesTimes2>,
    GenericArray<u8, <P::OWF as OWFParameters>::LambdaBytes>,
    IV,
)
where
    P: FAESTParameters,
{
    let mut mu = GenericArray::<u8, <P::OWF as OWFParameters>::LambdaBytesTimes2>::default();
    RO::<P>::hash_mu(&mut mu, &sk.pk.owf_input, &sk.pk.owf_output, msg);

    let mut r = GenericArray::<u8, <P::OWF as OWFParameters>::LambdaBytes>::default();
    let mut iv_pre = IV::default();
    RO::<P>::hash_r_iv(&mut r, &mut iv_pre, &sk.owf_key, &mu, rho);

    let mut iv = iv_pre;
    RO::<P>::hash_iv(&mut iv);

    (mu, r, iv)
}

/// FAEST-128f VRF: μ / `r` / `iv`, **VOLE** (`u`, `v`, `com`, `decom`), and the **compressed** dual-AES witness.
///
/// Runs [`mu_r_iv_vrf`] with `msg = vrf_input` (16-byte VRF block), builds the extended witness and
/// [`compress_faest128f_vrf_extendedwitness`](crate::parameter_vrf::compress_faest128f_vrf_extendedwitness),
/// then derives **VOLE-only** seeds [`vrf_fold_vole_r_iv`] from `(r, iv, vrf_witness_compressed)` and runs
/// [`volecommit`](crate::vole::volecommit) on the batch `c` slots (same layout as `signature.cs`).
/// Stock FAEST `sign` uses `r`,`iv` directly; the VRF path binds VOLE to the **compressed** witness bytes.
///
/// Then [`hash_challenge_1`], compressed `u` → `u_tilde`, [`hash_v_matrix`], masked witness `d`, and
/// [`FaestHash::hash_challenge_2_finalize`] to `chall2` (same as [`sign`] steps 8–11, 13–14).
#[allow(private_interfaces)]
pub struct Faest128fVrfProofMaterial {
    /// Message-binding hash μ = H(owf_input ‖ owf_output ‖ vrf_input).
    pub mu: GenericArray<u8, U32>,
    /// `r` from FAEST `hash_r_iv` (before folding to VOLE).
    pub r: GenericArray<u8, U16>,
    /// `iv` after `hash_iv` (before folding to VOLE); used in [`hash_challenge_1`] with `com`, `cs` (cf. `sign`).
    pub iv: IV,
    /// Seeds actually passed to [`volecommit`]: derived from `r`, `iv`, and `vrf_witness_compressed`.
    pub vole_r: GenericArray<u8, U16>,
    /// IV paired with [`Self::vole_r`] for [`volecommit`].
    pub vole_iv: IV,
    /// Batch commitment `c` slots written by [`volecommit`] (same layout as `signature.cs`).
    pub vole_cs: Box<[u8]>,
    /// Committed random linear system: long vector `u`, matrix `v` (constraint rows), `com`, `decom`.
    pub vole: Faest128fVoleCommitResult,
    /// First challenge: H(μ ‖ com ‖ cs ‖ iv) (FAEST `H2^1`).
    pub chall1: GenericArray<u8, <Faest128fBP as BaseParameters>::Chall1>,
    /// Compressed `u` via [`BaseParameters::hash_u_vector`] (same as `signature.u_tilde`).
    pub u_tilde: GenericArray<u8, <Faest128fBP as BaseParameters>::VoleHasherOutputLength>,
    /// Masked compressed witness `d = w ⊕ u` on the prefix where `u` exists; see [`mask_vrf_witness_compressed`].
    pub d: Box<[u8]>,
    /// Second challenge `chall2` after hashing `d` into the challenge-2 transcript.
    pub chall2: GenericArray<u8, <Faest128fBP as BaseParameters>::Chall>,
    /// Compressed dual extended witness: shared key/key-schedule prefix (56 B) + OWF tail + VRF tail.
    pub vrf_witness_compressed: Box<[u8]>,
    /// VRF output block `y` with `y = AES_k(vrf_input)` for the secret key `k` (same as OWF key).
    ///
    /// **Soundness** that this `y` matches the committed witness (without revealing the witness) is
    /// **not** established by [`faest128f_vrf_proof_verify`] alone — that requires a full FAEST-style
    /// verify with the dual-AES Quicksilver verifier ([`crate::zk_constraints_vrf::aes_verify_vrf_128f`],
    /// when implemented) plus VOLE reconstruction and challenges 2–3, analogous to [`faest_verify`].
    pub vrf_output: GenericArray<u8, <Faest128fOwf as OWFParameters>::OutputSize>,
}

/// FAEST-128f VRF **public** transcript: VOLE commitment `com`, batch `c` slots, and challenges,
/// without prover-only VOLE openings (`u`, `v`, [`BavcDecommitment`](crate::bavc::BavcDecommitment))
/// or PRG seeds (`r`, `vole_r`, `vole_iv`).
///
/// Includes the claimed VRF output [`Self::vrf_output`]. [`faest128f_vrf_proof_verify`] checks μ and
/// `chall1` only; **proving** `y = AES_k(vrf_input)` in zero knowledge needs the completed verifier
/// path described on [`Faest128fVrfProofMaterial::vrf_output`].
///
/// A verifier can recompute `chall1 = H(μ ‖ com ‖ cs ‖ iv)` from the public key and `vrf_input` and
/// check it against [`Self::chall1`]. Completing the FAEST challenge-2/3 chain uses the same style
/// of compact VOLE opening as in [`FAEST128fSignature`], not the full prover state in
/// [`Faest128fVrfProofMaterial`].
#[allow(private_interfaces)]
#[derive(Clone, Debug)]
pub struct Faest128fVrfProofPublic {
    /// Message-binding hash μ = H(owf_input ‖ owf_output ‖ vrf_input).
    pub mu: GenericArray<u8, U32>,
    /// `iv` after `hash_iv` (same input as [`Faest128fVrfProofMaterial::iv`] for [`crate::random_oracles::RandomOracle::hash_challenge_1`]).
    pub iv: IV,
    /// Batch commitment `c` slots (same layout as `signature.cs`).
    pub vole_cs: Box<[u8]>,
    /// BAVC commitment `com` only (binds VOLE); replaces full [`Faest128fVoleCommitResult`].
    pub vole_com: Faest128fVoleCom,
    /// First challenge: H(μ ‖ com ‖ cs ‖ iv).
    pub chall1: GenericArray<u8, <Faest128fBP as BaseParameters>::Chall1>,
    /// Compressed `u` via [`BaseParameters::hash_u_vector`].
    pub u_tilde: GenericArray<u8, <Faest128fBP as BaseParameters>::VoleHasherOutputLength>,
    /// Masked compressed witness `d = w ⊕ u` (prefix).
    pub d: Box<[u8]>,
    /// Second challenge after hashing `d` into the challenge-2 transcript.
    pub chall2: GenericArray<u8, <Faest128fBP as BaseParameters>::Chall>,
    /// Compressed dual extended witness.
    pub vrf_witness_compressed: Box<[u8]>,
    /// Claimed VRF output `y` (see [`Faest128fVrfProofMaterial::vrf_output`]).
    pub vrf_output: GenericArray<u8, <Faest128fOwf as OWFParameters>::OutputSize>,
}

impl Faest128fVrfProofPublic {
    /// Sum of all byte buffers (equals [`FAEST128F_VRF_PROOF_PUBLIC_BYTES`] for FAEST-128f).
    #[inline]
    pub fn total_bytes(&self) -> usize {
        let n = self.mu.len()
            + self.iv.len()
            + self.vole_cs.len()
            + self.vole_com.len()
            + self.chall1.len()
            + self.u_tilde.len()
            + self.d.len()
            + self.chall2.len()
            + self.vrf_witness_compressed.len()
            + self.vrf_output.len();
        debug_assert_eq!(n, FAEST128F_VRF_PROOF_PUBLIC_BYTES);
        n
    }
}

impl Faest128fVrfProofMaterial {
    /// Drops prover-only VOLE state ([`VoleCommitResult::u`], [`VoleCommitResult::v`],
    /// [`VoleCommitResult::decom`](VoleCommitResult::decom)) and PRG seeds, keeping the public
    /// commitment and transcript. See [`Faest128fVrfProofPublic`].
    pub fn into_public(self) -> Faest128fVrfProofPublic {
        let VoleCommitResult { com: vole_com, .. } = self.vole;
        Faest128fVrfProofPublic {
            mu: self.mu,
            iv: self.iv,
            vole_cs: self.vole_cs,
            vole_com,
            chall1: self.chall1,
            u_tilde: self.u_tilde,
            d: self.d,
            chall2: self.chall2,
            vrf_witness_compressed: self.vrf_witness_compressed,
            vrf_output: self.vrf_output,
        }
    }

    /// Same as [`Self::into_public`], cloning `vole_cs`, `d`, and `vrf_witness_compressed`.
    pub fn to_public(&self) -> Faest128fVrfProofPublic {
        Faest128fVrfProofPublic {
            mu: self.mu,
            iv: self.iv,
            vole_cs: self.vole_cs.clone(),
            vole_com: self.vole.com,
            chall1: self.chall1,
            u_tilde: self.u_tilde,
            d: self.d.clone(),
            chall2: self.chall2,
            vrf_witness_compressed: self.vrf_witness_compressed.clone(),
            vrf_output: self.vrf_output,
        }
    }
}

/// XORs the compressed VRF witness `w` with the VOLE long vector `u` (length `LHatBytes`).
///
/// Stock [`SignatureRefMut::mask_witness`] XORs `LBytes` of witness with `u[..LBytes]`. Here `w` is
/// [`FAEST128F_VRF_WITNESS_COMPRESSED_LEN`] bytes while `u` is shorter; we XOR `w[..u.len()]` with
/// `u` and copy `w[u.len()..]` into `d` (same as XOR against `u` zero-padded to `w.len()`).
fn mask_vrf_witness_compressed(d: &mut [u8], w: &[u8], u: &[u8]) {
    debug_assert_eq!(d.len(), FAEST128F_VRF_WITNESS_COMPRESSED_LEN);
    debug_assert_eq!(w.len(), FAEST128F_VRF_WITNESS_COMPRESSED_LEN);
    let n = u.len().min(w.len());
    xor_arrays_into(&mut d[..n], &w[..n], &u[..n]);
    if n < w.len() {
        d[n..].copy_from_slice(&w[n..]);
    }
}

/// Derives VOLE PRG inputs from FAEST `r`,`iv` and the **compressed** VRF witness (not the full 2×`L` bytes).
///
/// This is the VRF-specific binding: [`volecommit`](crate::vole::volecommit) uses `vole_r`,`vole_iv` from
/// here so the batch commitment is keyed to the compressed witness representation.
fn vrf_fold_vole_r_iv(
    r: &GenericArray<u8, U16>,
    iv: &IV,
    witness_compressed: &[u8],
) -> (GenericArray<u8, U16>, IV) {
    let mut h = Sha3_256::new();
    h.update(b"FAEST-VRF VOLE|v1|");
    h.update(r);
    h.update(iv);
    h.update((witness_compressed.len() as u64).to_le_bytes());
    h.update(witness_compressed);
    let d = h.finalize();
    let mut r_v = GenericArray::<u8, U16>::default();
    r_v.copy_from_slice(&d[..16]);
    let mut iv_v = IV::default();
    iv_v.copy_from_slice(&d[16..32]);
    (r_v, iv_v)
}

/// See [`Faest128fVrfProofMaterial`]. External code should use [`FAEST128fSigningKey::proof_vrf`](crate::FAEST128fSigningKey::proof_vrf).
pub(crate) fn faest128f_proof_vrf(
    sk: &SecretKey<<FAEST128fParameters as FAESTParameters>::OWF>,
    vrf_input: &[u8; 16],
    rho: &[u8],
) -> Faest128fVrfProofMaterial {
    type Owf = <FAEST128fParameters as FAESTParameters>::OWF;
    let (mu, r, iv) = mu_r_iv_vrf::<FAEST128fParameters>(vrf_input.as_slice(), sk, rho);

    let vrf_input_ga = GenericArray::from_slice(vrf_input.as_slice());
    let mut vrf_output = GenericArray::<u8, <Owf as OWFParameters>::OutputSize>::default();
    Owf::evaluate_owf(
        sk.owf_key.as_slice(),
        vrf_input_ga.as_slice(),
        vrf_output.as_mut_slice(),
    );
    let vrf_witness_full = aes_extendedwitness_vrf::<Owf>(
        &sk.owf_key,
        &sk.pk.owf_input,
        &sk.pk.owf_output,
        vrf_input_ga,
        &vrf_output,
    );
    let vrf_witness_compressed = compress_faest128f_vrf_extendedwitness(&vrf_witness_full);
    let (vole_r, vole_iv) = vrf_fold_vole_r_iv(&r, &iv, &vrf_witness_compressed);

    let cs_len = <<FAEST128fParameters as FAESTParameters>::OWF as OWFParameters>::LHatBytes::USIZE
        * (<<FAEST128fParameters as FAESTParameters>::Tau as TauParameters>::Tau::USIZE - 1);
    let mut cs_buf = vec![0u8; cs_len];
    let vole = volecommit::<
        <FAEST128fParameters as FAESTParameters>::BAVC,
        <<FAEST128fParameters as FAESTParameters>::OWF as OWFParameters>::LHatBytes,
    >(
        VoleCommitmentCRefMut::new(&mut cs_buf),
        &vole_r,
        &vole_iv,
    );
    let vole_cs = cs_buf.into_boxed_slice();

    let mut chall1 = GenericArray::default();
    RO::<FAEST128fParameters>::hash_challenge_1(
        chall1.as_mut_slice(),
        mu.as_slice(),
        &vole.com,
        vole_cs.as_ref(),
        iv.as_slice(),
    );

    let mut u_tilde = GenericArray::default();
    <Faest128fBP as BaseParameters>::hash_u_vector(u_tilde.as_mut_slice(), &vole.u, &chall1);

    let mut h2_hasher = RO::<FAEST128fParameters>::hash_challenge_2_init(chall1.as_slice(), u_tilde.as_slice());
    <Faest128fBP as BaseParameters>::hash_v_matrix(&mut h2_hasher, vole.v.as_slice(), &chall1);

    let mut d = vec![0u8; FAEST128F_VRF_WITNESS_COMPRESSED_LEN];
    mask_vrf_witness_compressed(&mut d, vrf_witness_compressed.as_ref(), vole.u.as_slice());
    let d = d.into_boxed_slice();

    let mut chall2 = GenericArray::default();
    RO::<FAEST128fParameters>::hash_challenge_2_finalize(h2_hasher, &mut chall2, d.as_ref());

    Faest128fVrfProofMaterial {
        mu,
        r,
        iv,
        vole_r,
        vole_iv,
        vole_cs,
        vole,
        chall1,
        u_tilde,
        d,
        chall2,
        vrf_witness_compressed,
        vrf_output,
    }
}

/// Verifies the **public** VRF transcript ([`Faest128fVrfProofPublic`]).
///
/// Performs the checks available **without** the VOLE matrix `v` or BAVC opening:
///
/// 1. `proof.d` and `proof.vrf_witness_compressed` each have length
///    [`FAEST128F_VRF_WITNESS_COMPRESSED_LEN`].
/// 2. `proof.vole_cs` has length `L̂ · (τ − 1)` for FAEST-128f (same layout as `signature.cs`).
/// 3. **Message binding:** `μ = H(owf_input ‖ owf_output ‖ vrf_input)`.
/// 4. **First challenge:** `chall1 = H(μ ‖ com ‖ cs ‖ iv)` (FAEST `H2^1`).
///
/// This does **not** validate `u_tilde`, `chall2`, or the masked witness `d` against VOLE / Quicksilver
/// (that needs `v` or the compact opening used in [`FAEST128fSignature`] verification).
///
/// It also does **not** cryptographically tie [`Faest128fVrfProofPublic::vrf_output`] to the secret key
/// or witness — that requires the full dual-AES Quicksilver verify ([`crate::zk_constraints_vrf::aes_verify_vrf_128f`],
/// currently unimplemented) and the same VOLE/challenge-3 machinery as [`faest_verify`].
///
/// External callers should use [`FAEST128fVerificationKey::vrf_proof_verify`](crate::FAEST128fVerificationKey::vrf_proof_verify).
pub(crate) fn faest128f_vrf_proof_verify(
    pk: &PublicKey<Faest128fOwf>,
    vrf_input: &[u8; 16],
    proof: &Faest128fVrfProofPublic,
) -> Result<(), Error> {
    if proof.d.len() != FAEST128F_VRF_WITNESS_COMPRESSED_LEN
        || proof.vrf_witness_compressed.len() != FAEST128F_VRF_WITNESS_COMPRESSED_LEN
    {
        return Err(Error::new());
    }
    let cs_len = <<FAEST128fParameters as FAESTParameters>::OWF as OWFParameters>::LHatBytes::USIZE
        * (<<FAEST128fParameters as FAESTParameters>::Tau as TauParameters>::Tau::USIZE - 1);
    if proof.vole_cs.len() != cs_len {
        return Err(Error::new());
    }

    let mut mu = GenericArray::<u8, <Faest128fOwf as OWFParameters>::LambdaBytesTimes2>::default();
    RO::<FAEST128fParameters>::hash_mu(
        mu.as_mut_slice(),
        pk.owf_input.as_slice(),
        pk.owf_output.as_slice(),
        vrf_input.as_slice(),
    );
    if mu != proof.mu {
        return Err(Error::new());
    }

    let mut chall1 = GenericArray::<u8, <Faest128fBP as BaseParameters>::Chall1>::default();
    RO::<FAEST128fParameters>::hash_challenge_1(
        chall1.as_mut_slice(),
        mu.as_slice(),
        proof.vole_com.as_slice(),
        proof.vole_cs.as_ref(),
        proof.iv.as_slice(),
    );
    if chall1 != proof.chall1 {
        return Err(Error::new());
    }

    Ok(())
}

#[inline]
pub(crate) fn faest_verify<P>(
    msg: &[u8],
    pk: &PublicKey<P::OWF>,
    signature: &GenericArray<u8, P::SignatureSize>,
) -> Result<(), Error>
where
    P: FAESTParameters,
{
    //::1-4
    let signature = SignatureRef::<P, P::OWF>::try_from(signature)?;

    verify::<P, P::OWF>(msg, pk, signature)
}

fn verify<P, O>(msg: &[u8], pk: &PublicKey<O>, signature: SignatureRef<P, O>) -> Result<(), Error>
where
    P: FAESTParameters<OWF = O>,
    O: OWFParameters,
{
    let ctr = signature.parse_ctr();

    // ::2
    let mut mu = GenericArray::<u8, O::LambdaBytesTimes2>::default();
    RO::<P>::hash_mu(&mut mu, &pk.owf_input, &pk.owf_output, msg);

    // ::3
    let mut iv = GenericArray::from_slice(signature.iv_pre).to_owned();
    RO::<P>::hash_iv(&mut iv);

    // ::7-8
    let chall3: &GenericArray<u8, O::LambdaBytes> = GenericArray::from_slice(signature.chall3);
    let decom_i = signature.parse_decom();
    let c = VoleCommitmentCRef::<O::LHatBytes>::new(signature.cs);
    let VoleReconstructResult { com, q } =
        volereconstruct::<P::BAVC, O::LHatBytes>(chall3, &decom_i, c, &iv).ok_or(Error::new())?;

    // ::10
    let mut chall1 = GenericArray::default();
    RO::<P>::hash_challenge_1(&mut chall1, &mu, com.as_slice(), c.as_slice(), &iv);

    let mut h2_hasher = RO::<P>::hash_challenge_2_init(chall1.as_slice(), signature.u_tilde);

    // ::12-14
    O::BaseParams::hash_q_matrix(
        &mut h2_hasher,
        q.as_slice(),
        signature.u_tilde,
        &chall1,
        P::decode_challenge_as_iter(chall3),
    );

    // ::15
    let mut chall2 = GenericArray::default();
    RO::<P>::hash_challenge_2_finalize(h2_hasher, &mut chall2, signature.d);

    // ::17
    let a0_tilde = P::OWF::verify(
        &q,
        GenericArray::from_slice(signature.d),
        pk,
        &chall2,
        chall3,
        GenericArray::from_slice(signature.a1_tilde),
        GenericArray::from_slice(signature.a2_tilde),
    );

    // ::18
    let mut chall3_prime = GenericArray::default();
    RO::<P>::hash_challenge_3(
        &mut chall3_prime,
        &chall2,
        a0_tilde.as_bytes().as_slice(),
        signature.a1_tilde,
        signature.a2_tilde,
        ctr,
    );

    // ::19
    if *chall3 == chall3_prime {
        Ok(())
    } else {
        Err(Error::new())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use generic_array::GenericArray;
    use rand::RngCore;
    #[cfg(feature = "serde")]
    use serde::{Deserialize, Serialize};

    use crate::parameter::{
        FAEST128fParameters, FAEST128sParameters, FAEST192fParameters, FAEST192sParameters,
        FAEST256fParameters, FAEST256sParameters, FAESTEM128fParameters, FAESTEM128sParameters,
        FAESTEM192fParameters, FAESTEM192sParameters, FAESTEM256fParameters, FAESTEM256sParameters,
        FAESTParameters,
    };

    const RUNS: usize = 3;

    #[generic_tests::define]
    mod faest {
        use super::*;

        #[cfg(not(feature = "std"))]
        use alloc::{vec, vec::Vec};

        use nist_pqc_seeded_rng::NistPqcAes256CtrRng;
        use rand_core::SeedableRng;

        fn random_message(mut rng: impl RngCore) -> Vec<u8> {
            let mut length = [0];
            while length[0] == 0 {
                rng.fill_bytes(&mut length);
            }
            let mut ret = vec![0; length[0] as usize];
            rng.fill_bytes(&mut ret);
            ret
        }

        #[test]
        fn sign_and_verify<P: FAESTParameters>() {
            let mut rng = NistPqcAes256CtrRng::seed_from_u64(1234);
            for _i in 0..RUNS {
                let sk = P::OWF::keygen_with_rng(&mut rng);
                let msg = random_message(&mut rng);
                let mut sigma = GenericArray::default_boxed();
                assert!(faest_sign::<P>(&msg, &sk, &[], &mut sigma).is_ok());
                let pk = sk.as_public_key();
                let res = faest_verify::<P>(&msg, &pk, &sigma);
                assert!(res.is_ok());
            }
        }

        #[cfg(feature = "serde")]
        #[test]
        fn serialize<P: FAESTParameters>() {
            let mut rng = NistPqcAes256CtrRng::seed_from_u64(1234);
            let sk = P::OWF::keygen_with_rng(&mut rng);

            let mut out = vec![];
            let mut ser = serde_json::Serializer::new(&mut out);

            sk.serialize(&mut ser).expect("serialize key pair");
            let serialized = String::from_utf8(out).expect("serialize to string");

            let mut de = serde_json::Deserializer::from_str(&serialized);
            let sk2 = SecretKey::<P::OWF>::deserialize(&mut de).expect("deserialize secret key");
            assert_eq!(sk, sk2);

            let pk = sk.as_public_key();
            let mut out = vec![];
            let mut ser = serde_json::Serializer::new(&mut out);

            pk.serialize(&mut ser).expect("serialize key pair");
            let serialized = String::from_utf8(out).expect("serialize to string");

            let mut de = serde_json::Deserializer::from_str(&serialized);
            let pk2 = PublicKey::<P::OWF>::deserialize(&mut de).expect("deserialize public key");
            assert_eq!(pk, pk2);
        }

        #[instantiate_tests(<FAEST128fParameters>)]
        mod faest_128f {}

        #[instantiate_tests(<FAEST128sParameters>)]
        mod faest_128s {}

        #[instantiate_tests(<FAEST192fParameters>)]
        mod faest_192f {}

        #[instantiate_tests(<FAEST192sParameters>)]
        mod faest_192s {}

        #[instantiate_tests(<FAEST256fParameters>)]
        mod faest_256f {}

        #[instantiate_tests(<FAEST256sParameters>)]
        mod faest_256s {}

        #[instantiate_tests(<FAESTEM128fParameters>)]
        mod faest_em_128f {}

        #[instantiate_tests(<FAESTEM128sParameters>)]
        mod faest_em_128s {}

        #[instantiate_tests(<FAESTEM192fParameters>)]
        mod faest_em_192f {}

        #[instantiate_tests(<FAESTEM192sParameters>)]
        mod faest_em_192s {}

        #[instantiate_tests(<FAESTEM256fParameters>)]
        mod faest_em_256f {}

        #[instantiate_tests(<FAESTEM256sParameters>)]
        mod faest_em_256s {}
    }

    // Test signature against TVs and verify
    #[generic_tests::define]
    mod faest_tvs {
        use super::*;
        use crate::utils::test::{hash_array, read_test_data};

        #[cfg(not(feature = "std"))]
        use alloc::vec::Vec;

        use serde::Deserialize;

        const MSG: [u8; 76] = [
            0x54, 0x68, 0x69, 0x73, 0x20, 0x64, 0x6f, 0x63, 0x75, 0x6d, 0x65, 0x6e, 0x74, 0x20,
            0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x62, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20,
            0x73, 0x70, 0x65, 0x63, 0x69, 0x66, 0x69, 0x65, 0x73, 0x20, 0x74, 0x68, 0x65, 0x20,
            0x46, 0x41, 0x45, 0x53, 0x54, 0x20, 0x64, 0x69, 0x67, 0x69, 0x74, 0x61, 0x6c, 0x20,
            0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x20, 0x61, 0x6c, 0x67, 0x6f,
            0x72, 0x69, 0x74, 0x68, 0x6d, 0x2e,
        ];

        const RHO: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];

        #[derive(Debug, Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct FaestProveData {
            lambda: usize,
            em: bool,
            sk: Vec<u8>,
            hashed_sig_s: Vec<u8>,
            hashed_sig_f: Vec<u8>,
        }

        #[test]
        fn sign_and_verify_tvs<
            FAESTSmall: FAESTParameters,
            FAESTFast: FAESTParameters<OWF = FAESTSmall::OWF>,
        >() {
            let database: Vec<FaestProveData> = read_test_data("FaestProve.json")
                .into_iter()
                .filter(|data: &FaestProveData| {
                    (data.em == FAESTSmall::OWF::IS_EM)
                        && (data.lambda == <FAESTSmall::OWF as OWFParameters>::Lambda::USIZE)
                })
                .collect();

            for data in database {
                let sk = SecretKey::<FAESTSmall::OWF>::try_from(data.sk.as_slice()).unwrap();
                let pk = sk.as_public_key();

                // Sign and compare with tvs
                let mut signature_s = GenericArray::default_boxed();
                assert!(faest_sign::<FAESTSmall>(&MSG, &sk, &RHO, &mut signature_s).is_ok());
                assert_eq!(
                    data.hashed_sig_s,
                    hash_array(signature_s.as_slice()).as_slice()
                );

                let mut signature_f = GenericArray::default_boxed();
                assert!(faest_sign::<FAESTFast>(&MSG, &sk, &RHO, &mut signature_f).is_ok());
                assert_eq!(
                    data.hashed_sig_f,
                    hash_array(signature_f.as_slice()).as_slice()
                );

                // verify
                assert!(faest_verify::<FAESTSmall>(&MSG, &pk, &signature_s).is_ok());
                assert!(faest_verify::<FAESTFast>(&MSG, &pk, &signature_f).is_ok());
            }
        }

        #[instantiate_tests(<FAEST128sParameters, FAEST128fParameters>)]
        mod faest_128 {}

        #[instantiate_tests(<FAEST192sParameters, FAEST192fParameters>)]
        mod faest_192 {}

        #[instantiate_tests(<FAEST256sParameters, FAEST256fParameters>)]
        mod faest_256 {}

        #[instantiate_tests(<FAESTEM128sParameters, FAESTEM128fParameters>)]
        mod faest_em_128 {}

        #[instantiate_tests(<FAESTEM192sParameters, FAESTEM192fParameters>)]
        mod faest_em_192 {}

        #[instantiate_tests(<FAESTEM256sParameters, FAESTEM256fParameters>)]
        mod faest_em_256 {}
    }
}

#[cfg(test)]
mod vrf_proof_public_verify_tests {
    use crate::{FAEST128fSigningKey, KeypairGenerator};
    use nist_pqc_seeded_rng::NistPqcAes256CtrRng;
    use rand_core::SeedableRng;
    use signature::Keypair;

    #[test]
    fn vrf_public_proof_accepts_valid() {
        let mut rng = NistPqcAes256CtrRng::seed_from_u64(42);
        let sk = FAEST128fSigningKey::generate(&mut rng);
        let vk = sk.verifying_key();
        let vrf_input = [7u8; 16];
        let proof = sk.proof_vrf_public(&vrf_input, &[]);
        vk.vrf_proof_verify(&vrf_input, &proof).unwrap();
    }
}
