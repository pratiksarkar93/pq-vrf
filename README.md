# FAEST-192s VRF (pq-vrf)

The `src/` crate implements a **post-quantum verifiable random function (VRF)** whose outputs and proofs are tied to **FAEST-192s**: the prover runs the same VOLE → Quicksilver → grind pipeline as a standard FAEST-192s signature, but the one-way function inside the zero-knowledge proof is the **VRF OWF192** path (two AES-192 evaluations in a single extended witness), not the stock single-OWF signing circuit.

The core logic lives in [`src/vrf.rs`](src/vrf.rs). [`src/main.rs`](src/main.rs) is a runnable demo (keygen, PRF timing, prove, verify, comparison to stock FAEST-192s sign/verify).

Paper: Coming Soon
FAEST V2.0 Paper: https://faest.info/faest-spec-v2.0.pdf

## Objects (types)

| Role | Type | Notes |
|------|------|--------|
| Secret key | `VrfFaest192sKeypair` | 16 B `owf_input`, 24 B `owf_key`, 16 B `owf_output = E_{owf_key}(owf_input)` (one AES block). Layout matches the first 40 B of a FAEST-192s secret. |
| Public key | `VrfVerificationKey` | `owf_input` and `owf_output` only (32 B). |
| Message-derived input | `vrf_input` (16 B) | First 16 bytes of **SHA3-256**(`message`). Same derivation for prove and verify. |
| VRF output | `vrf_output` (16 B) | `aes_evaluate_owf`: one AES-192 block `E_{owf_key}(vrf_input)`. |
| Proof | `VrfFaest192sProof` | Alias of `FAEST192sSignature` — same packed size and layout as a normal FAEST-192s signature (`FAEST192S_SIGNATURE_BYTES`). `vrf_input` / `vrf_output` are **not** inside the blob; the verifier recomputes `vrf_input` and uses the published `vrf_output`. |

**Binding in μ:** For the VRF transcript, the 32-byte public image passed into `faest192s_hash_mu` is **`pk_image = owf_output ‖ vrf_output`** (first half is the fixed OWF image, second half is the VRF result). That ties the proof to both the long-term key and the derived output.

## Protocol flow

1. **Key generation** — [`vrf_keygen_with_rng`](src/vrf.rs) (see `src/vrf.rs`):
   - **Sample `owf_key` (24 B):** fill from the RNG; resample until the low two bits of `owf_key[0]` are not both 1 (`owf_key[0] & 0b11 != 0b11`), matching FAEST OWF192 keygen.
   - **Sample `owf_input` (16 B)** uniformly at random.
   - **Derive `owf_output` (16 B):** one **AES-192 block encryption** of `owf_input` under `owf_key` — the same single-block path as VRF PRF evaluation, but with the *keygen-time* random `owf_input` instead of a message-derived `vrf_input`. Concretely `owf_output = AES-192_encrypt(owf_key, owf_input)` (single-block helper in `src/vrf.rs` using `Aes192Enc`; one block in/out, not a mode over multiple blocks).
   - `compute_verification_key()` returns only `owf_input` and `owf_output` (the secret is `owf_key`).

2. **Evaluate (prover)** — Given `message`:
   - `vrf_input ←` first 16 B of SHA3-256(`message`).
   - `vrf_output ← aes_evaluate_owf(keypair, vrf_input)` (deterministic PRF under the secret `owf_key`).
   - **Prove:** `vrf_evaluate_proof(keypair, vrf_input, vrf_output, msg, rho)` builds the extended witness (`aes_extendedwitness192_vrf` in `faest-signatures`), runs `faest192s_prove_vrf` (VRF Quicksilver constraints), packs with `faest192s_pack_signature`. Use `rho = &[]` if you do not need an extra signing randomness string.

3. **Verify** — `vrf_proof_verify(verifying_key, vrf_input, vrf_output, msg, proof)`: recomputes μ from `owf_input`, `pk_image = owf_output ‖ vrf_output`, and `msg`; reconstructs VOLE from the packed signature; runs `faest192s_vrf_verify` to check Quicksilver and challenge consistency.

## Dependencies

VRF proving and verification call into the **`faest-signatures`** subtree (e.g. `aes_extendedwitness192_vrf`, `faest192s_prove_vrf`, `faest192s_vrf_verify`, `zk_constraints_vrf`). Those items implement the second AES in the witness and the VRF-specific constraint system.

## Running the demo

From the repo root:

```bash
cargo run
```

For **timing numbers that are representative of production work**, use an optimized build:

```bash
cargo run --release
```

The binary prints type sizes, PRF/prove/verify wall times, and a comparison with stock `FAEST192sSigningKey` sign/verify on the same message.

## Output: timings and sizes

Timings are **single run**, **wall-clock** samples on your machine (`std::time::Instant`); they will vary with CPU, load, and build profile (use `cargo run --release` for representative numbers).

### Proof and signature size

| Object | Size | Notes |
|--------|------|--------|
| **VRF proof** (`VrfFaest192sProof` / `FAEST192sSignature`) | **11260 B** | Constant `FAEST192S_SIGNATURE_BYTES` from `faest`; the VRF “proof” is a packed signature blob (same format as standard FAEST-192s). |
| **FAEST-192s signature** (stock `FAEST192sSigningKey::sign`) | **11260 B** | Identical length to the VRF proof; the binary prints this in the `Stock FAEST-192s` line (`… B sig`). |
| `vrf_input` / `vrf_output` | 16 B each | Not included inside the proof; transmitted or recomputed by the verifier. |
| `VrfVerificationKey` | 32 B | Printed under `--- VRF type sizes ---`. |

### Timings printed by `main`

| `main` section (banner) | Variable / line | What is included in the span |
|-------------------------|-----------------|-----------------------------|
| `--- VRF PRF (hash + AES) ---` | one `Duration` | SHA3-256 of the message, first 16 B → `vrf_input`, then `aes_evaluate_owf` → `vrf_output` (no ZK / no VOLE). |
| `--- VRF prove (vrf_evaluate_proof) ---` | `vrf_prove_time` | Full VRF prover: extended witness, VOLE, `faest192s_prove_vrf`, challeng3 grind, `faest192s_pack_signature`. |
| `--- VRF verify (vrf_proof_verify) ---` | `vrf_verify_time` | Parse/reconstruct from packed proof, H₂, Quicksilver VRF check (`faest192s_vrf_verify` path in `vrf::vrf_proof_verify`). |
| `--- Stock FAEST-192s (same message) ---` | `sign: …`, `verify: …` | Standard FAEST-192s `sign` / `verify` on the same message and same proof length (stock OWF + Quicksilver, not the VRF circuit). |
| `--- VRF vs FAEST-192s (wall time) ---` | three lines | Same wall times in one place: VRF PRF; then VRF prove **and** FAEST sign; then VRF verify **and** FAEST verify (the middle and bottom lines echo the `VRF prove` / `VRF verify` and `Stock FAEST-192s` numbers). |

The **PRF** line is the cheap step (hash + one AES). **Prove** and **verify** cost most of the time. VRF prove uses `faest192s_prove_vrf`; stock sign uses the standard OWF192 prover—both output **11260** B signatures. Compare **VRF prove** to **FAEST sign** and **VRF verify** to **FAEST verify** in the last block.

### Example timings (`cargo run --release`)

The following is **one** successful run of `cargo run --release`. Your output will not match: seeds and wall-clock durations change each run; use the table as a **rough order-of-magnitude** reference.

| Step | Time |
|------|------:|
| VRF PRF (hash + AES) | 2.708 µs |
| VRF prove (`vrf_evaluate_proof`) | 317.198917 ms |
| VRF verify (`vrf_proof_verify`) | 268.2155 ms |
| FAEST-192s sign | 271.872166 ms |
| FAEST-192s verify | 264.407416 ms |

### Machine used for the example timings

| Type | Specs |
| --- | --- |
| Model | MacBook Pro (`MacBookPro17,1`) |
| Chip | Apple M1 |
| Cores | 8 (4 performance + 4 efficiency) |
| Memory | 16 GB |
| OS | macOS 15.4.1 |

Re-run `cargo run --release` on your own machine for comparable wall times.
