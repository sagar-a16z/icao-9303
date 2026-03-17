# icao-9303 — Development Guide

## Current state

### Working (and proven in ZK)
- **SOD signature verification** — RSA-PSS-SHA256 and ECDSA P-256, auto-detected from SPKI type
- **DG hash integrity** — SHA-256 of each DG (1,2,3,4,14) checked against SOD commitments
- **Certificate chain verification** — DS cert signed by CSCA (RSA-PSS or ECDSA, auto-detected). Outputs SHA-256 of CSCA SPKI for trust store lookup.
- **MRZ selective disclosure** — `verify_passport_packed(disclosure_mask, passport) -> PassportProofOutput` returns only requested fields (nationality, DOB, sex, expiry, issuing state)
- **Predicate proofs** — `check_age(min_age, current_date, ...)` and `check_not_expired(current_date, ...)` auto-detect RSA/ECDSA. Only hash DG1, 57% fewer cycles than full disclosure.
- **p256_fast ECDSA** — hand-tuned Solinas reduction + Montgomery scalar field. ~6M cycles (was 74M before, 2.7x RSA vs 33x before).
- **Private passport input** — `PassportData` struct (including CSCA cert) passed as `PrivateInput<T>`, cryptographically hidden by BlindFold
- **BlindFold ZK** — `zk` feature on host and guest; witness hidden, verifier sees only `(disclosure_mask, PassportProofOutput)`
- **jolt-inlines-sha2** — constraint-native SHA-256 for DG hashing (feature-gated `jolt-sha2`)

### Working (not in ZK guest)
- **Multi-size RSA cert verification** — `verify_cert_signature(&ds, &csca)` supports RSA-PSS 2048/3072/4096-bit keys
- **EfCom decoder** — `EfCom::from_bytes()` parses TLV listing which DGs are present

### Working (infrastructure)
- Full ASN.1/DER/CMS parsing: `EfSod`, `LdsSecurityObject`, `EfDg14`, `EfCom`
- `DigestAlgorithmIdentifier::hash_bytes()` / `hash_der()` — SHA-1/256/384/512
- `RSAPublicKey::verify()` — RFC 8017 RSA-PSS with constant-time and variable-time exponentiation
- `verify_pss_em()` — standalone PSS padding verification (used by advice-based RSA path)
- `ModRing` Montgomery arithmetic over generic `Uint<B,L>`
- `MrzRaw` — fixed-size byte array MRZ parser for ZK guest use
- BAC, Secure Messaging (3DES + AES), Chip Authentication skeleton, PACE key derivation
- **Advice-based RSA modexp** — guest/src/bignum.rs provides wide multiply + squaring verification; host provides (quotient, remainder) via `#[jolt::advice]`; guest verifies `a*b == q*n + r` for each of 17 steps (e=65537)

### Missing
- **RSA-4096 in ZK guest** — library supports 4096-bit RSA, not yet wired into Jolt guest
- **CSCA trust store** — verifier gets CSCA pubkey hash but no on-chain/off-chain trust store lookup yet. Note: `csca_pubkey_hash` in output leaks issuing country — long-term fix is Merkle inclusion proof against a global trust root.
- **`jolt-inlines-p256`** — constraint-native P-256 would reduce ECDSA from ~6M to ~500K cycles (requires upstream Jolt SDK work)

## Jolt ZK setup

- **Host**: `jolt-sdk` with `features = ["host", "zk"]`
- **Guest**: `jolt-sdk` with `features = ["guest-std", "zk"]`
- Seven provable functions — RSA and ECDSA split for optimal trace lengths:
  - ECDSA variants (trace sized for ECDSA P-256):
    - `verify_passport_packed(mask, PrivateInput<Vec<u8>>, PrivateInput<PassportDGs>)` — max_trace 2^24
    - `check_age(min_age, current_date, PrivateInput<...>, PrivateInput<...>)` — max_trace 2^23
    - `check_not_expired(current_date, PrivateInput<...>, PrivateInput<...>)` — max_trace 2^23
  - RSA variants (tighter trace lengths):
    - `verify_passport_packed_rsa(...)` — max_trace 2^23
    - `check_age_rsa(...)` — max_trace 2^21
    - `check_not_expired_rsa(...)` — max_trace 2^21
  - `verify_passport_struct(mask, PrivateInput<PassportData>)` — baseline, max_trace 2^24
  - Host selects RSA vs ECDSA variant based on dataset key type
- `pack_preparsed_passport()` extracts byte fields from SOD/CSCA on host, packs with raw DG bytes
- Guest structural integrity checks: messageDigest ↔ LDS hash, DS SPKI ↔ TBS offset
- `PassportData` includes `sod`, `dg1-4`, `dg14`, and `csca` (all `Vec<u8>`)
- `PassportProofOutput` includes `valid`, selective MRZ fields, and `csca_pubkey_hash: [u8; 32]`
- Host passes `PrivateInput::new(...)` — verifier API excludes it automatically
- BlindFold setup: `prover_prep.blindfold_setup()` → 3-arg `preprocess_verifier_*(shared, verifier_setup, Some(blindfold_setup))`
- Jolt SDK pinned to commit `97b2c96` (Rust 1.94 update)

## Measured performance (Apple M4 MacBook Pro, single-threaded)

| Variant | RSA trace | RSA time | RSA RAM | ECDSA trace | ECDSA time | ECDSA RAM |
|---------|-----------|----------|---------|-------------|------------|-----------|
| **Full disclosure** | 2^23 | ~18s | 7 GB | 2^24 | ~34s | 13 GB |
| **Age predicate** | 2^21 | ~7s | 3 GB | 2^23 | ~20s | 8 GB |
| **Not-expired predicate** | 2^21 | ~7s | 3 GB | 2^23 | ~20s | 8 GB |

Proving time and peak memory scale with `max_trace_length`, not actual cycle count.

## Per-section cycle breakdowns

**RSA age predicate (1.49M cycles, advice-based modexp):**

| Section | Cycles | % |
|---------|--------|---|
| `rsa_advice_modexp` (SOD) | 461,162 | 31.0% |
| `rsa_advice_modexp` (cert chain) | 460,787 | 31.0% |
| `rsa_pss_verify` (cert chain) | 119,849 | 8.1% |
| `rsa_pss_verify` (SOD) | 93,335 | 6.3% |
| `parse_lds` | 41,189 | 2.8% |
| `structural_checks` | 26,547 | 1.8% |
| `hash_signed_attrs` | 20,478 | 1.4% |
| `csca_hash` | 18,041 | 1.2% |
| `dg_hash_verify` (DG1 only) | 8,309 | 0.6% |
| `mrz_parse` | 1,044 | 0.1% |
| serde + overhead | ~237,000 | 15.9% |

**ECDSA packed (9.3M cycles):**

| Section | Cycles | % |
|---------|--------|---|
| `ecdsa_verify` (cert chain) | 2,921,333 | 31.5% |
| `ecdsa_verify` (SOD) | 2,898,176 | 31.3% |
| `dg_hash_verify` (5 DGs) | 2,800,224 | 30.2% |
| `parse_lds` | 43,178 | 0.5% |
| `structural_checks` | 23,569 | 0.3% |
| `hash_signed_attrs` | 21,198 | 0.2% |
| `csca_hash` | 8,143 | 0.1% |
| `mrz_parse` | 421 | ~0% |
| serde + overhead | ~554,000 | 6.0% |

Note: ~1.7M cycles from postcard deserialization of ~64KB via `PrivateInput` in full disclosure variants. Predicate variants deserialize only ~2.4KB preparsed buffer + 93B DG1, cutting serde overhead to ~126K. True zerocopy would need jolt-sdk changes to bypass postcard serde at the advice boundary.

## Test data details

### `tests/dataset/` — BSI TR-03105-5 ReferenceDataSet (German)
- `Datagroup1-4.bin`, `Datagroup14.bin`, `Datagroup15.bin` — raw DG files
- `EF_SOD.bin` — commits to DGs 1,2,3,4,14. Signed by HJP PB DS (RSA-PSS-SHA256)
- No CSCA cert available (HJP PB CS is proprietary, not publicly distributed)
- MRZ: ERIKA MUSTERMANN, DOB 960812, expiry 231031, nationality D<<

### `tests/dataset-my/` — Malaysian passport (from gmrtd project)
- `EF_SOD.bin` — RSA-PSS-SHA256, 2048-bit DS key
- `CSCA.cer` — 3072-bit RSA, self-signed Malaysian CSCA (valid 2019-2029)
- `DSC.cer` — DS certificate signed by CSCA
- DG hashes only (no DG binaries) — can verify steps 1+3 but not step 2

### `tests/dataset-synth/` — Synthetic RSA e2e dataset
- Regenerate: `./tests/gen-synthetic-dataset.sh`
- Uses BSI DG files from `tests/dataset/` for complete steps 1+2+3

### `tests/dataset-synth-ecdsa/` — Synthetic ECDSA P-256 e2e dataset
- Regenerate: `./tests/gen-synthetic-dataset-ecdsa.sh`
- Uses BSI DG files from `tests/dataset/` for complete steps 1+2+3

## What to work on (priority order)
1. Generate synthetic RSA-4096 dataset + `verify_passport_rsa4096` provable function
2. CSCA trust store — Merkle inclusion proof against global trust root (fixes country leak from `csca_pubkey_hash`)
3. Make DG set flexible instead of hardcoded `[1,2,3,4,14]`
4. Test real CSCA cert parsing from ICAO PKD (library-side tests)
5. Cross-validate custom crypto (RSA-PSS, ECDSA P-256) against RustCrypto crates in CI
6. Fuzz `p256_reduce()`, `verify_pss()`, `EcdsaSignature::from_der()`

## Optimization opportunities
1. **Zerocopy `PrivateInput`** — ~1.7M cycles (24% of full disclosure). Jolt SDK's `#[jolt::provable]` macro always uses postcard serde for `PrivateInput<T>`, even though `AdviceTapeIO` trait exists with bytemuck zero-copy. Requires upstream jolt-sdk PR to use `AdviceTapeIO` when available.
2. **`jolt-inlines-p256`** — would reduce ECDSA from ~6M to ~500K cycles. Requires upstream Jolt SDK work to add P-256 as a native instruction set (similar to existing `jolt-inlines-secp256k1` for Bitcoin's curve).
3. ~~**DER parsing offload**~~ — Done. Host pre-parses SOD/CSCA, saving ~450K cycles (5.9%).
4. ~~**ECDSA Jacobian + new_unchecked**~~ — Done. 202M → 74M cycles (2.73x improvement).
5. ~~**p256_fast Solinas reduction**~~ — Done. 74M → 6M cycles (12.3x). Hand-tuned `[u64; 4]` arithmetic with FIPS 186-4 D.2.3 Solinas reduction + Montgomery scalar field.
6. ~~**Advice-based RSA modexp**~~ — Done. Replaces Montgomery ring_setup+encode+pow_vt with 17 advice-verified modmul steps. RSA age predicate: 2.24M → 1.49M cycles (33.7% reduction). Inspired by [atheonxyz/jolt#6](https://github.com/atheonxyz/jolt/pull/6).
7. ~~**RSA/ECDSA provable split**~~ — Done. Separate provable functions with tuned max_trace_length. RSA predicates: 2^23 → 2^21 (9 GB → 3 GB, 26s → 7s). RSA packed: 2^24 → 2^23 (13 GB → 7 GB, 51s → 18s).

Note: RSA `analyze` no longer works (advice tape not populated in trace-only mode). Use `analyze --dataset ecdsa` for ECDSA, or run `age`/`packed` directly for RSA cycle counts in prove output.
