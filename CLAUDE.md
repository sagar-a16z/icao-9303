# icao-9303 — Development Guide

## What this is
Rust implementation of ICAO 9303 electronic passport (eMRTD) parsing, cryptography, and NFC communication. Includes a Jolt ZK proof that verifies passport authenticity with selective MRZ disclosure.

## Current state

### Working (and proven in ZK)
- **SOD signature verification** — RSA-PSS-SHA256 and ECDSA P-256, auto-detected from SPKI type
- **DG hash integrity** — SHA-256 of each DG (1,2,3,4,14) checked against SOD commitments
- **Certificate chain verification** — DS cert signed by CSCA (RSA-PSS or ECDSA, auto-detected). Outputs SHA-256 of CSCA SPKI for trust store lookup.
- **MRZ selective disclosure** — `verify_passport_packed(disclosure_mask, passport) -> PassportProofOutput` returns only requested fields (nationality, DOB, sex, expiry, issuing state)
- **Predicate proofs** — `check_age(min_age, current_date, ...)` and `check_nationality(allowed, ...)` auto-detect RSA/ECDSA. Only hash DG1, 57% fewer cycles than full disclosure.
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
- `ModRing` Montgomery arithmetic over generic `Uint<B,L>`
- `MrzRaw` — fixed-size byte array MRZ parser for ZK guest use
- BAC, Secure Messaging (3DES + AES), Chip Authentication skeleton, PACE key derivation

### Missing
- **RSA-4096 in ZK guest** — library supports 4096-bit RSA, not yet wired into Jolt guest
- **Expiry checking** — proof outputs expiry date but doesn't verify `expiry > today` inside guest
- **CSCA trust store** — verifier gets CSCA pubkey hash but no on-chain/off-chain trust store lookup yet
- **`jolt-inlines-p256`** — constraint-native P-256 would reduce ECDSA from ~6M to ~500K cycles (requires upstream Jolt SDK work)

## Passive Authentication steps (ICAO 9303 Part 11)

| Step | What | Status |
|------|------|--------|
| 1 | Verify SOD signature (DS cert signs LdsSecurityObject) | Done + ZK proven |
| 2 | Verify each DG hashes to its SOD commitment | Done + ZK proven |
| 3 | Verify DS cert was signed by CSCA | Done + ZK proven |
| 4 | Verify CSCA is in a trusted root store | CSCA pubkey hash output for external verification |

## Jolt ZK setup

- **Host**: `jolt-sdk` with `features = ["host", "zk"]`
- **Guest**: `jolt-sdk` with `features = ["guest-std", "zk"]`
- Four provable functions (all auto-detect RSA vs ECDSA from SPKI type):
  - `verify_passport_packed(mask, PrivateInput<Vec<u8>>, PrivateInput<PassportDGs>)` — host pre-parses SOD/CSCA, guest skips DER parsing
  - `verify_passport_struct(mask, PrivateInput<PassportData>)` — baseline, guest does full CMS/X.509 parsing
  - `check_age(min_age, current_date, PrivateInput<...>, PrivateInput<...>)` — DG1-only predicate proof
  - `check_nationality(allowed, allowed_count, PrivateInput<...>, PrivateInput<...>)` — DG1-only predicate proof
- `pack_preparsed_passport()` extracts byte fields from SOD/CSCA on host, packs with raw DG bytes
- Guest structural integrity checks: messageDigest ↔ LDS hash, DS SPKI ↔ TBS offset
- `PassportData` includes `sod`, `dg1-4`, `dg14`, and `csca` (all `Vec<u8>`)
- `PassportProofOutput` includes `valid`, selective MRZ fields, and `csca_pubkey_hash: [u8; 32]`
- Host passes `PrivateInput::new(...)` — verifier API excludes it automatically
- BlindFold setup: `prover_prep.blindfold_setup()` → 3-arg `preprocess_verifier_*(shared, verifier_setup, Some(blindfold_setup))`
- Jolt SDK pinned to commit `97b2c96` (Rust 1.94 update)

## Performance

### Cycle counts (all combinations)

| Variant | RSA-PSS-SHA256 | ECDSA P-256 | `max_trace_length` |
|---------|---------------|-------------|-------------------|
| **Full disclosure (packed)** | 5,291,277 | 9,269,988 | 2^24 |
| **Full disclosure (struct)** | 6,068,916 | 9,885,762 | 2^24 |
| **Age predicate (DG1-only)** | 2,244,803 | 6,048,286 | 2^23 |
| **Nationality predicate (DG1-only)** | ~2,245,000 | ~6,048,000 | 2^23 |

Estimated prove times (Apple M-series, single-threaded):

| `max_trace_length` | Peak RAM | RSA prove time | ECDSA prove time |
|-------------------|----------|---------------|-----------------|
| 2^23 (predicates) | <10 GB | ~9s | ~15s |
| 2^24 (full disclosure) | ~15 GB | ~20s | ~25s |

### Per-section breakdown

**RSA packed (5.3M cycles):**

| Section | Cycles | % |
|---------|--------|---|
| `dg_hash_verify` (5 DGs) | 2,800,236 | 52.9% |
| `rsa_verify` (cert chain) | 789,545 | 14.9% |
| `rsa_verify` (SOD) | 767,029 | 14.5% |
| `ring_setup` (×2) | 213,563 | 4.0% |
| `mont_encode` (×2) | 122,760 | 2.3% |
| `parse_lds` | 42,155 | 0.8% |
| `structural_checks` | 26,589 | 0.5% |
| `hash_signed_attrs` | 21,198 | 0.4% |
| `csca_hash` | 17,817 | 0.3% |
| `mrz_parse` | 421 | ~0% |
| serde + overhead | ~490,000 | 9.3% |

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

**ECDSA age predicate (6.0M cycles):**

| Section | Cycles | % |
|---------|--------|---|
| `ecdsa_verify` (cert chain) | 2,920,123 | 48.3% |
| `ecdsa_verify` (SOD) | 2,898,176 | 47.9% |
| `parse_lds` | 42,103 | 0.7% |
| `structural_checks` | 23,527 | 0.4% |
| `hash_signed_attrs` | 20,478 | 0.3% |
| `dg_hash_verify` (DG1 only) | 8,297 | 0.1% |
| `csca_hash` | 8,367 | 0.1% |
| `mrz_parse` | 1,044 | ~0% |
| serde + overhead | ~126,000 | 2.1% |

Note: ~1.7M cycles from postcard deserialization of ~64KB via `PrivateInput` in full disclosure variants. Predicate variants deserialize only ~2.4KB preparsed buffer + 93B DG1, cutting serde overhead to ~126K. True zerocopy would need jolt-sdk changes to bypass postcard serde at the advice boundary.

## Test data

### `tests/dataset/` — BSI TR-03105-5 ReferenceDataSet (German)
- `Datagroup1-4.bin`, `Datagroup14.bin`, `Datagroup15.bin` — raw DG files
- `EF_SOD.bin` — commits to DGs 1,2,3,4,14. Signed by HJP PB DS (RSA-PSS-SHA256)
- No CSCA cert available (HJP PB CS is proprietary, not publicly distributed)

### `tests/dataset-my/` — Malaysian passport (from gmrtd project)
- `EF_SOD.bin` — RSA-PSS-SHA256, 2048-bit DS key
- `CSCA.cer` — 3072-bit RSA, self-signed Malaysian CSCA (valid 2019-2029)
- `DSC.cer` — DS certificate signed by CSCA
- DG hashes only (no DG binaries) — can verify steps 1+3 but not step 2
- Full chain verified: `CSCA → DS cert → SOD signature`

### `tests/dataset-uk/` — UK passport DG binaries (from gmrtd project)
- `Datagroup1.bin` (93B), `Datagroup2.bin` (17KB), `Datagroup7.bin`, `Datagroup11-16.bin`
- `EF_SOD.bin` — RSA-PSS-SHA256
- No CSCA cert for this passport

### `tests/dataset-synth/` — Synthetic RSA e2e dataset (generated)
- `CSCA.cer` — Self-signed RSA 2048 Country Signing CA
- `DSC.cer` — Document Signer cert signed by CSCA (RSA-PSS-SHA256)
- `EF_SOD.bin` — CMS-signed LdsSecurityObject committing BSI DG hashes
- Uses BSI DG files from `tests/dataset/` for complete steps 1+2+3
- Regenerate: `./tests/gen-synthetic-dataset.sh`

### `tests/dataset-synth-ecdsa/` — Synthetic ECDSA P-256 e2e dataset (generated)
- `CSCA.cer` — Self-signed ECDSA P-256 Country Signing CA
- `DSC.cer` — Document Signer cert signed by CSCA (ECDSA-SHA256)
- `EF_SOD.bin` — CMS-signed LdsSecurityObject with ECDSA-SHA256 signature
- Uses BSI DG files from `tests/dataset/` for complete steps 1+2+3
- Regenerate: `./tests/gen-synthetic-dataset-ecdsa.sh`

| Dataset | SOD | DG bins | CSCA | Steps |
|---------|-----|---------|------|-------|
| BSI (DE) | ✅ | ✅ | ❌ | 1+2 |
| MY | ✅ | ❌ | ✅ | 1+3 |
| UK | ✅ | ✅ | ❌ | 1+2 |
| Synthetic RSA | ✅ | ✅ (BSI) | ✅ | 1+2+3 |
| Synthetic ECDSA | ✅ | ✅ (BSI) | ✅ | 1+2+3 |

## How to run

### Prerequisites

```bash
# Install Jolt CLI (needed once)
cargo install --git https://github.com/a16z/jolt --force jolt

# Generate synthetic test datasets (needed once)
./tests/gen-synthetic-dataset.sh          # RSA-PSS-SHA256
./tests/gen-synthetic-dataset-ecdsa.sh    # ECDSA P-256
```

### Library tests

```bash
cargo test          # 54 tests: ASN.1 parsing, RSA-PSS, ECDSA P-256, passive auth
```

### ZK proofs (from `icao-9303-jolt/`)

All commands run from the `icao-9303-jolt/` directory. First run compiles the
RISC-V guest binary (~30s); subsequent runs reuse the cached binary in
`/tmp/jolt-guest-targets/`.

**Full passport disclosure (RSA, ~17s prove time, <10 GB RAM):**
```bash
RUST_LOG=info cargo run --release                          # default: packed variant, synth RSA dataset
RUST_LOG=info cargo run --release -- packed                # same as above, explicit
RUST_LOG=info cargo run --release -- struct                # baseline: guest parses full CMS/X.509
```

**Age predicate proof (RSA, ~9s prove time):**
```bash
RUST_LOG=info cargo run --release -- age                   # proves holder is >= 18
```

**Nationality predicate proof (RSA, ~9s prove time):**
```bash
RUST_LOG=info cargo run --release -- nationality           # proves holder is German (D<<)
```

**ECDSA P-256 variants (same functions, different dataset):**
```bash
RUST_LOG=info cargo run --release -- age --dataset ecdsa              # ~15s prove time
RUST_LOG=info cargo run --release -- nationality --dataset ecdsa
RUST_LOG=info cargo run --release -- packed --dataset ecdsa
```

**Cycle analysis (no proving, prints per-section cycle counts):**
```bash
RUST_LOG=info cargo run --release -- analyze               # RSA dataset
RUST_LOG=info cargo run --release -- analyze --dataset ecdsa
```

### What the verifier sees

| Variant | Public inputs | Public output |
|---------|--------------|---------------|
| `packed`/`struct` | `disclosure_mask` | `PassportProofOutput { valid, nationality, dob, sex, expiry, csca_pubkey_hash }` |
| `age` | `min_age`, `current_date` | `PredicateOutput { valid, predicate, csca_pubkey_hash }` |
| `nationality` | `allowed[30]`, `allowed_count` | `PredicateOutput { valid, predicate, csca_pubkey_hash }` |

The passport data (SOD, DGs, CSCA) is passed as `PrivateInput` — the verifier
never sees it. BlindFold ZK ensures the witness is cryptographically hidden.

## What to work on (priority order)
1. Generate synthetic RSA-4096 dataset + `verify_passport_rsa4096` provable function
2. CSCA trust store — on-chain Merkle tree or smart contract lookup
3. Make DG set flexible instead of hardcoded `[1,2,3,4,14]`
4. Test real CSCA cert parsing from ICAO PKD (library-side tests)

## Optimization opportunities
1. **Zerocopy `PrivateInput`** — ~1.7M cycles (24%). Jolt SDK's `#[jolt::provable]` macro always uses postcard serde for `PrivateInput<T>`, even though `AdviceTapeIO` trait exists with bytemuck zero-copy. Requires upstream jolt-sdk PR to use `AdviceTapeIO` when available.
2. **`jolt-inlines-p256`** — would reduce ECDSA from ~6M to ~500K cycles. Requires upstream Jolt SDK work to add P-256 as a native instruction set (similar to existing `jolt-inlines-secp256k1` for Bitcoin's curve).
3. ~~**DER parsing offload**~~ — Done. Host pre-parses SOD/CSCA, saving ~450K cycles (5.9%).
4. ~~**ECDSA Jacobian + new_unchecked**~~ — Done. 202M → 74M cycles (2.73x improvement).
5. ~~**p256_fast Solinas reduction**~~ — Done. 74M → 6M cycles (12.3x). Hand-tuned `[u64; 4]` arithmetic with FIPS 186-4 D.2.3 Solinas reduction + Montgomery scalar field.
