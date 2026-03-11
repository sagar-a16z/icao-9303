# icao-9303 — Development Guide

## What this is
Rust implementation of ICAO 9303 electronic passport (eMRTD) parsing, cryptography, and NFC communication. Includes a Jolt ZK proof that verifies passport authenticity with selective MRZ disclosure.

## Current state

### Working (and proven in ZK)
- **SOD signature verification** — RSA-PSS-SHA256 end-to-end
- **DG hash integrity** — SHA-256 of each DG (1,2,3,4,14) checked against SOD commitments
- **Certificate chain verification** — DS cert signed by CSCA (RSA-PSS-SHA256, 2048-bit). Outputs SHA-256 of CSCA SPKI for trust store lookup.
- **MRZ selective disclosure** — `verify_passport(disclosure_mask, passport) -> PassportProofOutput` returns only requested fields (nationality, DOB, sex, expiry, issuing state)
- **Private passport input** — `PassportData` struct (including CSCA cert) passed as `PrivateInput<T>`, cryptographically hidden by BlindFold
- **BlindFold ZK** — `zk` feature on host and guest; witness hidden, verifier sees only `(disclosure_mask, PassportProofOutput)`
- **jolt-inlines-sha2** — constraint-native SHA-256 for DG hashing (feature-gated `jolt-sha2`)

### Working (not in ZK guest)
- **ECDSA P-256 verification** — complete `verify_ecdsa_p256()` with RFC 6979 test vector
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
- **ECDSA in ZK guest** — verification works in library tests but not yet wired into Jolt guest
- **Expiry checking** — proof outputs expiry date but doesn't verify `expiry > today` inside guest
- **CSCA trust store** — verifier gets CSCA pubkey hash but no on-chain/off-chain trust store lookup yet

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
- Two guest variants:
  - `verify_passport_packed(mask, PrivateInput<Vec<u8>>)` — host pre-parses SOD/CSCA, guest skips DER parsing
  - `verify_passport_struct(mask, PrivateInput<PassportData>)` — baseline, guest does full CMS/X.509 parsing
- `pack_preparsed_passport()` extracts byte fields from SOD/CSCA on host, packs with raw DG bytes
- Guest structural integrity checks: messageDigest ↔ LDS hash, DS SPKI ↔ TBS offset
- `PassportData` includes `sod`, `dg1-4`, `dg14`, and `csca` (all `Vec<u8>`)
- `PassportProofOutput` includes `valid`, selective MRZ fields, and `csca_pubkey_hash: [u8; 32]`
- Host passes `PrivateInput::new(...)` — verifier API excludes it automatically
- BlindFold setup: `prover_prep.blindfold_setup()` → 3-arg `preprocess_verifier_*(shared, verifier_setup, Some(blindfold_setup))`
- Jolt SDK pinned to commit `97b2c96` (Rust 1.94 update)

## Performance

| Metric | Pre-parsed (packed) | Struct (baseline) |
|--------|--------------------|--------------------|
| Total cycles | 7,134,555 | 7,584,354 |
| Prove time (M-series) | 17.2s @ 430 kHz | 18.1s @ 435 kHz |
| Prover memory | <10 GB | <10 GB |
| `max_trace_length` | 2^23 | 2^23 |

Pre-parsed saves ~450K cycles (5.9%) by having the host extract byte fields from SOD/CSCA, eliminating CMS/X.509 DER parsing in the guest.

Cycle breakdown (pre-parsed variant):

| Section | Cycles | % |
|---------|--------|---|
| `dg_hash_verify` | 3,130,532 | 43.9% |
| `cert_chain_verify` | 777,367 | 10.9% |
| `rsa_verify` (SOD) | 764,674 | 10.7% |
| `cert_chain_setup` | 250,805 | 3.5% |
| `ring_setup` | 124,510 | 1.7% |
| `mont_encode` | 96,357 | 1.4% |
| `parse_lds` | 43,751 | 0.6% |
| `structural_checks` | 26,605 | 0.4% |
| `hash_signed_attrs` | 23,729 | 0.3% |
| `csca_hash` | 17,822 | 0.2% |
| `mrz_parse` | 429 | ~0% |
| serde + overhead | ~1,877,974 | 26.3% |

Note: ~1.7M cycles from postcard deserialization of ~64KB via `PrivateInput`. True zerocopy would need jolt-sdk changes to bypass postcard serde at the advice boundary. The `#[jolt::provable]` macro is hardcoded to use postcard for `PrivateInput<T>`, even though Jolt has a zero-copy `AdviceTapeIO` trait (using `bytemuck::Pod` for direct byte casting).

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

### `tests/dataset-synth/` — Synthetic e2e dataset (generated)
- `CSCA.cer` — Self-signed RSA 2048 Country Signing CA
- `DSC.cer` — Document Signer cert signed by CSCA (RSA-PSS-SHA256)
- `EF_SOD.bin` — CMS-signed LdsSecurityObject committing BSI DG hashes
- Uses BSI DG files from `tests/dataset/` for complete steps 1+2+3
- Regenerate: `./tests/gen-synthetic-dataset.sh`

| Dataset | SOD | DG bins | CSCA | Steps |
|---------|-----|---------|------|-------|
| BSI (DE) | ✅ | ✅ | ❌ | 1+2 |
| MY | ✅ | ❌ | ✅ | 1+3 |
| UK | ✅ | ✅ | ❌ | 1+2 |
| Synthetic | ✅ | ✅ (BSI) | ✅ | 1+2+3 |

## What to work on (priority order)
1. Wire ECDSA into ZK guest for EC-signed passports
2. Predicate proofs (e.g. "age > 18") instead of raw field disclosure
3. CSCA trust store — on-chain Merkle tree or smart contract lookup

## Optimization opportunities
1. **Zerocopy `PrivateInput`** — ~1.7M cycles (24%). Jolt SDK's `#[jolt::provable]` macro always uses postcard serde for `PrivateInput<T>`, even though `AdviceTapeIO` trait exists with bytemuck zero-copy. Requires upstream jolt-sdk PR to use `AdviceTapeIO` when available.
2. **`jolt-inlines-secp256k1`** — when ECDSA verification is added to ZK guest
3. ~~**DER parsing offload**~~ — Done. Host pre-parses SOD/CSCA, saving ~450K cycles (5.9%).
