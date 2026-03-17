# icao-9303

Rust implementation of ICAO 9303 electronic passport (eMRTD) parsing, cryptography, and NFC communication. Includes a [Jolt](https://github.com/a16z/jolt) zero-knowledge proof that verifies passport authenticity with selective MRZ disclosure.

## What it does

Given a passport's NFC chip data (EF.SOD, data groups, CSCA certificate), this library verifies the full ICAO 9303 passive authentication chain and produces a ZK proof that the passport is authentic — without revealing the passport data to the verifier.

### Passive Authentication (ICAO 9303 Part 11)

| Step | What | Status |
|------|------|--------|
| 1 | Verify SOD signature (DS cert signs LdsSecurityObject) | Done + ZK proven |
| 2 | Verify each data group hashes to its SOD commitment | Done + ZK proven |
| 3 | Verify DS cert was signed by CSCA | Done + ZK proven |
| 4 | Verify CSCA is in a trusted root store | CSCA pubkey hash output for external lookup |

### Proof variants

| Variant | What the verifier learns | Prove time (RSA) | Prove time (ECDSA) |
|---------|------------------------|-----------------|-------------------|
| **Full disclosure** | Selected MRZ fields (nationality, DOB, sex, expiry) + CSCA hash | ~20s | ~25s |
| **Age predicate** | "Holder is >= N years old" + CSCA hash | ~9s | ~15s |
| **Not-expired predicate** | "Passport valid for >= 3 months" + CSCA hash | ~9s | ~15s |

All passport data (SOD, data groups, CSCA cert) is passed as `PrivateInput` and cryptographically hidden via BlindFold ZK.

### Supported signature algorithms

- **RSA-PSS** with SHA-256 (2048-bit keys in ZK; library supports 2048/3072/4096)
- **ECDSA P-256** with SHA-256 (auto-detected from SPKI type)

## How to run

### Prerequisites

```bash
# Rust toolchain
rustup default stable

# Install Jolt CLI (needed once for ZK proofs)
cargo install --git https://github.com/a16z/jolt --force jolt

# Generate synthetic test datasets (needed once)
./tests/gen-synthetic-dataset.sh          # RSA-PSS-SHA256 (requires OpenSSL 3.x + Python 3)
./tests/gen-synthetic-dataset-ecdsa.sh    # ECDSA P-256
```

### Library tests

```bash
cargo test          # 48 tests: ASN.1 parsing, RSA-PSS, ECDSA P-256, passive auth
```

### ZK proofs

All proof commands run from the `icao-9303-jolt/` directory. First run compiles the RISC-V guest binary (~30s); subsequent runs reuse the cached binary.

**Full passport disclosure:**
```bash
RUST_LOG=info cargo run --release                          # RSA dataset (default)
RUST_LOG=info cargo run --release -- packed --dataset ecdsa  # ECDSA dataset
```

**Predicate proofs:**
```bash
RUST_LOG=info cargo run --release -- age                   # proves holder is >= 18
RUST_LOG=info cargo run --release -- not-expired           # proves expiry >= today + 3 months
```

**ECDSA variants (same proofs, different dataset):**
```bash
RUST_LOG=info cargo run --release -- age --dataset ecdsa
RUST_LOG=info cargo run --release -- not-expired --dataset ecdsa
```

**Cycle analysis (no proving, prints per-section cycle counts):**
```bash
RUST_LOG=info cargo run --release -- analyze
RUST_LOG=info cargo run --release -- analyze --dataset ecdsa
```

### What the verifier sees

| Variant | Public inputs | Public output |
|---------|--------------|---------------|
| `packed`/`struct` | `disclosure_mask` | `PassportProofOutput { valid, nationality, dob, sex, expiry, csca_pubkey_hash }` |
| `age` | `min_age`, `current_date` | `PredicateOutput { valid, predicate, csca_pubkey_hash }` |
| `not-expired` | `current_date` | `PredicateOutput { valid, predicate, csca_pubkey_hash }` |

The passport data is never revealed to the verifier. BlindFold ZK ensures the witness is cryptographically hidden.

## Performance

| Variant | RSA-PSS-SHA256 | ECDSA P-256 |
|---------|---------------|-------------|
| **Full disclosure (packed)** | 5.3M cycles (~20s) | 9.3M cycles (~25s) |
| **Age predicate** | 2.2M cycles (~9s) | 6.0M cycles (~15s) |
| **Not-expired predicate** | ~2.2M cycles (~9s) | ~6.0M cycles (~15s) |

Prove times measured on Apple M-series, single-threaded. Full disclosure requires ~15 GB RAM; predicates require <10 GB.

Predicate proofs are ~57% cheaper than full disclosure because they only hash DG1 (93 bytes) instead of all 5 data groups (~64 KB).

## Architecture

```
icao-9303/                    Rust library: ASN.1 parsing, crypto, NFC protocols
  src/asn1/                   DER/CMS/X.509 parsing (EfSod, LdsSecurityObject, MRZ)
  src/crypto/                 RSA-PSS, ECDSA P-256, Montgomery arithmetic, EC groups
  src/emrtd/                  BAC, Secure Messaging, Chip Authentication, PACE

icao-9303-jolt/               Jolt ZK proof wrapper
  guest/src/lib.rs            RISC-V guest: 4 provable functions
  src/main.rs                 Host: compile, prove, verify
```

The ZK guest auto-detects RSA vs ECDSA from the public key type — a single set of provable functions handles both.

### Why custom crypto?

The RSA-PSS and ECDSA implementations are custom rather than using standard crates (`p256`, `rsa`). This is because the code runs inside a RISC-V zkVM where every instruction becomes a proof constraint:

- Standard crates use **constant-time** operations (side-channel resistance) which add 10-100x more instructions. In a zkVM there are no side channels — the prover already knows all inputs.
- The custom P-256 uses **FIPS 186-4 Solinas fast reduction** exploiting the prime's structure, reducing ECDSA from 74M to 6M cycles (12x improvement over even the project's own generic path).
- RSA uses **variable-time exponentiation** with e=65537 (17 squarings + 1 multiply vs 2048 squarings in constant-time).

Hashing uses standard crates (`sha2`, `sha1`) and `jolt-inlines-sha2` (constraint-native SHA-256). ASN.1/DER/CMS/X.509 parsing uses `der`, `cms`, and `x509-cert` crates.

## Test data

| Dataset | SOD | DG binaries | CSCA cert | Passive auth steps |
|---------|-----|-------------|-----------|-------------------|
| BSI TR-03105-5 (German) | yes | yes | no | 1+2 |
| Malaysian | yes | no | yes (3072-bit RSA) | 1+3 |
| UK | yes | yes | no | 1+2 |
| Synthetic RSA | yes | yes (BSI) | yes (2048-bit RSA) | 1+2+3 |
| Synthetic ECDSA | yes | yes (BSI) | yes (P-256) | 1+2+3 |

The synthetic datasets are generated by `tests/gen-synthetic-dataset*.sh` and are gitignored (they contain freshly generated keys). The BSI dataset is from the BSI TR-03105-5 reference data.

## References

* [ICAO 9303: Machine Readable Travel Documents](https://www.icao.int/publications/pages/publication.aspx?docnum=9303)
* [Jolt: SNARKs for Virtual Machines](https://github.com/a16z/jolt)

Standards:

* ISO/IEC 7816-4: Integrated Circuit(s) Cards with Contacts
* ISO/IEC 14443-3: Proximity Cards
* ITU-T X.690: ASN.1 encoding rules
* RFC 5280, RFC 5480, RFC 5114, RFC 5639, RFC 5652, RFC 8017
* FIPS 186-4: Digital Signature Standard (Solinas reduction, D.2.3)
* ANSI X9.62: Elliptic Curve Digital Signature Algorithm (ECDSA)
* BSI TR-03105, TR-03110, TR-03111

Cryptographic primitives:

* FIPS 46-3: Data Encryption Standard (DES)
* NIST SP 800-38B: CMAC Mode for Authentication
* ISO/IEC 10116-2006: Modes of operation for block ciphers
