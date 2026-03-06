# icao-9303 — Development Guide

## What this is
Rust implementation of ICAO 9303 electronic passport (eMRTD) parsing, cryptography, and NFC communication. The goal is complete **Passive Authentication**: cryptographically prove a passport is genuine without revealing its contents.

## Current state

### Working
- Full ASN.1/DER/CMS parsing: `EfSod`, `LdsSecurityObject`, `EfDg14`, `EfCom`
- `LdsSecurityObject::hash_for_dg(n)` — looks up DG hash commitments from SOD
- `DigestAlgorithmIdentifier::hash_bytes()` / `hash_der()` — SHA-1/256/384/512
- `RSAPublicKey::verify()` — complete RFC 8017 RSA-PSS verification
- `ModRingElement::pow_ct` / `pow_vt` — constant-time and variable-time modular exponentiation
- BAC (Basic Access Control), Secure Messaging (3DES + AES), Chip Authentication skeleton
- Jolt ZK proof of RSA-PSS-SHA256 SOD signature — see `icao-9303-jolt/`

### Partial / todo!()
- `EfSod::verify_signature()` — extracts signer info but hits `todo!()` before calling verify
- Chip Authentication — key agreement algorithm extraction hits `todo!()`
- PACE — key derivation works, protocol missing

### Missing
- **DG hash verification** — `hash_for_dg` + `hash_bytes` exist but no unified `verify_dg_hashes()` API
- **MRZ parsing** — DG1 binary format not parsed into structured fields
- **DS cert → CSCA chain validation** — no X.509 certificate chain code at all
- **CSCA trust anchor** — no root store; BSI test CSCA cert not included in dataset
- **ECDSA signature verification** — needed for EC-based passports (many modern ones)

## Full Passive Authentication steps (ICAO 9303 Part 11)
1. Verify EF.SOD RSA-PSS/ECDSA signature (DS cert signs LdsSecurityObject) ← **done in Jolt**
2. Verify each DG's bytes hash to the committed value in LdsSecurityObject ← **building blocks exist**
3. Verify DS certificate was signed by a Country Signing CA (CSCA)
4. Verify CSCA is in a trusted list (ICAO PKD or BSI test list)

## Test data
`tests/dataset/` contains BSI TR-03105-5 ReferenceDataSet:
- `Datagroup1-4.bin`, `Datagroup14.bin`, `Datagroup15.bin` — raw DG files
- `EF_SOD.bin` — signed Document Security Object
- `EF_COM.bin` — lists which DGs are present
- `DG14_pk.bin`, `DG14_sk.pkcs8`, `DG15_pk.bin`, `DG15_sk.pkcs8` — key pairs

**Missing from dataset**: CSCA certificate. Available separately from BSI:
https://www.bsi.bund.de/EN/Themen/Oeffentliche-Verwaltung/Elektronische-Identitaeten/Public-Key-Infrastrukturen/CSCA/Test-CSCA-Zertifikate/Test-CSCA-Zertifikate_node.html

## What to work on (priority order)
1. Implement `EfSod::verify_signature()` — wire up `RSAPublicKey::verify` (or ECDSA)
2. Add `LdsSecurityObject::verify_dg_hashes(dgs: &[(usize, &[u8])]) -> Result<()>`
3. Fetch BSI test CSCA cert, add to dataset, add to `Dataset` struct
4. Add MRZ parsing — extract name/DOB/passport number fields from DG1 bytes
5. Implement DS cert signature verification against CSCA public key
6. Add ECDSA verification — `src/crypto/ecdsa.rs` using existing EC curve code
7. Integrate steps 1-4 into the Jolt guest for a full Passive Authentication proof
