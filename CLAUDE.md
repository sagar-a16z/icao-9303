# icao-9303 — Development Guide

## What this is
Rust implementation of ICAO 9303 electronic passport (eMRTD) parsing, cryptography, and NFC communication. Includes a Jolt ZK proof that verifies passport authenticity without revealing its contents.

## Current state

### Working (and proven in ZK)
- **SOD signature verification** — `EfSod::verify_signature()` does RSA-PSS-SHA256 end-to-end
- **DG hash integrity** — `LdsSecurityObject::verify_dg_hashes()` checks SHA-256 of each DG against SOD commitments
- **Jolt guest** proves both steps in 7.3M cycles (17s on M-series, ~3.6s at 2 MHz)
- `max_trace_length` tightened to 2^23 (<10 GB prover memory)

### Working (not yet in ZK guest)
- **MRZ parsing** — `Mrz::from_dg1()` extracts name, DOB, nationality, document number, sex, expiry from DG1
- **EfCom decoder** — `EfCom::from_bytes()` parses the non-DER TLV listing which DGs are present
- **DS cert extraction** — `ds_cert_from_sod()` pulls the X.509 DS certificate from SignedData
- **Certificate signature verification** — `verify_cert_signature()` verifies DS cert against issuer (RSA-PSS only)
- **ECDSA signature parsing** — `EcdsaSignature::from_der()` parses SEQUENCE{r,s}; scalar verification not implemented

### Working (infrastructure)
- Full ASN.1/DER/CMS parsing: `EfSod`, `LdsSecurityObject`, `EfDg14`, `EfCom`
- `DigestAlgorithmIdentifier::hash_bytes()` / `hash_der()` — SHA-1/256/384/512
- `RSAPublicKey::verify()` — RFC 8017 RSA-PSS with constant-time and variable-time exponentiation
- `ModRing` Montgomery arithmetic over generic `Uint<B,L>`
- BAC, Secure Messaging (3DES + AES), Chip Authentication skeleton, PACE key derivation

### Missing
- **CSCA trust anchor** — no root cert in dataset, no root store. BSI test CSCA cert available separately
- **ECDSA scalar verification** — DER parsing done, but `u1*G + u2*Q` point math not wired to existing EC curves
- **Selective disclosure** — MRZ parsing exists but not integrated into ZK guest for predicate proofs

## Passive Authentication steps (ICAO 9303 Part 11)

| Step | What | Status |
|------|------|--------|
| 1 | Verify SOD signature (DS cert signs LdsSecurityObject) | Done + ZK proven |
| 2 | Verify each DG hashes to its SOD commitment | Done + ZK proven |
| 3 | Verify DS cert was signed by CSCA | Skeleton (`certificate.rs`), no test CSCA cert |
| 4 | Verify CSCA is in a trusted root store | Missing |

## Production ZK proof (target)

```
CSCA root cert (trusted anchor — ICAO PKD)
  └─ signs → DS certificate (in EF.SOD)
       └─ signs → LdsSecurityObject
            └─ commits → hash(DG1), hash(DG2), ... hash(DG14)
                 └─ DG1 → MRZ (name, DOB, nationality, passport#, expiry)
```

Prove the full chain, selectively disclose only what the verifier needs (e.g. "age > 18").

## Performance

| Metric | Value |
|--------|-------|
| Total cycles | 7,282,405 |
| Prove time (M-series) | 17.1s @ 427 kHz |
| Prove time (beefy @ 2 MHz) | ~3.6s estimated |
| Prover memory | <10 GB |
| `max_trace_length` | 2^23 |

Cycle breakdown: `dg_hash_verify` 79%, `rsa_verify` 11%, `parse_sod` 6%, rest 4%.

## Optimization opportunities
1. **`jolt-inlines-sha2`** — constraint-native SHA-256 would cut the 5.7M DG hash cycles significantly
2. **`jolt-inlines-secp256k1`** — if/when ECDSA verification is added for EC-based passports
3. **Advice functions** — offload expensive witness computation (e.g. DER parsing) to host

## Test data
`tests/dataset/` — BSI TR-03105-5 ReferenceDataSet:
- `Datagroup1-4.bin`, `Datagroup14.bin`, `Datagroup15.bin` — raw DG files
- `EF_SOD.bin` — signed Document Security Object (commits to DGs 1, 2, 3, 4, 14 only)
- `EF_COM.bin` — lists which DGs are present
- `DG14_pk.bin`, `DG14_sk.pkcs8`, `DG15_pk.bin`, `DG15_sk.pkcs8` — key pairs

**Missing**: CSCA certificate (available from BSI test PKI)

## What to work on (priority order)
1. Integrate `jolt-inlines-sha2` to cut DG hash cycle count
2. Fetch BSI test CSCA cert, add `verify_cert_signature` test
3. Wire ECDSA scalar math to existing `EllipticCurve` / `ModRingElement`
4. Add MRZ parsing + selective disclosure to Jolt guest
5. Full 4-step Passive Authentication in a single ZK proof
