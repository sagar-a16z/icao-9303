# icao-9303-jolt — Notes

## What this proves

The Jolt proof runs the following icao-9303 code paths inside a RISC-V ZK virtual machine and produces a proof that they executed correctly:

- **ASN.1/DER parsing** — `EfSod::from_der`, `SubjectPublicKeyInfo::from_der`, CMS `SignedData` traversal
- **Signed-attributes digest** — `DigestAlgorithmIdentifier::hash_bytes` over the DER-encoded signed attributes (RFC 5652 §5.4)
- **RSA key construction** — `RSAPublicKey::try_from(spki)`, including Montgomery ring parameter setup
- **RSA-PSS-SHA256 verification** — `RSAPublicKey::verify` → `verify_pss` → `ModRingElement::pow_vt` → MGF1 → hash comparison

The input is the BSI TR-03105-5 reference passport dataset (`tests/dataset/EF_SOD.bin`), baked in at compile time.

## What this does not prove

**`verify_signature` is not exercised.** The dispatch function in `src/crypto/signature.rs` contains a `todo!()` and is bypassed entirely. The guest calls `RSAPublicKey::verify` directly.

**Only the RSA-PSS path is covered.** EC signature verification, DH key agreement, and the BAC/PACE protocol layers are not exercised.

**The input is public.** The SOD bytes are a compile-time constant, so the proof demonstrates correct execution on known data — not knowledge of a private input. A verifier who inspects the binary already knows the bytes.

**The Jolt `zk` feature is not enabled.** Without it, proof transcripts do not hide witness values.

## Upgrade path to privacy-preserving passport verification

Two changes are needed to make this a real proof of passport possession without revealing which passport.

### 1. Move SOD bytes to a private input

Change the guest signature from a zero-argument function to one that accepts the SOD bytes as `UntrustedAdvice`. Jolt's `UntrustedAdvice<T>` passes data from the prover to the guest without exposing it in the verifier's view of the proof.

```rust
#[jolt::provable(...)]
fn verify_sod(sod_bytes: jolt::UntrustedAdvice<Vec<u8>>) -> bool {
    let sod = EfSod::from_der(&*sod_bytes).unwrap();
    // ... rest unchanged
}
```

On the host, pass the bytes read from a live NFC scan:

```rust
let sod_bytes = connect_reader()?.read_ef_sod();
let (output, proof, io) = prove(UntrustedAdvice::new(sod_bytes));
```

### 2. Enable the `zk` feature

Without the `zk` feature, advice values appear in plaintext in the proof transcript. Add `"zk"` to the host's `jolt-sdk` dependency:

```toml
jolt-sdk = { git = "https://github.com/a16z/jolt", features = ["host", "zk"] }
```

This enables the BlindFold protocol, which cryptographically hides the witness from the verifier.

### What the verifier learns after both changes

Only the public output (`true` / `false`) and the proof. The verifier can check that a valid passport EF.SOD was presented and its RSA-PSS-SHA256 signature verified, without learning the passport's content or identity.

### What remains out of scope

Proving that the passport belongs to a specific person, that the Document Signer Certificate chains to a trusted Country Signing CA, or that the data groups are internally consistent would require additional proof logic. Those are natural follow-on steps.
