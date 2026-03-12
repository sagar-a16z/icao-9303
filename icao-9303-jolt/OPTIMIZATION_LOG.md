# Jolt ZK Guest Optimization Log

## Baseline (before optimizations)

Two provable functions sharing `verify_passport_inner()`:

| Variant | Total Cycles | Prove Time |
|---------|-------------|------------|
| Packed (`Vec<u8>`) | 7,445,662 | 17.4s |
| Struct (`PassportData`) | 7,583,661 | 18.7s |

Cycle breakdown (packed variant):

| Section | Cycles | % |
|---------|--------|---|
| `dg_hash_verify` | 2,845,637 | 38.2% |
| `cert_chain_verify` | 776,354 | 10.4% |
| `rsa_verify` (SOD) | 759,686 | 10.2% |
| `parse_sod` | 380,988 | 5.1% |
| `cert_chain_setup` | 290,601 | 3.9% |
| `parse_csca` | 182,703 | 2.5% |
| `ring_setup` | 105,227 | 1.4% |
| `mont_encode` | 102,582 | 1.4% |
| `hash_signed_attrs` | 33,841 | 0.5% |
| `extract_cert` | 19,275 | 0.3% |
| `csca_hash` | 16,459 | 0.2% |
| `mrz_parse` | 438 | ~0% |
| serde + overhead | ~1,931,871 | 25.9% |

## Optimization 1: Host-side DER pre-parsing

**Goal**: Eliminate `parse_sod` (381K), `parse_csca` (183K), and parts of `cert_chain_setup` (~100K) by having the host extract needed byte fields before passing to guest.

**Approach**:
- Host parses SOD + CSCA using the library, extracts byte fields
- Guest receives pre-parsed fields in the packed buffer
- Guest does lightweight structural checks + all crypto verification

**Packed buffer fields** (pre-parsed):
1. signed_attrs_der — for hash + RSA signature verification
2. digest_alg_der — algorithm identifier
3. sig_algo_der — RSA-PSS signature algorithm
4. signature_bytes — SOD RSA signature
5. ds_spki_der — Document Signer public key
6. lds_der — raw LDS DER bytes (for DG hash verification)
7. tbs_der — DS cert TBSCertificate (for cert chain verification)
8. cert_sig_bytes — DS cert signature
9. cert_sig_algo_der — cert signature algorithm
10. ds_spki_offset_in_tbs — u32 offset (for structural integrity check)
11. csca_spki_der — CSCA public key
12. dg1, dg2, dg3, dg4, dg14 — raw data group bytes

**Structural integrity checks** (guest-side):
1. `hash(lds_der) == messageDigest_in_signed_attrs` — prevents fake LDS
2. `tbs_der[offset..offset+len] == ds_spki_der` — prevents fake DS key

**Security reasoning**:
- Chain of trust: csca_pubkey_hash (public output) → CSCA signs tbs_der → tbs_der contains ds_spki → ds_spki verifies SOD signature → signed_attrs commit to LDS → LDS commits to DG hashes
- If any advice field is faked, either crypto fails or structural check fails
- Prover can't forge because breaking the chain requires breaking RSA

**Expected savings**: ~560K cycles from DER parsing + some from cert_chain_setup

**Actual results**:

| Metric | Pre-parsed | Struct (baseline) | Delta |
|--------|-----------|-------------------|-------|
| Total cycles | 7,134,555 | 7,584,354 | -449,799 (5.9%) |
| Prove time | 17.2s | 18.1s | -0.9s |

Eliminated sections: parse_sod (382K), extract_cert (19K), parse_csca (182K) = 584K saved
New sections: structural_checks (27K), parse_lds (44K) = 71K added
cert_chain_setup reduced by 39K (no tbs_der re-encoding)
dg_hash_verify regressed by 287K (cross-ELF alignment noise with jolt-inlines-sha2)
Serde overhead reduced by ~193K (slightly smaller buffer)

**Net savings: 450K cycles (5.9%)** — matches expected DER parsing savings despite the
dg_hash_verify regression. Without the alignment noise, savings would be ~737K (9.7%).

**Note**: The dg_hash_verify regression was caused by alignment: all DG bytes lived in one
`Vec<u8>` heap allocation (align=1 from jolt's BumpAllocator), so DG sub-slices could land
on misaligned addresses. jolt-inlines-sha2's LW loads cost 6 instructions for misaligned
vs 2-3 for aligned. Fixed in Optimization 2.

## Optimization 2: Split DG data into separate PrivateInput

**Goal**: Eliminate the 287K dg_hash_verify alignment regression by giving each DG its own
aligned heap allocation.

**Approach**:
- Split `verify_passport_packed` into two `PrivateInput` arguments:
  1. `preparsed_buf: PrivateInput<Vec<u8>>` — pre-parsed SOD/CSCA fields (~2.4KB)
  2. `dgs: PrivateInput<PassportDGs>` — DG data as separate Vecs
- `PassportDGs` is a struct with `dg1..dg14` as individual `Vec<u8>` fields
- When postcard deserializes `PassportDGs`, each Vec gets its own heap allocation → naturally aligned
- No changes to verification logic or security model

**Actual results**:

| Section | Before (single buf) | After (split DGs) | Delta |
|---------|--------------------|--------------------|-------|
| `dg_hash_verify` | 3,130,532 | 2,800,292 | -330,240 |
| `structural_checks` | 27,039 | 26,605 | -434 |
| `ring_setup` | 127,197 | 125,567 | -1,630 |
| `cert_chain_setup` | 250,965 | 251,057 | +92 |
| Other sections | ~similar | ~similar | ~0 |

dg_hash_verify is now 43K cycles *below* the struct baseline (2,800,292 vs 2,843,416),
confirming the regression was purely alignment-related.

**Tracked sections total**: 4,930,284 (was 5,202,684 before fix)

Estimated total with serde overhead: ~6,862K cycles — **~722K savings (9.5%) vs struct baseline**.

## Optimization 3: serde_bytes on Vec<u8> fields

**Goal**: Reduce postcard deserialization overhead for `PrivateInput<T>` structs containing
`Vec<u8>` fields. Without `serde_bytes`, postcard deserializes each byte individually (~1 serde
call per byte). With it, the entire byte slice is read in one shot.

**Approach**: Annotate all `Vec<u8>` fields with `#[serde(with = "serde_bytes")]` in
`PassportData`, `PassportDGs`, and any future structs passed as `PrivateInput`.

**Impact**: serde overhead dropped from ~2M cycles to ~350-560K cycles — **~24% of total proof
cycles saved** for the struct variant. The packed variant also benefits because `PassportDGs`
(~61KB of DG data) is deserialized as a `PrivateInput`.

## Predicate proofs: DG1-only verification

**Goal**: For predicate checks (age, nationality), only DG1 matters — skip hashing DG2-4/14
(~61KB of biometric data) to save ~2.8M cycles.

**Why DG hashing can't be offloaded to advice**: The chain of trust requires the guest to hash
raw DG bytes and compare against the signed LDS commitment. If the host provides hashes as
advice, it could supply fake DG data with matching fake hashes — the guest must compute hashes
itself to bind DG data to the SOD signature.

**What predicate proofs skip**: Only DG1 (93 bytes, ~1K cycles to hash) is needed. DG2/3/4/14
hashing (~2.8M cycles) is eliminated entirely. The full chain of trust is still verified:
CSCA → DS cert → SOD signature → LDS → DG1 hash.

**Results**:

| Variant | Total Cycles | Prove Time | vs Full Packed |
|---------|-------------|------------|----------------|
| Full packed (5 DGs) | 5,281,961 | 19.7s | baseline |
| Age check (DG1 only) | 2,233,268 | 9.3s | **-57.8%** |
| Nationality check (DG1 only) | 2,233,463 | 9.4s | **-57.7%** |

Predicate proofs output `PredicateOutput { valid, predicate, csca_pubkey_hash }` — the verifier
learns only the boolean result and the CSCA identity, never the actual DOB or nationality.

## ECDSA P-256 support

**Goal**: Support passports signed with ECDSA P-256 (secp256r1) instead of RSA-PSS.

**Approach**:
- Library: Extended `SignatureAlgorithmIdentifier` with ECDSA-SHA256/384/512 variants
- Library: Added `verify_ecdsa_cert()` and updated `verify_cert_signature()` + `EfSod::verify_signature()`
- Guest: Added `verify_passport_dg1_only_ecdsa()` and ECDSA predicate functions (`check_age_ecdsa`, `check_nationality_ecdsa`)
- Test data: `tests/gen-synthetic-dataset-ecdsa.sh` generates synthetic ECDSA P-256 CSCA + DS + SOD

**Performance evolution**:

| Optimization | ECDSA Age Check Cycles | Improvement |
|-------------|----------------------|-------------|
| Affine coordinates + `new()` | ~202,000,000 | baseline |
| Jacobian projective coords | ~115,000,000 | 1.75x |
| + `new_unchecked()` for secp256r1 | 74,029,449 | 2.73x total |

**Key optimizations**:
1. **Jacobian projective coordinates** (`elliptic_curve.rs`): Replaced affine double-and-add
   (1 field inversion per point op, ~256 inversions/scalar mul) with Jacobian (X,Y,Z) coordinates.
   Only multiplications during computation, single inversion at the end.
2. **`new_unchecked()`** (`elliptic_curve.rs`, `named.rs`): `EllipticCurve::new()` validates the
   generator has the claimed order via a full scalar multiply. `secp256r1()` was calling this every
   time, and `verify_ecdsa_p256()` constructs the curve twice (SOD + cert chain) = 4 unnecessary
   scalar multiplications. `new_unchecked()` skips validation; `test_construct` validates separately.

**Comparison: ECDSA vs RSA predicate proofs**:

| Variant | Total Cycles | `max_trace_length` | Estimated Prove Time |
|---------|-------------|-------------------|---------------------|
| RSA age check | 2,233,268 | 2^22 | ~9s |
| ECDSA age check | 74,029,449 | 2^27 | ~5-10 min |

ECDSA P-256 is **33x more expensive** than RSA-2048 in a RISC-V zkVM. This is expected:
- RSA is one 2048-bit modular exponentiation (~750K cycles)
- ECDSA requires 4 × 256-bit EC scalar multiplications (~18M each), plus field inversions
- No constraint-native P-256 instructions exist in Jolt (unlike `jolt-inlines-secp256k1` for Bitcoin's curve)

**Future**: A `jolt-inlines-p256` crate (constraint-native P-256 operations) could reduce ECDSA
to ~500K cycles, on par with RSA. This requires upstream Jolt SDK work to add P-256 as a native
instruction set alongside secp256k1.
