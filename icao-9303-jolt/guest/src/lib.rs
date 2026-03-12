use cms::cert::CertificateChoices;
use der::{asn1::OctetString, Decode, Encode};
use icao_9303::{
    asn1::{
        emrtd::{mrz::MrzRaw, EfSod, LdsSecurityObject},
        public_key_info::SubjectPublicKeyInfo,
        DigestAlgorithmIdentifier,
        SignatureAlgorithmIdentifier,
    },
    crypto::{p256_fast::verify_ecdsa_p256_fast, mod_ring::RingRefExt, rsa::RSAPublicKey},
};
use jolt::{end_cycle_tracking, start_cycle_tracking};
use ruint::Uint;
use serde::{Deserialize, Serialize};

type Uint2048 = Uint<2048, 32>;

/// All passport data read from the NFC chip — passed as a private input
/// so the verifier never sees the raw bytes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PassportData {
    #[serde(with = "serde_bytes")]
    pub sod: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub dg1: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub dg2: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub dg3: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub dg4: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub dg14: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub csca: Vec<u8>,
}

/// Data groups as separate Vec allocations — each gets its own aligned heap
/// allocation when deserialized, avoiding the alignment regression from packing
/// all DG bytes into a single flat buffer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PassportDGs {
    #[serde(with = "serde_bytes")]
    pub dg1: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub dg2: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub dg3: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub dg4: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub dg14: Vec<u8>,
}

/// Disclosure bitmask constants.
pub const DISCLOSE_ISSUING_STATE: u8 = 1 << 0;
pub const DISCLOSE_NATIONALITY: u8 = 1 << 1;
pub const DISCLOSE_DOB: u8 = 1 << 2;
pub const DISCLOSE_SEX: u8 = 1 << 3;
pub const DISCLOSE_EXPIRY: u8 = 1 << 4;

/// Public output of the passport ZK proof.
/// The verifier sees ONLY this struct -- all passport data is hidden
/// except for the fields selected by `disclosure_mask`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PassportProofOutput {
    pub valid: bool,
    pub disclosure_mask: u8,
    pub issuing_state: [u8; 3],
    pub nationality: [u8; 3],
    pub date_of_birth: [u8; 6],
    pub sex: u8,
    pub expiry_date: [u8; 6],
    /// SHA-256 of the CSCA's SubjectPublicKeyInfo DER — lets verifier
    /// check the trust anchor without seeing the full cert.
    pub csca_pubkey_hash: [u8; 32],
}

/// Output of a predicate ZK proof — verifier learns only a boolean predicate
/// result (e.g. "over 18") without seeing any passport data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PredicateOutput {
    /// Whether the full chain of trust verified (SOD sig + cert chain + DG1 hash).
    pub valid: bool,
    /// The predicate result (e.g. true = over 18, true = nationality is allowed).
    pub predicate: bool,
    /// SHA-256 of the CSCA's SubjectPublicKeyInfo DER.
    pub csca_pubkey_hash: [u8; 32],
}

// ─── Packed buffer helpers ──────────────────────────────────────────────────

/// Append a length-prefixed, 4-byte-aligned field to a buffer.
fn pack_field(buf: &mut Vec<u8>, field: &[u8]) {
    buf.extend_from_slice(&(field.len() as u32).to_le_bytes());
    buf.extend_from_slice(field);
    let pad = (4 - (field.len() % 4)) % 4;
    buf.extend(core::iter::repeat(0u8).take(pad));
}

/// Take a length-prefixed, 4-byte-aligned slice from the buffer.
fn take_slice(buf: &[u8]) -> (&[u8], &[u8]) {
    let len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    let pad = (4 - (len % 4)) % 4;
    (&buf[4..4 + len], &buf[4 + len + pad..])
}

/// Read a u32 from the first 4 bytes of the buffer, advance past it.
fn take_u32(buf: &[u8]) -> (u32, &[u8]) {
    let val = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    (val, &buf[4..])
}

// ─── Host-side pre-parsing ──────────────────────────────────────────────────

/// Pack raw passport fields into a flat buffer (no pre-parsing).
/// Used by the struct→packed baseline comparison.
pub fn pack_passport(
    sod: &[u8],
    dg1: &[u8],
    dg2: &[u8],
    dg3: &[u8],
    dg4: &[u8],
    dg14: &[u8],
    csca: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::new();
    for field in [sod, dg1, dg2, dg3, dg4, dg14, csca] {
        pack_field(&mut buf, field);
    }
    buf
}

/// Pre-parse SOD + CSCA on the host and return (preparsed_buf, dgs).
///
/// The preparsed buffer contains extracted SOD/CSCA byte fields (no DG data).
/// DGs are returned separately as `PassportDGs` so each gets its own aligned
/// heap allocation in the guest (avoids jolt-inlines-sha2 alignment regression).
///
/// Buffer layout (each field is length-prefixed + 4-byte-aligned):
///   0: signed_attrs_der
///   1: digest_alg_der
///   2: sig_algo_der
///   3: signature_bytes
///   4: ds_spki_der
///   5: lds_der (raw LdsSecurityObject DER, for DG hash verification)
///   6: tbs_der (DS cert TBSCertificate, for cert chain verification)
///   7: cert_sig_bytes (DS cert signature)
///   8: cert_sig_algo_der
///   9: csca_spki_der
///  Then: u32 ds_spki_offset_in_tbs (not length-prefixed, just raw 4 bytes)
pub fn pack_preparsed_passport(
    sod_bytes: &[u8],
    dg1: &[u8],
    dg2: &[u8],
    dg3: &[u8],
    dg4: &[u8],
    dg14: &[u8],
    csca_bytes: &[u8],
) -> (Vec<u8>, PassportDGs) {
    // ── Parse SOD ────────────────────────────────────────────────────────────
    let sod = EfSod::from_der(sod_bytes).expect("EfSod::from_der");
    let signer = sod.signer_info();

    let signed_attrs_der = signer
        .signed_attrs
        .as_ref()
        .expect("missing signed_attrs")
        .to_der()
        .unwrap();
    let digest_alg_der = signer.digest_alg.to_der().unwrap();
    let sig_algo_der = signer.signature_algorithm.to_der().unwrap();
    let signature_bytes = signer.signature.as_bytes();

    // DS certificate
    let certs = sod.signed_data().certificates.as_ref().expect("no certs in SOD");
    let ds_cert = match certs.0.iter().next().unwrap() {
        CertificateChoices::Certificate(c) => c,
        _ => panic!("unexpected certificate type"),
    };
    let ds_spki_der = ds_cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .unwrap();

    // LDS DER bytes (encapsulated content → OCTET STRING value)
    let econ = sod.encapsulated_content();
    let octet_string = econ
        .econtent
        .as_ref()
        .expect("missing econtent")
        .decode_as::<OctetString>()
        .expect("econtent not OctetString");
    let lds_der = octet_string.as_bytes().to_vec();

    // DS cert TBS + signature for cert chain verification
    let tbs_der = ds_cert.tbs_certificate.to_der().unwrap();
    let cert_sig_bytes = ds_cert
        .signature
        .as_bytes()
        .expect("cert signature not a bit string");
    let cert_sig_algo_der = ds_cert.signature_algorithm.to_der().unwrap();

    // Find offset of DS SPKI within TBS DER (for structural integrity check)
    let ds_spki_offset = tbs_der
        .windows(ds_spki_der.len())
        .position(|w| w == ds_spki_der.as_slice())
        .expect("DS SPKI not found in TBS DER") as u32;

    // ── Parse CSCA ───────────────────────────────────────────────────────────
    let csca_cert = x509_cert::Certificate::from_der(csca_bytes).expect("CSCA parse");
    let csca_spki_der = csca_cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .unwrap();

    // ── Pack pre-parsed fields (no DG data) ─────────────────────────────────
    let mut buf = Vec::new();
    pack_field(&mut buf, &signed_attrs_der);     // 0
    pack_field(&mut buf, &digest_alg_der);       // 1
    pack_field(&mut buf, &sig_algo_der);         // 2
    pack_field(&mut buf, signature_bytes);        // 3
    pack_field(&mut buf, &ds_spki_der);          // 4
    pack_field(&mut buf, &lds_der);              // 5
    pack_field(&mut buf, &tbs_der);              // 6
    pack_field(&mut buf, cert_sig_bytes);         // 7
    pack_field(&mut buf, &cert_sig_algo_der);    // 8
    pack_field(&mut buf, &csca_spki_der);        // 9
    // Append ds_spki_offset as raw u32 (no length prefix)
    buf.extend_from_slice(&ds_spki_offset.to_le_bytes());

    let dgs = PassportDGs {
        dg1: dg1.to_vec(),
        dg2: dg2.to_vec(),
        dg3: dg3.to_vec(),
        dg4: dg4.to_vec(),
        dg14: dg14.to_vec(),
    };

    (buf, dgs)
}

// ─── Guest verification with pre-parsed data ────────────────────────────────

/// Verify passport from pre-parsed byte slices (no CMS/X.509 DER parsing).
///
/// The host extracts all needed fields; the guest does:
/// - Lightweight DER parsing for algorithm identifiers (tiny structures)
/// - Structural integrity checks (messageDigest ↔ LDS, SPKI ↔ TBS)
/// - All cryptographic verification (RSA-PSS or ECDSA P-256, auto-detected)
fn verify_passport_preparsed(
    disclosure_mask: u8,
    signed_attrs_der: &[u8],
    digest_alg_der: &[u8],
    sig_algo_der: &[u8],
    signature_bytes: &[u8],
    ds_spki_der: &[u8],
    lds_der: &[u8],
    tbs_der: &[u8],
    cert_sig_bytes: &[u8],
    cert_sig_algo_der: &[u8],
    ds_spki_offset: u32,
    csca_spki_der: &[u8],
    dg1: &[u8],
    dg2: &[u8],
    dg3: &[u8],
    dg4: &[u8],
    dg14: &[u8],
) -> PassportProofOutput {
    // ── 1. Hash signed attributes (RFC 5652 §5.4) ─────────────────────────
    start_cycle_tracking("hash_signed_attrs");
    let digest = DigestAlgorithmIdentifier::from_der(digest_alg_der).unwrap();
    let message_hash = digest.hash_bytes(signed_attrs_der);
    end_cycle_tracking("hash_signed_attrs");

    // ── 2. Structural check: messageDigest in signed_attrs == hash(lds_der)
    //    This prevents a malicious prover from substituting a fake LDS.
    start_cycle_tracking("structural_checks");
    let lds_hash = digest.hash_bytes(lds_der);
    let msg_digest = extract_message_digest(signed_attrs_der)
        .expect("messageDigest attribute not found in signed_attrs");
    let structural_valid = msg_digest == lds_hash.as_slice();

    // Structural check: ds_spki_der is at the claimed offset in tbs_der
    let off = ds_spki_offset as usize;
    let spki_in_tbs = off + ds_spki_der.len() <= tbs_der.len()
        && &tbs_der[off..off + ds_spki_der.len()] == ds_spki_der;
    let structural_valid = structural_valid && spki_in_tbs;
    end_cycle_tracking("structural_checks");

    // ── 3. SOD signature verification (auto-detect RSA vs ECDSA) ─────────
    let ds_spki = SubjectPublicKeyInfo::from_der(ds_spki_der).unwrap();
    let sig_algo = SignatureAlgorithmIdentifier::from_der(sig_algo_der).unwrap();
    let sig_valid = verify_signature(&ds_spki, &sig_algo, signature_bytes, &message_hash);

    // ── 5. Data group hash verification via LDS ───────────────────────────
    start_cycle_tracking("parse_lds");
    let lso = LdsSecurityObject::from_der(lds_der).unwrap();
    end_cycle_tracking("parse_lds");

    start_cycle_tracking("dg_hash_verify");
    let dg_hashes_valid = lso
        .verify_dg_hashes(&[
            (1, dg1),
            (2, dg2),
            (3, dg3),
            (4, dg4),
            (14, dg14),
        ])
        .is_ok();
    end_cycle_tracking("dg_hash_verify");

    // ── 6. CSCA public key hash ───────────────────────────────────────────
    start_cycle_tracking("csca_hash");
    let csca_digest = DigestAlgorithmIdentifier::Sha256(
        icao_9303::asn1::DigestAlgorithmParameters::Null,
    );
    let csca_pubkey_hash_vec = csca_digest.hash_bytes(csca_spki_der);
    let mut csca_pubkey_hash = [0u8; 32];
    csca_pubkey_hash.copy_from_slice(&csca_pubkey_hash_vec);
    end_cycle_tracking("csca_hash");

    // ── 7. Certificate chain: DS cert signed by CSCA ──────────────────────
    let csca_spki = SubjectPublicKeyInfo::from_der(csca_spki_der).unwrap();
    let cert_sig_algo = SignatureAlgorithmIdentifier::from_der(cert_sig_algo_der).unwrap();
    let cert_digest_algo = cert_sig_algo.digest_algorithm();
    let cert_message_hash = cert_digest_algo.hash_bytes(tbs_der);
    let cert_chain_valid = verify_signature(&csca_spki, &cert_sig_algo, cert_sig_bytes, &cert_message_hash);

    let valid = structural_valid && sig_valid && dg_hashes_valid && cert_chain_valid;

    // ── 8. Parse MRZ and apply selective disclosure ───────────────────────
    start_cycle_tracking("mrz_parse");
    let mrz = MrzRaw::from_dg1(dg1).unwrap();
    end_cycle_tracking("mrz_parse");

    PassportProofOutput {
        valid,
        disclosure_mask,
        issuing_state: if disclosure_mask & DISCLOSE_ISSUING_STATE != 0 { mrz.issuing_state } else { [0; 3] },
        nationality: if disclosure_mask & DISCLOSE_NATIONALITY != 0 { mrz.nationality } else { [0; 3] },
        date_of_birth: if disclosure_mask & DISCLOSE_DOB != 0 { mrz.date_of_birth } else { [0; 6] },
        sex: if disclosure_mask & DISCLOSE_SEX != 0 { mrz.sex } else { 0 },
        expiry_date: if disclosure_mask & DISCLOSE_EXPIRY != 0 { mrz.expiry_date } else { [0; 6] },
        csca_pubkey_hash,
    }
}

/// Extract the messageDigest attribute value from DER-encoded SignedAttributes.
///
/// SignedAttributes is a SET OF Attribute, where each Attribute is:
///   SEQUENCE { OID, SET OF AttributeValue }
/// We search for OID 1.2.840.113549.1.9.4 (id-messageDigest) and extract
/// the OCTET STRING value.
fn extract_message_digest(signed_attrs_der: &[u8]) -> Option<&[u8]> {
    // id-messageDigest OID: 1.2.840.113549.1.9.4
    // DER encoding: 06 09 2A 86 48 86 F7 0D 01 09 04
    const MSG_DIGEST_OID: [u8; 11] = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04];

    // Find the OID in the signed_attrs DER
    let pos = signed_attrs_der
        .windows(MSG_DIGEST_OID.len())
        .position(|w| w == MSG_DIGEST_OID)?;

    // After the OID, we expect: SET { OCTET STRING { hash_bytes } }
    // Navigate: skip OID → SET tag+len → OCTET STRING tag+len → value
    let after_oid = &signed_attrs_der[pos + MSG_DIGEST_OID.len()..];

    // Skip SET tag (0x31) + length
    if after_oid.is_empty() || after_oid[0] != 0x31 {
        return None;
    }
    let (_, set_content) = skip_tag_length(after_oid)?;

    // Parse OCTET STRING tag (0x04) + length → value
    if set_content.is_empty() || set_content[0] != 0x04 {
        return None;
    }
    let (octet_len, octet_value) = skip_tag_length(set_content)?;
    Some(&octet_value[..octet_len])
}

/// Skip a DER tag+length, return (content_length, content_start).
fn skip_tag_length(data: &[u8]) -> Option<(usize, &[u8])> {
    if data.len() < 2 {
        return None;
    }
    let rest = &data[1..]; // skip tag byte
    if rest[0] < 0x80 {
        // Short form length
        let len = rest[0] as usize;
        Some((len, &rest[1..]))
    } else {
        // Long form length
        let num_bytes = (rest[0] & 0x7F) as usize;
        if rest.len() < 1 + num_bytes {
            return None;
        }
        let mut len = 0usize;
        for i in 0..num_bytes {
            len = (len << 8) | rest[1 + i] as usize;
        }
        Some((len, &rest[1 + num_bytes..]))
    }
}

// ─── Core verification logic (original, for struct variant baseline) ────────

/// Core verification logic — parses raw SOD + CSCA bytes in the guest.
/// Used by the struct variant as a baseline.
fn verify_passport_inner(
    disclosure_mask: u8,
    sod_bytes: &[u8],
    dg1: &[u8],
    dg2: &[u8],
    dg3: &[u8],
    dg4: &[u8],
    dg14: &[u8],
    csca_bytes: &[u8],
) -> PassportProofOutput {
    // ── 1. Parse EF.SOD ───────────────────────────────────────────────────
    start_cycle_tracking("parse_sod");
    let sod = EfSod::from_der(sod_bytes).unwrap();
    let signer = sod.signer_info();
    end_cycle_tracking("parse_sod");

    // ── 2. Hash signed attributes (RFC 5652 §5.4) ─────────────────────────
    start_cycle_tracking("hash_signed_attrs");
    let digest = DigestAlgorithmIdentifier::from_der(
        &signer.digest_alg.to_der().unwrap(),
    )
    .unwrap();
    let message_hash = if let Some(signed_attrs) = &signer.signed_attrs {
        digest.hash_bytes(&signed_attrs.to_der().unwrap())
    } else {
        digest.hash_der(sod.encapsulated_content())
    };
    end_cycle_tracking("hash_signed_attrs");

    // ── 3. Extract DS certificate from SOD ──────────────────────────────────
    start_cycle_tracking("extract_cert");
    let certs = sod.signed_data().certificates.as_ref().unwrap();
    let ds_cert = match certs.0.iter().next().unwrap() {
        CertificateChoices::Certificate(c) => c,
        _ => panic!("unexpected certificate type"),
    };
    let spki_der = ds_cert.tbs_certificate.subject_public_key_info.to_der().unwrap();
    let spki = SubjectPublicKeyInfo::from_der(&spki_der).unwrap();
    end_cycle_tracking("extract_cert");

    // ── 4. SOD signature verification (auto-detect RSA vs ECDSA) ────────────
    let sig_algo = SignatureAlgorithmIdentifier::from_der(
        &signer.signature_algorithm.to_der().unwrap(),
    )
    .unwrap();
    let sig_valid = verify_signature(&spki, &sig_algo, signer.signature.as_bytes(), &message_hash);

    // ── 5. Data group hash verification ─────────────────────────────────────
    start_cycle_tracking("dg_hash_verify");
    let lso = sod.lds_security_object().unwrap();
    let dg_hashes_valid = lso
        .verify_dg_hashes(&[
            (1, dg1),
            (2, dg2),
            (3, dg3),
            (4, dg4),
            (14, dg14),
        ])
        .is_ok();
    end_cycle_tracking("dg_hash_verify");

    // ── 6. Certificate chain: DS cert signed by CSCA ────────────────────────
    start_cycle_tracking("parse_csca");
    let csca = x509_cert::Certificate::from_der(csca_bytes).unwrap();
    let csca_spki_der = csca.tbs_certificate.subject_public_key_info.to_der().unwrap();
    let csca_spki = SubjectPublicKeyInfo::from_der(&csca_spki_der).unwrap();
    end_cycle_tracking("parse_csca");

    start_cycle_tracking("csca_hash");
    let csca_digest = DigestAlgorithmIdentifier::Sha256(
        icao_9303::asn1::DigestAlgorithmParameters::Null,
    );
    let csca_pubkey_hash_vec = csca_digest.hash_bytes(&csca_spki_der);
    let mut csca_pubkey_hash = [0u8; 32];
    csca_pubkey_hash.copy_from_slice(&csca_pubkey_hash_vec);
    end_cycle_tracking("csca_hash");

    let tbs_der = ds_cert.tbs_certificate.to_der().unwrap();
    let cert_sig_algo = SignatureAlgorithmIdentifier::from_der(
        &ds_cert.signature_algorithm.to_der().unwrap(),
    )
    .unwrap();
    let cert_digest_algo = cert_sig_algo.digest_algorithm();
    let cert_message_hash = cert_digest_algo.hash_bytes(&tbs_der);
    let cert_sig_bytes = ds_cert
        .signature
        .as_bytes()
        .expect("cert signature not a bit string");
    let cert_chain_valid = verify_signature(&csca_spki, &cert_sig_algo, cert_sig_bytes, &cert_message_hash);

    let valid = sig_valid && dg_hashes_valid && cert_chain_valid;

    // ── 7. Parse MRZ and apply selective disclosure ─────────────────────────
    start_cycle_tracking("mrz_parse");
    let mrz = MrzRaw::from_dg1(dg1).unwrap();
    end_cycle_tracking("mrz_parse");

    PassportProofOutput {
        valid,
        disclosure_mask,
        issuing_state: if disclosure_mask & DISCLOSE_ISSUING_STATE != 0 { mrz.issuing_state } else { [0; 3] },
        nationality: if disclosure_mask & DISCLOSE_NATIONALITY != 0 { mrz.nationality } else { [0; 3] },
        date_of_birth: if disclosure_mask & DISCLOSE_DOB != 0 { mrz.date_of_birth } else { [0; 6] },
        sex: if disclosure_mask & DISCLOSE_SEX != 0 { mrz.sex } else { 0 },
        expiry_date: if disclosure_mask & DISCLOSE_EXPIRY != 0 { mrz.expiry_date } else { [0; 6] },
        csca_pubkey_hash,
    }
}

// ─── Provable functions ─────────────────────────────────────────────────────

/// Pre-parsed variant — host extracts byte fields from SOD/CSCA,
/// guest skips all CMS/X.509 DER parsing.
///
/// DGs are passed as a separate `PrivateInput<PassportDGs>` so each DG gets
/// its own aligned heap allocation (fixes jolt-inlines-sha2 LW alignment regression).
#[jolt::provable(heap_size = 0x800000, stack_size = 0x40000, max_trace_length = 0x1000000, max_output_size = 64, max_untrusted_advice_size = 0x10000)]
fn verify_passport_packed(disclosure_mask: u8, preparsed_buf: jolt::PrivateInput<Vec<u8>>, dgs: jolt::PrivateInput<PassportDGs>) -> PassportProofOutput {
    let buf = &*preparsed_buf;

    // Unpack pre-parsed SOD/CSCA fields
    let (signed_attrs_der, buf) = take_slice(buf);
    let (digest_alg_der, buf) = take_slice(buf);
    let (sig_algo_der, buf) = take_slice(buf);
    let (signature_bytes, buf) = take_slice(buf);
    let (ds_spki_der, buf) = take_slice(buf);
    let (lds_der, buf) = take_slice(buf);
    let (tbs_der, buf) = take_slice(buf);
    let (cert_sig_bytes, buf) = take_slice(buf);
    let (cert_sig_algo_der, buf) = take_slice(buf);
    let (csca_spki_der, buf) = take_slice(buf);
    let (ds_spki_offset, _) = take_u32(buf);

    // DGs come from separate PrivateInput — each Vec has its own aligned allocation
    let dgs = &*dgs;

    verify_passport_preparsed(
        disclosure_mask,
        signed_attrs_der,
        digest_alg_der,
        sig_algo_der,
        signature_bytes,
        ds_spki_der,
        lds_der,
        tbs_der,
        cert_sig_bytes,
        cert_sig_algo_der,
        ds_spki_offset,
        csca_spki_der,
        &dgs.dg1, &dgs.dg2, &dgs.dg3, &dgs.dg4, &dgs.dg14,
    )
}

/// Baseline struct variant — Jolt macro postcard-deserializes the struct,
/// guest does full CMS/X.509 DER parsing.
#[jolt::provable(heap_size = 0x800000, stack_size = 0x40000, max_trace_length = 0x1000000, max_output_size = 64, max_untrusted_advice_size = 0x10000)]
fn verify_passport_struct(disclosure_mask: u8, passport: jolt::PrivateInput<PassportData>) -> PassportProofOutput {
    let passport = &*passport;

    verify_passport_inner(
        disclosure_mask,
        &passport.sod,
        &passport.dg1,
        &passport.dg2,
        &passport.dg3,
        &passport.dg4,
        &passport.dg14,
        &passport.csca,
    )
}

// ─── Predicate proofs ────────────────────────────────────────────────────────

/// Core verification for predicate proofs — verifies SOD signature, cert chain,
/// and DG1 hash only (skips DG2-4/14 to save ~2.8M cycles).
///
/// Auto-detects RSA vs ECDSA from the SPKI type — works for any crypto config.
fn verify_passport_dg1_only(
    signed_attrs_der: &[u8],
    digest_alg_der: &[u8],
    sig_algo_der: &[u8],
    signature_bytes: &[u8],
    ds_spki_der: &[u8],
    lds_der: &[u8],
    tbs_der: &[u8],
    cert_sig_bytes: &[u8],
    cert_sig_algo_der: &[u8],
    ds_spki_offset: u32,
    csca_spki_der: &[u8],
    dg1: &[u8],
) -> (bool, MrzRaw, [u8; 32]) {
    // ── 1. Hash signed attributes ───────────────────────────────────────
    start_cycle_tracking("hash_signed_attrs");
    let digest = DigestAlgorithmIdentifier::from_der(digest_alg_der).unwrap();
    let message_hash = digest.hash_bytes(signed_attrs_der);
    end_cycle_tracking("hash_signed_attrs");

    // ── 2. Structural checks ────────────────────────────────────────────
    start_cycle_tracking("structural_checks");
    let lds_hash = digest.hash_bytes(lds_der);
    let msg_digest = extract_message_digest(signed_attrs_der)
        .expect("messageDigest attribute not found in signed_attrs");
    let structural_valid = msg_digest == lds_hash.as_slice();

    let off = ds_spki_offset as usize;
    let spki_in_tbs = off + ds_spki_der.len() <= tbs_der.len()
        && &tbs_der[off..off + ds_spki_der.len()] == ds_spki_der;
    let structural_valid = structural_valid && spki_in_tbs;
    end_cycle_tracking("structural_checks");

    // ── 3. SOD signature verification (auto-detect RSA vs ECDSA) ────────
    let ds_spki = SubjectPublicKeyInfo::from_der(ds_spki_der).unwrap();
    let sig_algo = SignatureAlgorithmIdentifier::from_der(sig_algo_der).unwrap();
    let sig_valid = verify_signature(&ds_spki, &sig_algo, signature_bytes, &message_hash);

    // ── 4. DG1 hash verification only ───────────────────────────────────
    start_cycle_tracking("parse_lds");
    let lso = LdsSecurityObject::from_der(lds_der).unwrap();
    end_cycle_tracking("parse_lds");

    start_cycle_tracking("dg_hash_verify");
    let dg1_hash_valid = lso.verify_dg_hashes(&[(1, dg1)]).is_ok();
    end_cycle_tracking("dg_hash_verify");

    // ── 5. CSCA public key hash ─────────────────────────────────────────
    start_cycle_tracking("csca_hash");
    let csca_digest = DigestAlgorithmIdentifier::Sha256(
        icao_9303::asn1::DigestAlgorithmParameters::Null,
    );
    let csca_pubkey_hash_vec = csca_digest.hash_bytes(csca_spki_der);
    let mut csca_pubkey_hash = [0u8; 32];
    csca_pubkey_hash.copy_from_slice(&csca_pubkey_hash_vec);
    end_cycle_tracking("csca_hash");

    // ── 6. Certificate chain: DS cert signed by CSCA ────────────────────
    let csca_spki = SubjectPublicKeyInfo::from_der(csca_spki_der).unwrap();
    let cert_sig_algo = SignatureAlgorithmIdentifier::from_der(cert_sig_algo_der).unwrap();
    let cert_digest_algo = cert_sig_algo.digest_algorithm();
    let cert_message_hash = cert_digest_algo.hash_bytes(tbs_der);
    let cert_chain_valid = verify_signature(&csca_spki, &cert_sig_algo, cert_sig_bytes, &cert_message_hash);

    let valid = structural_valid && sig_valid && dg1_hash_valid && cert_chain_valid;

    // ── 7. Parse MRZ ────────────────────────────────────────────────────
    start_cycle_tracking("mrz_parse");
    let mrz = MrzRaw::from_dg1(dg1).unwrap();
    end_cycle_tracking("mrz_parse");

    (valid, mrz, csca_pubkey_hash)
}

/// Verify a signature using the appropriate algorithm (RSA-PSS or ECDSA P-256)
/// based on the public key type.
fn verify_signature(
    spki: &SubjectPublicKeyInfo,
    sig_algo: &SignatureAlgorithmIdentifier,
    signature_bytes: &[u8],
    message_hash: &[u8],
) -> bool {
    match spki {
        SubjectPublicKeyInfo::Rsa(_) => {
            start_cycle_tracking("ring_setup");
            let rsa_key = RSAPublicKey::<Uint2048>::try_from(spki.clone()).unwrap();
            end_cycle_tracking("ring_setup");

            start_cycle_tracking("mont_encode");
            let sig_elem = rsa_key.ring.from(Uint2048::from_be_slice(signature_bytes));
            let msg_elem = rsa_key.ring.from(Uint2048::from_be_slice(message_hash));
            end_cycle_tracking("mont_encode");

            start_cycle_tracking("rsa_verify");
            let valid = rsa_key.verify(msg_elem, sig_elem, sig_algo).is_ok();
            end_cycle_tracking("rsa_verify");
            valid
        }
        SubjectPublicKeyInfo::Ec(ec) => {
            start_cycle_tracking("ecdsa_verify");
            let valid = verify_ecdsa_p256_fast(message_hash, signature_bytes, ec.point.as_bytes()).is_ok();
            end_cycle_tracking("ecdsa_verify");
            valid
        }
        _ => panic!("unsupported public key type for signature verification"),
    }
}

/// Unpack pre-parsed buffer fields (shared by all predicate provable functions).
fn unpack_preparsed(buf: &[u8]) -> (
    &[u8], &[u8], &[u8], &[u8], &[u8], &[u8], &[u8], &[u8], &[u8], &[u8], u32
) {
    let (signed_attrs_der, buf) = take_slice(buf);
    let (digest_alg_der, buf) = take_slice(buf);
    let (sig_algo_der, buf) = take_slice(buf);
    let (signature_bytes, buf) = take_slice(buf);
    let (ds_spki_der, buf) = take_slice(buf);
    let (lds_der, buf) = take_slice(buf);
    let (tbs_der, buf) = take_slice(buf);
    let (cert_sig_bytes, buf) = take_slice(buf);
    let (cert_sig_algo_der, buf) = take_slice(buf);
    let (csca_spki_der, buf) = take_slice(buf);
    let (ds_spki_offset, _) = take_u32(buf);
    (
        signed_attrs_der, digest_alg_der, sig_algo_der, signature_bytes,
        ds_spki_der, lds_der, tbs_der, cert_sig_bytes, cert_sig_algo_der,
        csca_spki_der, ds_spki_offset,
    )
}

/// Compare MRZ YYMMDD date against a threshold.
/// Returns true if the MRZ date is before the threshold (i.e. person is old enough).
/// `threshold` is [YY, YY, MM, MM, DD, DD] as ASCII digits.
fn mrz_date_before(date: &[u8; 6], threshold: &[u8; 6]) -> bool {
    // Simple lexicographic comparison works for YYMMDD when century is handled.
    // MRZ uses 2-digit year: 00-99. ICAO convention: 00-49 = 2000-2049, 50-99 = 1950-1999.
    // For age checks, we compare birth year vs threshold year with century adjustment.
    let birth_century: u8 = if date[0] >= b'5' { 19 } else { 20 };
    let thresh_century: u8 = if threshold[0] >= b'5' { 19 } else { 20 };

    if birth_century != thresh_century {
        return birth_century < thresh_century;
    }
    // Same century — lexicographic comparison on YYMMDD
    date < threshold
}

/// Predicate proof: passport holder is at least `min_age` years old.
///
/// Public inputs: `min_age`, `current_date` (YYMMDD, verifier checks it matches today).
/// Output: PredicateOutput with `predicate = true` if holder is >= min_age.
/// Only hashes DG1 — skips DG2-4/14 for ~50% cycle savings.
#[jolt::provable(heap_size = 0x800000, stack_size = 0x80000, max_trace_length = 0x800000, max_output_size = 48, max_untrusted_advice_size = 0x10000)]
fn check_age(
    min_age: u8,
    current_date: [u8; 6],
    preparsed_buf: jolt::PrivateInput<Vec<u8>>,
    dg1: jolt::PrivateInput<Vec<u8>>,
) -> PredicateOutput {
    let (
        signed_attrs_der, digest_alg_der, sig_algo_der, signature_bytes,
        ds_spki_der, lds_der, tbs_der, cert_sig_bytes, cert_sig_algo_der,
        csca_spki_der, ds_spki_offset,
    ) = unpack_preparsed(&*preparsed_buf);

    let (valid, mrz, csca_pubkey_hash) = verify_passport_dg1_only(
        signed_attrs_der, digest_alg_der, sig_algo_der, signature_bytes,
        ds_spki_der, lds_der, tbs_der, cert_sig_bytes, cert_sig_algo_der,
        ds_spki_offset, csca_spki_der, &*dg1,
    );

    // Compute threshold date: current_date - min_age years
    // YYMMDD subtraction: subtract min_age from year, keep month/day
    let cur_yy = (current_date[0] - b'0') * 10 + (current_date[1] - b'0');
    let thresh_yy = cur_yy.wrapping_sub(min_age);
    let threshold: [u8; 6] = [
        b'0' + thresh_yy / 10,
        b'0' + thresh_yy % 10,
        current_date[2], current_date[3], // same month
        current_date[4], current_date[5], // same day
    ];

    let predicate = mrz_date_before(&mrz.date_of_birth, &threshold);

    PredicateOutput { valid, predicate, csca_pubkey_hash }
}

/// Predicate proof: passport holder's nationality is in an allowed set.
///
/// Public inputs: `allowed` (concatenated 3-letter codes, up to 10 countries,
/// e.g. b"USAGBRDEU000000000000000000000"). `allowed_count` = number of codes.
/// Output: PredicateOutput with `predicate = true` if nationality is in the set.
#[jolt::provable(heap_size = 0x800000, stack_size = 0x80000, max_trace_length = 0x800000, max_output_size = 48, max_untrusted_advice_size = 0x10000)]
fn check_nationality(
    allowed: [u8; 30],
    allowed_count: u8,
    preparsed_buf: jolt::PrivateInput<Vec<u8>>,
    dg1: jolt::PrivateInput<Vec<u8>>,
) -> PredicateOutput {
    let (
        signed_attrs_der, digest_alg_der, sig_algo_der, signature_bytes,
        ds_spki_der, lds_der, tbs_der, cert_sig_bytes, cert_sig_algo_der,
        csca_spki_der, ds_spki_offset,
    ) = unpack_preparsed(&*preparsed_buf);

    let (valid, mrz, csca_pubkey_hash) = verify_passport_dg1_only(
        signed_attrs_der, digest_alg_der, sig_algo_der, signature_bytes,
        ds_spki_der, lds_der, tbs_der, cert_sig_bytes, cert_sig_algo_der,
        ds_spki_offset, csca_spki_der, &*dg1,
    );

    // Check if nationality is in the allowed list (up to 10 × 3-byte codes)
    let count = allowed_count as usize;
    let mut predicate = false;
    let mut i = 0;
    while i < count && i * 3 + 3 <= allowed.len() {
        if allowed[i * 3..i * 3 + 3] == mrz.nationality {
            predicate = true;
            break;
        }
        i += 1;
    }

    PredicateOutput { valid, predicate, csca_pubkey_hash }
}

