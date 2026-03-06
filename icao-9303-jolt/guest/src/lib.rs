use cms::cert::CertificateChoices;
use der::{Decode, Encode};
use icao_9303::{
    asn1::{
        emrtd::{mrz::MrzRaw, EfSod},
        public_key_info::SubjectPublicKeyInfo,
        DigestAlgorithmIdentifier,
        SignatureAlgorithmIdentifier,
    },
    crypto::{mod_ring::RingRefExt, rsa::RSAPublicKey},
};
use jolt::{end_cycle_tracking, start_cycle_tracking};
use ruint::Uint;
use serde::{Deserialize, Serialize};

const SOD_BYTES: &[u8] = include_bytes!("../../../tests/dataset/EF_SOD.bin");
const DG1_BYTES: &[u8] = include_bytes!("../../../tests/dataset/Datagroup1.bin");
const DG2_BYTES: &[u8] = include_bytes!("../../../tests/dataset/Datagroup2.bin");
const DG3_BYTES: &[u8] = include_bytes!("../../../tests/dataset/Datagroup3.bin");
const DG4_BYTES: &[u8] = include_bytes!("../../../tests/dataset/Datagroup4.bin");
const DG14_BYTES: &[u8] = include_bytes!("../../../tests/dataset/Datagroup14.bin");

type Uint2048 = Uint<2048, 32>;

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
}

/// Prove ICAO 9303 Passive Authentication with selective MRZ disclosure:
///
/// 1. RSA-PSS-SHA256 signature on the LdsSecurityObject (SOD).
/// 2. SHA-256 hash of each data group matches its SOD commitment.
/// 3. Parse MRZ from DG1 and selectively disclose fields per `disclosure_mask`.
#[jolt::provable(heap_size = 0x800000, stack_size = 0x40000, max_trace_length = 0x800000, max_output_size = 64)]
fn verify_passport(disclosure_mask: u8) -> PassportProofOutput {
    // ── 1. Parse EF.SOD ───────────────────────────────────────────────────
    start_cycle_tracking("parse_sod");
    let sod = EfSod::from_der(SOD_BYTES).unwrap();
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

    // ── 3. Extract RSA public key from DS certificate ─────────────────────
    start_cycle_tracking("extract_cert");
    let certs = sod.signed_data().certificates.as_ref().unwrap();
    let cert = match certs.0.iter().next().unwrap() {
        CertificateChoices::Certificate(c) => c,
        _ => panic!("unexpected certificate type"),
    };
    let spki_der = cert.tbs_certificate.subject_public_key_info.to_der().unwrap();
    let spki = SubjectPublicKeyInfo::from_der(&spki_der).unwrap();
    end_cycle_tracking("extract_cert");

    start_cycle_tracking("ring_setup");
    let rsa_key = RSAPublicKey::<Uint2048>::try_from(spki).unwrap();
    end_cycle_tracking("ring_setup");

    // ── 4. RSA-PSS verification ───────────────────────────────────────────
    start_cycle_tracking("mont_encode");
    let sig_elem =
        rsa_key.ring.from(Uint2048::from_be_slice(signer.signature.as_bytes()));
    let msg_elem = rsa_key.ring.from(Uint2048::from_be_slice(&message_hash));
    let sig_algo = SignatureAlgorithmIdentifier::from_der(
        &signer.signature_algorithm.to_der().unwrap(),
    )
    .unwrap();
    end_cycle_tracking("mont_encode");

    start_cycle_tracking("rsa_verify");
    let sig_valid = rsa_key.verify(msg_elem, sig_elem, &sig_algo).is_ok();
    end_cycle_tracking("rsa_verify");

    // ── 5. Data group hash verification ───────────────────────────────────
    start_cycle_tracking("dg_hash_verify");
    let lso = sod.lds_security_object().unwrap();
    let dg_hashes_valid = lso
        .verify_dg_hashes(&[
            (1, DG1_BYTES),
            (2, DG2_BYTES),
            (3, DG3_BYTES),
            (4, DG4_BYTES),
            (14, DG14_BYTES),
        ])
        .is_ok();
    end_cycle_tracking("dg_hash_verify");

    let valid = sig_valid && dg_hashes_valid;

    // ── 6. Parse MRZ and apply selective disclosure ───────────────────────
    start_cycle_tracking("mrz_parse");
    let mrz = MrzRaw::from_dg1(DG1_BYTES).unwrap();
    end_cycle_tracking("mrz_parse");

    PassportProofOutput {
        valid,
        disclosure_mask,
        issuing_state: if disclosure_mask & DISCLOSE_ISSUING_STATE != 0 { mrz.issuing_state } else { [0; 3] },
        nationality: if disclosure_mask & DISCLOSE_NATIONALITY != 0 { mrz.nationality } else { [0; 3] },
        date_of_birth: if disclosure_mask & DISCLOSE_DOB != 0 { mrz.date_of_birth } else { [0; 6] },
        sex: if disclosure_mask & DISCLOSE_SEX != 0 { mrz.sex } else { 0 },
        expiry_date: if disclosure_mask & DISCLOSE_EXPIRY != 0 { mrz.expiry_date } else { [0; 6] },
    }
}
