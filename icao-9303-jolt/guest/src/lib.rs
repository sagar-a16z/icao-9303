use cms::cert::CertificateChoices;
use der::{Decode, Encode};
use icao_9303::{
    asn1::{
        emrtd::EfSod,
        public_key_info::SubjectPublicKeyInfo,
        DigestAlgorithmIdentifier,
        SignatureAlgorithmIdentifier,
    },
    crypto::{mod_ring::RingRefExt, rsa::RSAPublicKey},
};
use jolt::{end_cycle_tracking, start_cycle_tracking};
use ruint::Uint;

const SOD_BYTES: &[u8] = include_bytes!("../../../tests/dataset/EF_SOD.bin");
const DG1_BYTES: &[u8] = include_bytes!("../../../tests/dataset/Datagroup1.bin");
const DG2_BYTES: &[u8] = include_bytes!("../../../tests/dataset/Datagroup2.bin");
const DG3_BYTES: &[u8] = include_bytes!("../../../tests/dataset/Datagroup3.bin");
const DG4_BYTES: &[u8] = include_bytes!("../../../tests/dataset/Datagroup4.bin");
const DG14_BYTES: &[u8] = include_bytes!("../../../tests/dataset/Datagroup14.bin");

type Uint2048 = Uint<2048, 32>;

/// Prove ICAO 9303 Passive Authentication steps 1 and 2:
///
/// 1. The EF.SOD carries a valid RSA-PSS-SHA256 signature (DS cert signed
///    the LdsSecurityObject).
/// 2. Every data group on chip hashes to the value committed in the SOD.
#[jolt::provable(heap_size = 0x800000, stack_size = 0x40000, max_trace_length = 0x800000)]
fn verify_sod() -> bool {
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
    // BSI test SOD commits to DGs 1, 2, 3, 4, 14 only.
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

    sig_valid && dg_hashes_valid
}
