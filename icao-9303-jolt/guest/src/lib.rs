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

// BSI TR-03105-5 reference passport dataset, baked in at compile time.
const SOD_BYTES: &[u8] = include_bytes!("../../../tests/dataset/EF_SOD.bin");

type Uint2048 = Uint<2048, 32>;

/// Prove that the BSI reference passport's Document Security Object carries a
/// valid RSA-PSS-SHA256 signature — using icao-9303's own parsing and
/// verification code paths.
#[jolt::provable(heap_size = 0x800000, stack_size = 0x40000, max_trace_length = 0x8000000)]
fn verify_sod() -> bool {
    // ── 1. Parse EF.SOD using the library's types ─────────────────────────────
    start_cycle_tracking("parse_sod");
    let sod = EfSod::from_der(SOD_BYTES).unwrap();
    let signer = sod.signer_info();
    end_cycle_tracking("parse_sod");

    // ── 2. Hash the signed attributes (RFC 5652 §5.4) ─────────────────────────
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

    // ── 3. Extract RSA public key from the embedded DS certificate ─────────────
    start_cycle_tracking("extract_cert");
    let certs = sod.signed_data().certificates.as_ref().unwrap();
    let cert = match certs.0.iter().next().unwrap() {
        CertificateChoices::Certificate(c) => c,
        _ => panic!("unexpected certificate type"),
    };
    let spki_der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .unwrap();
    let spki = SubjectPublicKeyInfo::from_der(&spki_der).unwrap();
    end_cycle_tracking("extract_cert");

    start_cycle_tracking("ring_setup");
    let rsa_key = RSAPublicKey::<Uint2048>::try_from(spki).unwrap();
    end_cycle_tracking("ring_setup");

    // ── 4. Build ring elements and verify via the library's RSA-PSS path ───────
    start_cycle_tracking("mont_encode");
    let sig_elem = rsa_key.ring.from(Uint2048::from_be_slice(signer.signature.as_bytes()));
    let msg_elem = rsa_key.ring.from(Uint2048::from_be_slice(&message_hash));
    let sig_algo = SignatureAlgorithmIdentifier::from_der(
        &signer.signature_algorithm.to_der().unwrap(),
    )
    .unwrap();
    end_cycle_tracking("mont_encode");

    start_cycle_tracking("rsa_verify");
    let result = rsa_key.verify(msg_elem, sig_elem, &sig_algo).is_ok();
    end_cycle_tracking("rsa_verify");

    result
}
