mod dataset;

use {
    anyhow::{bail, Result},
    cms::cert::CertificateChoices,
    dataset::Dataset,
    der::{Decode, Encode},
    icao_9303::{
        asn1::{
            emrtd::EfSod,
            public_key_info::SubjectPublicKeyInfo,
            DigestAlgorithmIdentifier,
            SignatureAlgorithmIdentifier,
        },
        crypto::{mod_ring::RingRefExt, rsa::RSAPublicKey},
    },
    ruint::Uint,
};

type Uint2048 = Uint<2048, 32>;

/// Full end-to-end test via the library's verify_signature() dispatcher.
#[test]
fn test_verify() -> Result<()> {
    let dataset = Dataset::load()?;
    let sod = EfSod::from_der(&dataset.sod)?;
    sod.verify_signature()?;
    Ok(())
}

/// Verify the DS certificate is present and has non-empty Subject / Issuer.
#[test]
fn test_extract_signer_cert() -> Result<()> {
    let d = Dataset::load()?;
    let sod = EfSod::from_der(&d.sod)?;

    let certs = sod
        .signed_data()
        .certificates
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("No certificates in SignedData"))?;

    let cert = match certs.0.iter().next() {
        Some(CertificateChoices::Certificate(c)) => c,
        _ => bail!("No usable certificate"),
    };

    let subject = cert.tbs_certificate.subject.to_string();
    let issuer = cert.tbs_certificate.issuer.to_string();
    println!("Subject: {subject}");
    println!("Issuer:  {issuer}");

    assert!(!subject.is_empty());
    assert!(!issuer.is_empty());
    Ok(())
}

/// Confirm the DS certificate carries an RSA public key.
#[test]
fn test_extract_public_key() -> Result<()> {
    let d = Dataset::load()?;
    let sod = EfSod::from_der(&d.sod)?;

    let certs = sod.signed_data().certificates.as_ref().unwrap();
    let cert = match certs.0.iter().next().unwrap() {
        CertificateChoices::Certificate(c) => c,
        _ => bail!("unexpected"),
    };

    let spki_der = cert.tbs_certificate.subject_public_key_info.to_der()?;
    let spki = SubjectPublicKeyInfo::from_der(&spki_der)?;

    assert!(
        matches!(spki, SubjectPublicKeyInfo::Rsa(_)),
        "Expected RSA SubjectPublicKeyInfo"
    );
    Ok(())
}

/// Per RFC 5652 §5.4, signedAttrs must be present so we hash them, not eContent.
#[test]
fn test_signed_attrs_present() -> Result<()> {
    let d = Dataset::load()?;
    let sod = EfSod::from_der(&d.sod)?;
    assert!(
        sod.signer_info().signed_attrs.is_some(),
        "signed_attrs must be present"
    );
    Ok(())
}

/// Manual RSA-PSS verification — same logic as verify_signature(), spelled out.
/// Useful as documentation and as a regression test independent of the dispatcher.
#[test]
fn test_rsa_pss_verify_manual() -> Result<()> {
    let d = Dataset::load()?;
    let sod = EfSod::from_der(&d.sod)?;
    let signer = sod.signer_info();

    let digest = DigestAlgorithmIdentifier::from_der(&signer.digest_alg.to_der()?)?;
    let message_hash = if let Some(sa) = &signer.signed_attrs {
        digest.hash_bytes(&sa.to_der()?)
    } else {
        digest.hash_der(sod.encapsulated_content())
    };

    let certs = sod.signed_data().certificates.as_ref().unwrap();
    let cert = match certs.0.iter().next().unwrap() {
        CertificateChoices::Certificate(c) => c,
        _ => bail!("unexpected"),
    };
    let spki = SubjectPublicKeyInfo::from_der(&cert.tbs_certificate.subject_public_key_info.to_der()?)?;
    let rsa_key = RSAPublicKey::<Uint2048>::try_from(spki)?;

    let sig_elem = rsa_key.ring.from(Uint2048::from_be_slice(signer.signature.as_bytes()));
    let msg_elem = rsa_key.ring.from(Uint2048::from_be_slice(&message_hash));
    let sig_algo = SignatureAlgorithmIdentifier::from_der(&signer.signature_algorithm.to_der()?)?;

    rsa_key.verify(msg_elem, sig_elem, &sig_algo)?;
    Ok(())
}

/// Verify the DS certificate was signed by the CSCA (step 3 of Passive Authentication).
/// Skips gracefully if CSCA.cer is not present in the test dataset.
#[test]
fn test_verify_ds_cert_by_csca() -> Result<()> {
    let d = Dataset::load()?;
    let csca_der = match &d.csca {
        Some(c) => c,
        None => {
            println!("Skipping — CSCA.cer not found in tests/dataset/");
            return Ok(());
        }
    };

    let csca = x509_cert::Certificate::from_der(csca_der)?;
    let sod = EfSod::from_der(&d.sod)?;
    let ds = icao_9303::crypto::certificate::ds_cert_from_sod(&sod)?;

    icao_9303::crypto::certificate::verify_cert_signature(&ds, &csca)?;
    Ok(())
}
