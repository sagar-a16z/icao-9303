//! X.509 certificate signature verification.
//!
//! Used for Passive Authentication step 3: verify the Document Signer
//! certificate (DS cert) was signed by a Country Signing CA (CSCA).

use {
    crate::{
        asn1::{
            public_key_info::SubjectPublicKeyInfo,
            DigestAlgorithmIdentifier,
            SignatureAlgorithmIdentifier,
        },
        crypto::{mod_ring::RingRefExt, rsa::RSAPublicKey},
    },
    anyhow::{bail, Result},
    der::{Decode, Encode},
    ruint::Uint,
};

type Uint2048 = Uint<2048, 32>;

/// Verify that `cert` was signed by `issuer_cert`.
///
/// Implements the core of X.509 certificate path validation:
/// hash the TBS (to-be-signed) portion of `cert` and verify the
/// signature using the public key from `issuer_cert`.
///
/// Currently supports RSA-PSS only. Returns an error for EC-signed
/// certificates (many modern passports) until ECDSA is implemented.
pub fn verify_cert_signature(
    cert: &x509_cert::Certificate,
    issuer_cert: &x509_cert::Certificate,
) -> Result<()> {
    // ── 1. Extract issuer public key ───────────────────────────────────────
    let issuer_spki_der = issuer_cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()?;
    let issuer_spki = SubjectPublicKeyInfo::from_der(&issuer_spki_der)?;

    // ── 2. Get TBS bytes and hash them ─────────────────────────────────────
    let tbs_der = cert.tbs_certificate.to_der()?;

    let sig_algo =
        SignatureAlgorithmIdentifier::from_der(&cert.signature_algorithm.to_der()?)?;

    let digest_algo = match &sig_algo {
        SignatureAlgorithmIdentifier::RsaPss(params) => params.hash_algorithm.clone(),
        _ => bail!("Unsupported signature algorithm for certificate verification (only RSA-PSS currently supported)"),
    };

    let message_hash = digest_algo.hash_bytes(&tbs_der);

    // ── 3. Verify with issuer's RSA key ────────────────────────────────────
    let rsa_key = RSAPublicKey::<Uint2048>::try_from(issuer_spki)?;

    let sig_bytes = cert
        .signature
        .as_bytes()
        .ok_or_else(|| anyhow::anyhow!("Certificate signature is not a bit string"))?;

    let sig_elem = rsa_key.ring.from(Uint2048::from_be_slice(sig_bytes));
    let msg_elem = rsa_key.ring.from(Uint2048::from_be_slice(&message_hash));

    rsa_key.verify(msg_elem, sig_elem, &sig_algo)?;

    Ok(())
}

/// Extract the first certificate from an EF.SOD as an `x509_cert::Certificate`.
pub fn ds_cert_from_sod(
    sod: &crate::asn1::emrtd::EfSod,
) -> Result<x509_cert::Certificate> {
    use cms::cert::CertificateChoices;
    let certs = sod
        .signed_data()
        .certificates
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("No certificates in SignedData"))?;
    match certs.0.iter().next() {
        Some(CertificateChoices::Certificate(c)) => Ok(c.clone()),
        _ => bail!("No usable certificate in SignedData"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ds_cert_extraction() -> anyhow::Result<()> {
        let sod_bytes = std::fs::read("tests/dataset/EF_SOD.bin")?;
        let sod = crate::asn1::emrtd::EfSod::from_der(&sod_bytes)?;
        let ds = ds_cert_from_sod(&sod)?;

        println!("DS Subject:  {}", ds.tbs_certificate.subject);
        println!("DS Issuer:   {}", ds.tbs_certificate.issuer);

        assert!(!ds.tbs_certificate.subject.to_string().is_empty());
        Ok(())
    }
}
