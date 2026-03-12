//! X.509 certificate signature verification.
//!
//! Used for Passive Authentication step 3: verify the Document Signer
//! certificate (DS cert) was signed by a Country Signing CA (CSCA).

use {
    crate::{
        asn1::{
            public_key_info::SubjectPublicKeyInfo,
            DigestAlgorithmIdentifier, DigestAlgorithmParameters,
            SignatureAlgorithmIdentifier,
        },
        crypto::{ecdsa, mod_ring::RingRefExt, rsa::RSAPublicKey},
    },
    anyhow::{bail, Result},
    der::{Decode, Encode},
    ruint::Uint,
};

type Uint2048 = Uint<2048, 32>;
type Uint3072 = Uint<3072, 48>;
type Uint4096 = Uint<4096, 64>;

/// Verify that `cert` was signed by `issuer_cert`.
///
/// Implements the core of X.509 certificate path validation:
/// hash the TBS (to-be-signed) portion of `cert` and verify the
/// signature using the public key from `issuer_cert`.
///
/// Supports RSA-PSS with 2048, 3072, and 4096-bit keys.
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

    let sig_bytes = cert
        .signature
        .as_bytes()
        .ok_or_else(|| anyhow::anyhow!("Certificate signature is not a bit string"))?;

    match &sig_algo {
        SignatureAlgorithmIdentifier::RsaPss(params) => {
            let message_hash = params.hash_algorithm.hash_bytes(&tbs_der);
            let sig_bit_len = sig_bytes.len() * 8;
            match sig_bit_len {
                ..=2048 => verify_rsa_cert::<2048, 32>(issuer_spki, sig_bytes, &message_hash, &sig_algo),
                ..=3072 => verify_rsa_cert::<3072, 48>(issuer_spki, sig_bytes, &message_hash, &sig_algo),
                ..=4096 => verify_rsa_cert::<4096, 64>(issuer_spki, sig_bytes, &message_hash, &sig_algo),
                _ => bail!("RSA signature too large: {sig_bit_len} bits"),
            }
        }
        SignatureAlgorithmIdentifier::EcdsaSha256 => {
            let digest = DigestAlgorithmIdentifier::Sha256(DigestAlgorithmParameters::Absent);
            verify_ecdsa_cert(issuer_spki, sig_bytes, &tbs_der, &digest)
        }
        SignatureAlgorithmIdentifier::EcdsaSha384 => {
            let digest = DigestAlgorithmIdentifier::Sha384(DigestAlgorithmParameters::Absent);
            verify_ecdsa_cert(issuer_spki, sig_bytes, &tbs_der, &digest)
        }
        SignatureAlgorithmIdentifier::EcdsaSha512 => {
            let digest = DigestAlgorithmIdentifier::Sha512(DigestAlgorithmParameters::Absent);
            verify_ecdsa_cert(issuer_spki, sig_bytes, &tbs_der, &digest)
        }
        _ => bail!("Unsupported signature algorithm for certificate verification"),
    }
}

fn verify_rsa_cert<const B: usize, const L: usize>(
    issuer_spki: SubjectPublicKeyInfo,
    sig_bytes: &[u8],
    message_hash: &[u8],
    sig_algo: &SignatureAlgorithmIdentifier,
) -> Result<()>
where
    Uint<B, L>: ruint::UintTryFrom<u64>,
{
    let rsa_key = RSAPublicKey::<Uint<B, L>>::try_from(issuer_spki)?;
    let sig_elem = rsa_key.ring.from(Uint::<B, L>::from_be_slice(sig_bytes));
    let msg_elem = rsa_key.ring.from(Uint::<B, L>::from_be_slice(message_hash));
    rsa_key.verify(msg_elem, sig_elem, sig_algo)?;
    Ok(())
}

fn verify_ecdsa_cert(
    issuer_spki: SubjectPublicKeyInfo,
    sig_bytes: &[u8],
    tbs_der: &[u8],
    digest: &DigestAlgorithmIdentifier,
) -> Result<()> {
    let pubkey_bytes = match issuer_spki {
        SubjectPublicKeyInfo::Ec(ec) => ec.point.as_bytes().to_vec(),
        _ => bail!("Expected EC public key for ECDSA signature verification"),
    };
    let message_hash = digest.hash_bytes(tbs_der);
    ecdsa::verify_ecdsa_p256(&message_hash, sig_bytes, &pubkey_bytes)
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

    /// MY dataset: full Passive Authentication steps 1 + 3.
    /// Step 1: SOD signature verification (DS cert signs LdsSecurityObject)
    /// Step 3: DS cert was signed by 3072-bit CSCA
    #[test]
    fn test_my_full_passive_auth() -> anyhow::Result<()> {
        let csca_der = std::fs::read("tests/dataset-my/CSCA.cer")?;
        let sod_bytes = std::fs::read("tests/dataset-my/EF_SOD.bin")?;

        // Step 1: verify SOD signature
        let sod = crate::asn1::emrtd::EfSod::from_der(&sod_bytes)?;
        sod.verify_signature()?;
        println!("Step 1 OK: SOD signature valid");

        // Step 3: verify DS cert chains to CSCA
        let csca = x509_cert::Certificate::from_der(&csca_der)?;
        let ds = ds_cert_from_sod(&sod)?;

        println!("CSCA: {}", csca.tbs_certificate.subject);
        println!("DS:   {}", ds.tbs_certificate.subject);

        verify_cert_signature(&ds, &csca)?;
        println!("Step 3 OK: DS cert signed by CSCA");

        Ok(())
    }

    /// Synthetic ECDSA P-256 dataset: full Passive Authentication steps 1 + 2 + 3.
    /// Uses BSI DG files with a synthetic ECDSA CSCA + DS + SOD.
    #[test]
    fn test_synthetic_ecdsa_full_passive_auth() -> anyhow::Result<()> {
        let csca_der = std::fs::read("tests/dataset-synth-ecdsa/CSCA.cer")?;
        let sod_bytes = std::fs::read("tests/dataset-synth-ecdsa/EF_SOD.bin")?;

        // Step 1: verify SOD signature (ECDSA-SHA256)
        let sod = crate::asn1::emrtd::EfSod::from_der(&sod_bytes)?;
        sod.verify_signature()?;
        println!("Step 1 OK: SOD signature valid (ECDSA-SHA256)");

        // Step 2: verify DG hashes match SOD commitments
        let dg1 = std::fs::read("tests/dataset/Datagroup1.bin")?;
        let dg2 = std::fs::read("tests/dataset/Datagroup2.bin")?;
        let dg3 = std::fs::read("tests/dataset/Datagroup3.bin")?;
        let dg4 = std::fs::read("tests/dataset/Datagroup4.bin")?;
        let dg14 = std::fs::read("tests/dataset/Datagroup14.bin")?;
        sod.verify_dg_hashes(&[
            (1, &dg1), (2, &dg2), (3, &dg3), (4, &dg4), (14, &dg14),
        ])?;
        println!("Step 2 OK: DG hashes match SOD commitments");

        // Step 3: verify DS cert chains to CSCA (ECDSA-SHA256)
        let csca = x509_cert::Certificate::from_der(&csca_der)?;
        let ds = ds_cert_from_sod(&sod)?;

        println!("CSCA: {}", csca.tbs_certificate.subject);
        println!("DS:   {}", ds.tbs_certificate.subject);

        verify_cert_signature(&ds, &csca)?;
        println!("Step 3 OK: DS cert signed by CSCA (ECDSA-SHA256)");

        Ok(())
    }

    /// Synthetic dataset: full Passive Authentication steps 1 + 2 + 3.
    /// Uses BSI DG files with a synthetic CSCA + DS + SOD.
    #[test]
    fn test_synthetic_full_passive_auth() -> anyhow::Result<()> {
        let csca_der = std::fs::read("tests/dataset-synth/CSCA.cer")?;
        let sod_bytes = std::fs::read("tests/dataset-synth/EF_SOD.bin")?;

        // Step 1: verify SOD signature (DS cert signs LdsSecurityObject)
        let sod = crate::asn1::emrtd::EfSod::from_der(&sod_bytes)?;
        sod.verify_signature()?;
        println!("Step 1 OK: SOD signature valid");

        // Step 2: verify DG hashes match SOD commitments
        let dg1 = std::fs::read("tests/dataset/Datagroup1.bin")?;
        let dg2 = std::fs::read("tests/dataset/Datagroup2.bin")?;
        let dg3 = std::fs::read("tests/dataset/Datagroup3.bin")?;
        let dg4 = std::fs::read("tests/dataset/Datagroup4.bin")?;
        let dg14 = std::fs::read("tests/dataset/Datagroup14.bin")?;
        sod.verify_dg_hashes(&[
            (1, &dg1), (2, &dg2), (3, &dg3), (4, &dg4), (14, &dg14),
        ])?;
        println!("Step 2 OK: DG hashes match SOD commitments");

        // Step 3: verify DS cert chains to CSCA
        let csca = x509_cert::Certificate::from_der(&csca_der)?;
        let ds = ds_cert_from_sod(&sod)?;

        println!("CSCA: {}", csca.tbs_certificate.subject);
        println!("DS:   {}", ds.tbs_certificate.subject);

        verify_cert_signature(&ds, &csca)?;
        println!("Step 3 OK: DS cert signed by CSCA");

        Ok(())
    }
}
