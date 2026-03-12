//! Signature verification for EF.SOD.

use {
    crate::{
        asn1::{
            emrtd::EfSod,
            public_key_info::SubjectPublicKeyInfo,
            DigestAlgorithmIdentifier,
            SignatureAlgorithmIdentifier,
        },
        crypto::{ecdsa, mod_ring::RingRefExt, rsa::RSAPublicKey},
    },
    anyhow::{bail, Result},
    cms::cert::CertificateChoices,
    der::{Decode, Encode},
    ruint::Uint,
};

type Uint2048 = Uint<2048, 32>;

impl EfSod {
    /// Verify the signature of the SOD against the DS certificate
    /// embedded in the SignedData structure.
    ///
    /// Implements ICAO 9303 Part 11 Passive Authentication step 1:
    /// verify the Document Signer certificate signed the LdsSecurityObject.
    ///
    /// Supports RSA-PSS (2048-bit) and ECDSA (P-256) signatures.
    pub fn verify_signature(&self) -> Result<()> {
        let signer = self.signer_info();

        // ── 1. Digest algorithm and message hash ───────────────────────────
        // Per RFC 5652 §5.4: when signedAttrs are present (always in ICAO
        // passports), the signature covers DER(signedAttrs SET), not eContent.
        let digest = DigestAlgorithmIdentifier::from_der(&signer.digest_alg.to_der()?)?;
        let message_hash = if let Some(signed_attrs) = &signer.signed_attrs {
            digest.hash_bytes(&signed_attrs.to_der()?)
        } else {
            digest.hash_der(self.encapsulated_content())
        };

        // ── 2. Extract DS certificate ──────────────────────────────────────
        let certs = self
            .signed_data()
            .certificates
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No certificates in SignedData"))?;
        let cert = match certs.0.iter().next() {
            Some(CertificateChoices::Certificate(c)) => c,
            _ => bail!("No usable certificate found in SignedData"),
        };

        // ── 3. Determine signature algorithm and verify ────────────────────
        let spki_der = cert.tbs_certificate.subject_public_key_info.to_der()?;
        let spki = SubjectPublicKeyInfo::from_der(&spki_der)?;
        let sig_algo =
            SignatureAlgorithmIdentifier::from_der(&signer.signature_algorithm.to_der()?)?;

        match &sig_algo {
            SignatureAlgorithmIdentifier::RsaPss(_) => {
                let rsa_key = RSAPublicKey::<Uint2048>::try_from(spki)?;
                let sig_elem =
                    rsa_key.ring.from(Uint2048::from_be_slice(signer.signature.as_bytes()));
                let msg_elem = rsa_key.ring.from(Uint2048::from_be_slice(&message_hash));
                rsa_key.verify(msg_elem, sig_elem, &sig_algo)?;
            }
            SignatureAlgorithmIdentifier::EcdsaSha256
            | SignatureAlgorithmIdentifier::EcdsaSha384
            | SignatureAlgorithmIdentifier::EcdsaSha512 => {
                let pubkey_bytes = match spki {
                    SubjectPublicKeyInfo::Ec(ec) => ec.point.as_bytes().to_vec(),
                    _ => bail!("Expected EC public key for ECDSA SOD signature"),
                };
                ecdsa::verify_ecdsa_p256(
                    &message_hash,
                    signer.signature.as_bytes(),
                    &pubkey_bytes,
                )?;
            }
            _ => bail!("Unsupported SOD signature algorithm: {:?}", sig_algo),
        }

        Ok(())
    }
}
