//! Signature verification for EF.SOD.

use {
    crate::{
        asn1::{
            emrtd::EfSod,
            public_key_info::SubjectPublicKeyInfo,
            DigestAlgorithmIdentifier,
            SignatureAlgorithmIdentifier,
        },
        crypto::{mod_ring::RingRefExt, rsa::RSAPublicKey},
    },
    anyhow::{bail, Result},
    cms::cert::CertificateChoices,
    der::{Decode, Encode},
    ruint::Uint,
};

type Uint2048 = Uint<2048, 32>;

impl EfSod {
    /// Verify the RSA-PSS signature of the SOD against the DS certificate
    /// embedded in the SignedData structure.
    ///
    /// Implements ICAO 9303 Part 11 Passive Authentication step 1:
    /// verify the Document Signer certificate signed the LdsSecurityObject.
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

        // ── 3. Build RSA public key from SPKI ─────────────────────────────
        let spki_der = cert.tbs_certificate.subject_public_key_info.to_der()?;
        let spki = SubjectPublicKeyInfo::from_der(&spki_der)?;
        let rsa_key = RSAPublicKey::<Uint2048>::try_from(spki)?;

        // ── 4. Build Montgomery ring elements ─────────────────────────────
        let sig_elem =
            rsa_key.ring.from(Uint2048::from_be_slice(signer.signature.as_bytes()));
        let msg_elem = rsa_key.ring.from(Uint2048::from_be_slice(&message_hash));

        // ── 5. Verify ─────────────────────────────────────────────────────
        let sig_algo =
            SignatureAlgorithmIdentifier::from_der(&signer.signature_algorithm.to_der()?)?;
        rsa_key.verify(msg_elem, sig_elem, &sig_algo)?;

        Ok(())
    }
}
