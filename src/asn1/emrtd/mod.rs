pub mod mrz;
pub mod security_info;

use {
    self::security_info::{
        ChipAuthenticationInfo, ChipAuthenticationPublicKeyInfo, SecurityInfo, SecurityInfos,
    },
    super::{ApplicationTagged, ContentInfo, ContentType, DigestAlgorithmIdentifier},
    crate::ensure_err,
    cms::signed_data::{EncapsulatedContentInfo, SignedData, SignerInfo},
    der::{
        asn1::{ObjectIdentifier as Oid, OctetString, PrintableString},
        Decode, Error, ErrorKind, Length, Result, Sequence, Tag,
    },
    security_info::{ChipAuthenticationProtocol, KeyAgreement, SymmetricCipher},
};

/// EF_CardAccess is a [`SecurityInfos`] with no further wrapping.
///
/// See ICAO-9303-10 3.11.3
pub type EfCardAccess = SecurityInfos;

/// EF_DG14 is a [`SecurityInfos`] with no further wrapping.
///
/// See ICAO-9303-10 3.11.4
pub type EfDg14 = ApplicationTagged<14, SecurityInfos>;

/// EF_SOD is a wrapped [`SignedData`] structure.
///
/// See ICAO-9303-10 4.7.14. The 0x6E tag is an ASN1 Application
/// constructed application tag with the value 14.
pub type EfSod = ApplicationTagged<23, ContentInfo<SignedData>>;

/// ICAO-9303-10 4.6.2.3
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
pub struct LdsSecurityObject {
    pub version:                u64,
    pub hash_algorithm:         DigestAlgorithmIdentifier,
    pub data_group_hash_values: Vec<DataGroupHash>,
    pub lds_version_info:       Option<LdsVersionInfo>,
}

/// ICAO-9303-10 4.6.2.3
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
pub struct LdsVersionInfo {
    pub lds_version:     PrintableString,
    pub unicode_version: PrintableString,
}

/// ICAO-9303-10 4.6.2.3
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
pub struct DataGroupHash {
    pub data_group_number: u64,
    pub hash_value:        OctetString,
}

impl ContentType for LdsSecurityObject {
    /// ICAO-9303-10 4.6.2.3
    const CONTENT_TYPE: Oid = Oid::new_unwrap("2.23.136.1.1.1");
}

/// EF.COM — lists the data groups present on the chip.
///
/// Simple nested TLV (not DER Sequence):
/// `0x60 { 0x5F01 <lds_ver>, 0x5F36 <unicode_ver>, 0x5C <dg_tags> }`
///
/// See ICAO 9303-10 §4.7.2.
pub struct EfCom {
    pub lds_version:     String,
    pub unicode_version: String,
    /// Raw DG tag bytes present (0x61=DG1, 0x75=DG2, 0x63=DG3, …)
    pub data_groups: Vec<u8>,
}

impl EfCom {
    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        anyhow::ensure!(!bytes.is_empty() && bytes[0] == 0x60, "Expected tag 0x60");
        let (outer_len, skip) = Self::parse_len(bytes, 1)?;
        let content = &bytes[1 + skip..1 + skip + outer_len];

        let mut pos = 0;
        let mut lds_version = String::new();
        let mut unicode_version = String::new();
        let mut data_groups = Vec::new();

        while pos < content.len() {
            let (tag, tag_len) = if content[pos] == 0x5F {
                anyhow::ensure!(pos + 1 < content.len(), "Truncated 2-byte tag");
                (((content[pos] as u16) << 8) | content[pos + 1] as u16, 2)
            } else {
                (content[pos] as u16, 1)
            };
            pos += tag_len;
            let (vlen, lskip) = Self::parse_len(content, pos)?;
            pos += lskip;
            let value = &content[pos..pos + vlen];
            pos += vlen;
            match tag {
                0x5F01 => lds_version = std::str::from_utf8(value).unwrap_or("").to_string(),
                0x5F36 => unicode_version = std::str::from_utf8(value).unwrap_or("").to_string(),
                0x5C => data_groups = value.to_vec(),
                _ => {}
            }
        }
        Ok(Self { lds_version, unicode_version, data_groups })
    }

    /// Returns true if the given raw DG tag byte is listed as present.
    pub fn contains_dg(&self, dg_tag: u8) -> bool {
        self.data_groups.contains(&dg_tag)
    }

    fn parse_len(buf: &[u8], offset: usize) -> anyhow::Result<(usize, usize)> {
        anyhow::ensure!(buf.len() > offset, "Buffer too short for length");
        let b = buf[offset];
        if b & 0x80 == 0 {
            Ok((b as usize, 1))
        } else {
            let n = (b & 0x7f) as usize;
            anyhow::ensure!(
                buf.len() >= offset + 1 + n,
                "Buffer too short for long-form length"
            );
            let mut val = 0usize;
            for &byte in &buf[offset + 1..offset + 1 + n] {
                val = (val << 8) | byte as usize;
            }
            Ok((val, 1 + n))
        }
    }
}

impl EfDg14 {
    pub fn chip_authentication(
        &self,
    ) -> Option<(&ChipAuthenticationInfo, &ChipAuthenticationPublicKeyInfo)> {
        // For now, we take the first ChipAuthentication and
        // ChipAuthenticationPublicKey.
        let ca = self
            .0
            .iter()
            .find_map(|si| match si {
                SecurityInfo::ChipAuthentication(ca) => Some(ca),
                _ => None,
            })
            .unwrap_or(
                // Some passports only have ChipAuthenticationPublicKey. In this case we assume
                // that the Cipher is the 3DES-CBC-CBC.
                &ChipAuthenticationInfo {
                    protocol: ChipAuthenticationProtocol {
                        key_agreement: KeyAgreement::Ecdh, // TODO: From pubkey
                        cipher:        Some(SymmetricCipher::Tdes),
                    },
                    version:  1,
                    key_id:   None,
                },
            );
        // Do some verification checks
        if ca.protocol.cipher.is_none() || ca.version != 1 {
            // TODO: Error message
            return None;
        }
        // Find the corresponding ChipAuthenticationPublicKey based on key id (could
        // both be None)
        let capk = self.0.iter().find_map(|si| match si {
            SecurityInfo::ChipAuthenticationPublicKey(capk) if capk.key_id == ca.key_id => {
                Some(capk)
            }
            _ => None,
        })?;
        Some((ca, capk))
    }
}

impl EfSod {
    pub fn signed_data(&self) -> &SignedData {
        &self.0 .0
    }

    pub fn signer_info(&self) -> &SignerInfo {
        // TODO: Handle errors
        self.signed_data()
            .signer_infos
            .0
            .as_slice()
            .first()
            .expect("missing signer info")
    }

    pub fn signature(&self) -> &[u8] {
        self.signer_info().signature.as_bytes()
    }

    /// Returns the Blake3 hash of the document signature
    pub fn document_hash(&self) -> [u8; 32] {
        *blake3::hash(self.signature()).as_bytes()
    }

    pub fn encapsulated_content(&self) -> &EncapsulatedContentInfo {
        &self.signed_data().encap_content_info
    }

    pub fn lds_security_object(&self) -> Result<LdsSecurityObject> {
        let econ = self.encapsulated_content();
        ensure_err!(
            econ.econtent_type == LdsSecurityObject::CONTENT_TYPE,
            Error::new(
                ErrorKind::OidUnknown {
                    oid: econ.econtent_type,
                },
                Length::ZERO,
            )
        );
        let octet_string = econ
            .econtent
            .as_ref()
            .ok_or(Error::new(
                ErrorKind::TagUnexpected {
                    expected: Some(Tag::OctetString),
                    actual:   Tag::Null, // Actually None
                },
                Length::ZERO,
            ))?
            .decode_as::<OctetString>()?;
        LdsSecurityObject::from_der(octet_string.as_bytes())
    }

    /// Convenience: verify data group hashes via the embedded LdsSecurityObject.
    pub fn verify_dg_hashes(&self, dgs: &[(usize, &[u8])]) -> anyhow::Result<()> {
        self.lds_security_object()
            .map_err(|e| anyhow::anyhow!("{e}"))?
            .verify_dg_hashes(dgs)
    }
}

impl LdsSecurityObject {
    pub fn hash_for_dg(&self, dg_number: usize) -> Option<&[u8]> {
        for entry in &self.data_group_hash_values {
            if entry.data_group_number == dg_number as u64 {
                return Some(entry.hash_value.as_bytes());
            }
        }
        None
    }

    /// Verify that each provided data group hashes to its committed value.
    ///
    /// `dgs` is a slice of `(dg_number, raw_bytes)` pairs. Returns `Ok(())`
    /// if every DG matches; errors on the first mismatch or missing commitment.
    pub fn verify_dg_hashes(&self, dgs: &[(usize, &[u8])]) -> anyhow::Result<()> {
        for (dg_number, bytes) in dgs {
            let committed = self.hash_for_dg(*dg_number).ok_or_else(|| {
                anyhow::anyhow!("No committed hash for DG {dg_number}")
            })?;
            let computed = self.hash_algorithm.hash_bytes(bytes);
            anyhow::ensure!(
                committed == computed.as_slice(),
                "DG {dg_number} hash mismatch: expected {} got {}",
                hex::encode(committed),
                hex::encode(&computed)
            );
        }
        Ok(())
    }
}
