//! Machine Readable Zone (MRZ) parsing from EF.DG1.
//!
//! Supports TD3 format (88-byte, 2-line × 44-char), used in all passports.
//! See ICAO 9303 Part 4.

use anyhow::{anyhow, ensure, Result};

/// Raw MRZ fields as fixed-size byte arrays.
/// Suitable for ZK guest contexts where String allocation is expensive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MrzRaw {
    pub document_type: [u8; 2],
    pub issuing_state: [u8; 3],
    pub nationality: [u8; 3],
    pub date_of_birth: [u8; 6],
    pub sex: u8,
    pub expiry_date: [u8; 6],
    pub document_number: [u8; 9],
}

impl MrzRaw {
    /// Parse from raw EF.DG1 bytes into fixed-size arrays.
    pub fn from_dg1(dg1: &[u8]) -> Result<Self> {
        ensure!(!dg1.is_empty() && dg1[0] == 0x61, "Invalid DG1 tag");
        let (outer_len, outer_skip) = parse_length(dg1, 1)?;
        let content = &dg1[1 + outer_skip..1 + outer_skip + outer_len];
        ensure!(content.len() >= 2 && content[0] == 0x5F && content[1] == 0x1F, "Expected 0x5F1F");
        let (mrz_len, mrz_skip) = parse_length(content, 2)?;
        Self::from_td3_bytes(&content[2 + mrz_skip..2 + mrz_skip + mrz_len])
    }

    /// Parse from raw 88-byte TD3 MRZ data.
    pub fn from_td3_bytes(mrz: &[u8]) -> Result<Self> {
        ensure!(mrz.len() == 88, "TD3 MRZ must be 88 bytes, got {}", mrz.len());
        let mut document_type = [0u8; 2];
        document_type.copy_from_slice(&mrz[0..2]);
        let mut issuing_state = [0u8; 3];
        issuing_state.copy_from_slice(&mrz[2..5]);
        let mut document_number = [0u8; 9];
        document_number.copy_from_slice(&mrz[44..53]);
        let mut nationality = [0u8; 3];
        nationality.copy_from_slice(&mrz[54..57]);
        let mut date_of_birth = [0u8; 6];
        date_of_birth.copy_from_slice(&mrz[57..63]);
        let sex = mrz[64];
        let mut expiry_date = [0u8; 6];
        expiry_date.copy_from_slice(&mrz[65..71]);
        Ok(Self { document_type, issuing_state, nationality, date_of_birth, sex, expiry_date, document_number })
    }
}

/// Parsed TD3 Machine Readable Zone from EF.DG1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mrz {
    /// Document type (e.g. "P" for passport, "P<" when secondary type absent)
    pub document_type: String,
    /// 3-character issuing state code (ICAO 9303 Part 3)
    pub issuing_state: String,
    /// Surname
    pub surname: String,
    /// Given names
    pub given_names: Vec<String>,
    /// Document number (up to 9 chars, trailing filler stripped)
    pub document_number: String,
    /// 3-character nationality code
    pub nationality: String,
    /// Date of birth in YYMMDD format
    pub date_of_birth: String,
    /// Sex: 'M', 'F', or '<' (unspecified)
    pub sex: char,
    /// Expiry date in YYMMDD format
    pub expiry_date: String,
    /// Personal number (optional, trailing filler stripped)
    pub personal_number: String,
}

impl Mrz {
    /// Parse MRZ from raw EF.DG1 bytes.
    ///
    /// DG1 is TLV-wrapped: tag 0x61 → tag 0x5F1F → 88 raw MRZ bytes.
    pub fn from_dg1(dg1: &[u8]) -> Result<Self> {
        ensure!(!dg1.is_empty(), "DG1 data is empty");
        ensure!(
            dg1[0] == 0x61,
            "Invalid DG1 application tag: expected 0x61, got 0x{:02x}",
            dg1[0]
        );

        // Parse outer length (short-form only for now)
        let (outer_len, outer_skip) = parse_length(dg1, 1)?;
        let content = &dg1[1 + outer_skip..1 + outer_skip + outer_len];

        // Expect 0x5F 0x1F tag
        ensure!(
            content.len() >= 2 && content[0] == 0x5F && content[1] == 0x1F,
            "Expected MRZ tag 0x5F1F"
        );
        let (mrz_len, mrz_skip) = parse_length(content, 2)?;
        let mrz_bytes = &content[2 + mrz_skip..2 + mrz_skip + mrz_len];

        Self::from_td3_bytes(mrz_bytes)
    }

    /// Parse from raw 88-byte TD3 MRZ data.
    ///
    /// Layout:
    /// - Line 1 (bytes 0–43): type(2) + issuing_state(3) + primary_id(39)
    /// - Line 2 (bytes 44–87): doc_num(9) + chk(1) + nationality(3) +
    ///   dob(6) + chk(1) + sex(1) + expiry(6) + chk(1) + personal(14) +
    ///   chk(1) + composite_chk(1)
    pub fn from_td3_bytes(mrz: &[u8]) -> Result<Self> {
        ensure!(
            mrz.len() == 88,
            "TD3 MRZ must be exactly 88 bytes, got {}",
            mrz.len()
        );
        let s = std::str::from_utf8(mrz).map_err(|e| anyhow!("MRZ not UTF-8: {e}"))?;

        let document_type = s[0..2].trim_end_matches('<').to_string();
        let issuing_state = s[2..5].to_string();

        // Primary identifier: surname << given_names (each given name separated by <)
        let primary = &s[5..44];
        let (surname_raw, given_raw) = primary.split_once("<<").unwrap_or((primary, ""));
        let surname = surname_raw.trim_end_matches('<').to_string();
        let given_names = given_raw
            .split('<')
            .filter(|n| !n.is_empty())
            .map(|n| n.to_string())
            .collect();

        let document_number = s[44..53].trim_end_matches('<').to_string();
        // byte 53: doc number check digit (skip)
        let nationality = s[54..57].to_string();
        let date_of_birth = s[57..63].to_string();
        // byte 63: dob check digit (skip)
        let sex = s.chars().nth(64).ok_or_else(|| anyhow!("MRZ too short for sex"))?;
        let expiry_date = s[65..71].to_string();
        // byte 71: expiry check digit (skip)
        let personal_number = s[72..86].trim_end_matches('<').to_string();
        // bytes 86-87: personal number check digit + composite check digit (skip)

        Ok(Self {
            document_type,
            issuing_state,
            surname,
            given_names,
            document_number,
            nationality,
            date_of_birth,
            sex,
            expiry_date,
            personal_number,
        })
    }
}

/// Parse BER/DER short-form or long-form length starting at `buf[offset]`.
/// Returns `(length_value, bytes_consumed)`.
fn parse_length(buf: &[u8], offset: usize) -> Result<(usize, usize)> {
    ensure!(buf.len() > offset, "Buffer too short for length byte");
    let b = buf[offset];
    if b & 0x80 == 0 {
        Ok((b as usize, 1))
    } else {
        let n = (b & 0x7f) as usize;
        ensure!(buf.len() >= offset + 1 + n, "Buffer too short for long-form length");
        let mut val = 0usize;
        for &byte in &buf[offset + 1..offset + 1 + n] {
            val = (val << 8) | byte as usize;
        }
        Ok((val, 1 + n))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_bsi_dg1() -> Result<()> {
        let dg1 = std::fs::read("tests/dataset/Datagroup1.bin")?;
        let mrz = Mrz::from_dg1(&dg1)?;

        assert_eq!(mrz.document_type, "P");
        assert_eq!(mrz.issuing_state, "D<<");
        assert_eq!(mrz.surname, "MUSTERMANN");
        assert_eq!(mrz.given_names, vec!["ERIKA"]);
        assert_eq!(mrz.document_number, "C11T002JM");
        assert_eq!(mrz.date_of_birth, "960812");
        assert_eq!(mrz.sex, 'F');
        assert_eq!(mrz.expiry_date, "231031");

        Ok(())
    }

    #[test]
    fn test_parse_td3_direct() -> Result<()> {
        let mrz_bytes =
            b"P<D<<MUSTERMANN<<ERIKA<<<<<<<<<<<<<<<<<<<<<<C11T002JM4D<<9608122F2310314<<<<<<<<<<<<<<<4";
        let mrz = Mrz::from_td3_bytes(mrz_bytes)?;

        assert_eq!(mrz.surname, "MUSTERMANN");
        assert_eq!(mrz.given_names, vec!["ERIKA"]);
        assert_eq!(mrz.document_number, "C11T002JM");
        assert_eq!(mrz.sex, 'F');

        Ok(())
    }
}
