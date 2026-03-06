mod dataset;

use {anyhow::Result, dataset::Dataset, der::Decode, icao_9303::asn1::emrtd::EfSod};

#[test]
fn test_dg_hash_all() -> Result<()> {
    let d = Dataset::load()?;
    let sod = EfSod::from_der(&d.sod)?;
    let lso = sod.lds_security_object().map_err(|e| anyhow::anyhow!("{e}"))?;

    // The BSI test dataset SOD commits to DGs 1, 2, 3, 4, 14 (not DG15).
    lso.verify_dg_hashes(&[
        (1, d.dg1.as_slice()),
        (2, d.dg2.as_slice()),
        (3, d.dg3.as_slice()),
        (4, d.dg4.as_slice()),
        (14, d.dg14.as_slice()),
    ])?;

    Ok(())
}

#[test]
fn test_dg_hash_tamper_detection() -> Result<()> {
    let d = Dataset::load()?;
    let sod = EfSod::from_der(&d.sod)?;
    let lso = sod.lds_security_object().map_err(|e| anyhow::anyhow!("{e}"))?;

    let mut tampered = d.dg1.clone();
    tampered[10] ^= 0xFF; // flip a byte

    let result = lso.verify_dg_hashes(&[(1, tampered.as_slice())]);
    assert!(result.is_err(), "Tampered DG1 should fail hash verification");
    assert!(
        result.unwrap_err().to_string().contains("mismatch"),
        "Error should mention mismatch"
    );

    Ok(())
}
