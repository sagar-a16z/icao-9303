use guest::{PassportProofOutput, DISCLOSE_DOB, DISCLOSE_EXPIRY, DISCLOSE_NATIONALITY, DISCLOSE_SEX};
use std::time::Instant;
use tracing::info;

pub fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // Disclose nationality, DOB, sex, and expiry — but NOT name or document number
    let mask: u8 = DISCLOSE_NATIONALITY | DISCLOSE_DOB | DISCLOSE_SEX | DISCLOSE_EXPIRY;

    // ── 1. Trace / cycle-count analysis ──────────────────────────────────
    info!("Analyzing guest cycle count...");
    let summary = guest::analyze_verify_passport(mask);
    summary
        .write_to_file("summary.txt".into())
        .expect("failed to write summary");
    info!("Cycle analysis written to summary.txt");

    // ── 2. Compile & preprocess ──────────────────────────────────────────
    let target_dir = "/tmp/jolt-guest-targets";
    let mut program = guest::compile_verify_passport(target_dir);

    let shared = guest::preprocess_shared_verify_passport(&mut program);
    let prover_prep = guest::preprocess_prover_verify_passport(shared.clone());
    let verifier_prep = guest::preprocess_verifier_verify_passport(
        shared,
        prover_prep.generators.to_verifier_setup(),
    );

    let prove = guest::build_prover_verify_passport(program, prover_prep);
    let verify = guest::build_verifier_verify_passport(verifier_prep);

    // ── 3. Prove ─────────────────────────────────────────────────────────
    info!("Proving passport verification (mask=0x{mask:02x})...");
    let t = Instant::now();
    let (output, proof, io) = prove(mask);
    info!("Prover runtime: {:.2}s", t.elapsed().as_secs_f64());

    // ── 4. Verify ────────────────────────────────────────────────────────
    let is_valid = verify(mask, output.clone(), io.panic, proof);

    info!("Passport valid:        {}", output.valid);
    info!(
        "Disclosed nationality: {}",
        std::str::from_utf8(&output.nationality).unwrap_or("N/A")
    );
    info!(
        "Disclosed DOB:         {}",
        std::str::from_utf8(&output.date_of_birth).unwrap_or("N/A")
    );
    info!(
        "Disclosed sex:         {}",
        if output.sex != 0 { output.sex as char } else { '-' }
    );
    info!(
        "Disclosed expiry:      {}",
        std::str::from_utf8(&output.expiry_date).unwrap_or("N/A")
    );
    info!("Proof valid:           {is_valid}");

    assert!(!io.panic, "guest panicked");
    assert!(output.valid, "Passport verification failed");
    assert!(is_valid, "Jolt proof verification failed");
}
