use std::time::Instant;
use tracing::info;

pub fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // ── 1. Trace / cycle-count analysis ──────────────────────────────────
    info!("Analyzing guest cycle count...");
    let summary = guest::analyze_verify_sod();
    summary
        .write_to_file("summary.txt".into())
        .expect("failed to write summary");
    info!("Cycle analysis written to summary.txt");

    // ── 2. Compile & preprocess ──────────────────────────────────────────
    let target_dir = "/tmp/jolt-guest-targets";
    let mut program = guest::compile_verify_sod(target_dir);

    let shared = guest::preprocess_shared_verify_sod(&mut program);
    let prover_prep = guest::preprocess_prover_verify_sod(shared.clone());
    let verifier_prep = guest::preprocess_verifier_verify_sod(
        shared,
        prover_prep.generators.to_verifier_setup(),
    );

    let prove = guest::build_prover_verify_sod(program, prover_prep);
    let verify = guest::build_verifier_verify_sod(verifier_prep);

    // ── 3. Prove ─────────────────────────────────────────────────────────
    info!("Proving SOD signature verification...");
    let t = Instant::now();
    let (output, proof, io) = prove();
    info!("Prover runtime: {:.2}s", t.elapsed().as_secs_f64());

    // ── 4. Verify ────────────────────────────────────────────────────────
    let is_valid = verify(output, io.panic, proof);
    info!("SOD signature valid: {output}");
    info!("Proof valid:         {is_valid}");
    assert!(!io.panic, "guest panicked");
    assert!(output, "SOD signature verification returned false");
    assert!(is_valid, "Jolt proof verification failed");
}
