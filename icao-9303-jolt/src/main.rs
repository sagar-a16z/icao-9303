use guest::{pack_preparsed_passport, PassportData, DISCLOSE_DOB, DISCLOSE_EXPIRY, DISCLOSE_NATIONALITY, DISCLOSE_SEX};
use jolt_sdk::PrivateInput;
use std::time::Instant;
use tracing::info;

pub fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let mask: u8 = DISCLOSE_NATIONALITY | DISCLOSE_DOB | DISCLOSE_SEX | DISCLOSE_EXPIRY;

    // ── Load passport data from disk ─────────────────────────────────────
    let sod = std::fs::read("../tests/dataset-synth/EF_SOD.bin").expect("EF_SOD.bin");
    let dg1 = std::fs::read("../tests/dataset/Datagroup1.bin").expect("Datagroup1.bin");
    let dg2 = std::fs::read("../tests/dataset/Datagroup2.bin").expect("Datagroup2.bin");
    let dg3 = std::fs::read("../tests/dataset/Datagroup3.bin").expect("Datagroup3.bin");
    let dg4 = std::fs::read("../tests/dataset/Datagroup4.bin").expect("Datagroup4.bin");
    let dg14 = std::fs::read("../tests/dataset/Datagroup14.bin").expect("Datagroup14.bin");
    let csca = std::fs::read("../tests/dataset-synth/CSCA.cer").expect("CSCA.cer");

    let variant = std::env::args().nth(1).unwrap_or_else(|| "packed".into());

    match variant.as_str() {
        "packed" => run_packed(mask, &sod, &dg1, &dg2, &dg3, &dg4, &dg14, &csca),
        "struct" => run_struct(mask, &sod, &dg1, &dg2, &dg3, &dg4, &dg14, &csca),
        "analyze" => {
            info!("═══ PACKED (pre-parsed) ═══");
            analyze_packed(mask, &sod, &dg1, &dg2, &dg3, &dg4, &dg14, &csca);
            info!("");
            info!("═══ STRUCT (baseline) ═══");
            analyze_struct(mask, &sod, &dg1, &dg2, &dg3, &dg4, &dg14, &csca);
        }
        other => panic!("Unknown variant '{other}'. Use: packed, struct, or analyze"),
    }
}

fn analyze_packed(mask: u8, sod: &[u8], dg1: &[u8], dg2: &[u8], dg3: &[u8], dg4: &[u8], dg14: &[u8], csca: &[u8]) {
    let (buf, dgs) = pack_preparsed_passport(sod, dg1, dg2, dg3, dg4, dg14, csca);
    info!("Pre-parsed buffer: {} bytes (+ DGs as separate struct)", buf.len());
    let summary = guest::analyze_verify_passport_packed(mask, PrivateInput::new(buf), PrivateInput::new(dgs));
    summary.write_to_file("summary-packed.txt".into()).expect("write");
    info!("Written to summary-packed.txt");
}

fn analyze_struct(mask: u8, sod: &[u8], dg1: &[u8], dg2: &[u8], dg3: &[u8], dg4: &[u8], dg14: &[u8], csca: &[u8]) {
    let passport = make_passport(sod, dg1, dg2, dg3, dg4, dg14, csca);
    let summary = guest::analyze_verify_passport_struct(mask, PrivateInput::new(passport));
    summary.write_to_file("summary-struct.txt".into()).expect("write");
    info!("Written to summary-struct.txt");
}

fn run_packed(mask: u8, sod: &[u8], dg1: &[u8], dg2: &[u8], dg3: &[u8], dg4: &[u8], dg14: &[u8], csca: &[u8]) {
    let (buf, dgs) = pack_preparsed_passport(sod, dg1, dg2, dg3, dg4, dg14, csca);
    info!("Pre-parsed buffer: {} bytes (+ DGs as separate struct)", buf.len());

    let target_dir = "/tmp/jolt-guest-targets";
    let mut program = guest::compile_verify_passport_packed(target_dir);
    let shared = guest::preprocess_shared_verify_passport_packed(&mut program);
    let prover_prep = guest::preprocess_prover_verify_passport_packed(shared.clone());
    let blindfold_setup = prover_prep.blindfold_setup();
    let verifier_prep = guest::preprocess_verifier_verify_passport_packed(
        shared,
        prover_prep.generators.to_verifier_setup(),
        Some(blindfold_setup),
    );
    let prove = guest::build_prover_verify_passport_packed(program, prover_prep);
    let verify = guest::build_verifier_verify_passport_packed(verifier_prep);

    info!("Proving (packed, mask=0x{mask:02x})...");
    let t = Instant::now();
    let (output, proof, io) = prove(mask, PrivateInput::new(buf), PrivateInput::new(dgs));
    info!("Prover runtime: {:.2}s", t.elapsed().as_secs_f64());

    let is_valid = verify(mask, output.clone(), io.panic, proof);
    print_result(&output, is_valid, &io);
}

fn run_struct(mask: u8, sod: &[u8], dg1: &[u8], dg2: &[u8], dg3: &[u8], dg4: &[u8], dg14: &[u8], csca: &[u8]) {
    let passport = make_passport(sod, dg1, dg2, dg3, dg4, dg14, csca);

    let target_dir = "/tmp/jolt-guest-targets";
    let mut program = guest::compile_verify_passport_struct(target_dir);
    let shared = guest::preprocess_shared_verify_passport_struct(&mut program);
    let prover_prep = guest::preprocess_prover_verify_passport_struct(shared.clone());
    let blindfold_setup = prover_prep.blindfold_setup();
    let verifier_prep = guest::preprocess_verifier_verify_passport_struct(
        shared,
        prover_prep.generators.to_verifier_setup(),
        Some(blindfold_setup),
    );
    let prove = guest::build_prover_verify_passport_struct(program, prover_prep);
    let verify = guest::build_verifier_verify_passport_struct(verifier_prep);

    info!("Proving (struct, mask=0x{mask:02x})...");
    let t = Instant::now();
    let (output, proof, io) = prove(mask, PrivateInput::new(passport));
    info!("Prover runtime: {:.2}s", t.elapsed().as_secs_f64());

    let is_valid = verify(mask, output.clone(), io.panic, proof);
    print_result(&output, is_valid, &io);
}

fn make_passport(sod: &[u8], dg1: &[u8], dg2: &[u8], dg3: &[u8], dg4: &[u8], dg14: &[u8], csca: &[u8]) -> PassportData {
    PassportData {
        sod: sod.to_vec(),
        dg1: dg1.to_vec(),
        dg2: dg2.to_vec(),
        dg3: dg3.to_vec(),
        dg4: dg4.to_vec(),
        dg14: dg14.to_vec(),
        csca: csca.to_vec(),
    }
}

fn print_result(output: &guest::PassportProofOutput, is_valid: bool, io: &jolt_sdk::JoltDevice) {
    info!("Passport valid:        {}", output.valid);
    info!("Disclosed nationality: {}", std::str::from_utf8(&output.nationality).unwrap_or("N/A"));
    info!("Disclosed DOB:         {}", std::str::from_utf8(&output.date_of_birth).unwrap_or("N/A"));
    info!("Disclosed sex:         {}", if output.sex != 0 { output.sex as char } else { '-' });
    info!("Disclosed expiry:      {}", std::str::from_utf8(&output.expiry_date).unwrap_or("N/A"));
    info!("CSCA pubkey hash:      {}", hex::encode(output.csca_pubkey_hash));
    info!("Proof valid:           {is_valid}");
    assert!(!io.panic, "guest panicked");
    assert!(output.valid, "Passport verification failed");
    assert!(is_valid, "Jolt proof verification failed");
}
