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

    // ── Load ECDSA dataset (for ecdsa variants) ──────────────────────────
    let sod_ecdsa = std::fs::read("../tests/dataset-synth-ecdsa/EF_SOD.bin").ok();
    let csca_ecdsa = std::fs::read("../tests/dataset-synth-ecdsa/CSCA.cer").ok();

    let variant = std::env::args().nth(1).unwrap_or_else(|| "packed".into());

    match variant.as_str() {
        "packed" => run_packed(mask, &sod, &dg1, &dg2, &dg3, &dg4, &dg14, &csca),
        "struct" => run_struct(mask, &sod, &dg1, &dg2, &dg3, &dg4, &dg14, &csca),
        "age" => run_age_check(&sod, &dg1, &csca),
        "nationality" => run_nationality_check(&sod, &dg1, &csca),
        "age-ecdsa" => {
            let sod_ec = sod_ecdsa.as_ref().expect("Run tests/gen-synthetic-dataset-ecdsa.sh first");
            let csca_ec = csca_ecdsa.as_ref().expect("Run tests/gen-synthetic-dataset-ecdsa.sh first");
            run_age_check_ecdsa(sod_ec, &dg1, csca_ec);
        }
        "nationality-ecdsa" => {
            let sod_ec = sod_ecdsa.as_ref().expect("Run tests/gen-synthetic-dataset-ecdsa.sh first");
            let csca_ec = csca_ecdsa.as_ref().expect("Run tests/gen-synthetic-dataset-ecdsa.sh first");
            run_nationality_check_ecdsa(sod_ec, &dg1, csca_ec);
        }
        "analyze" => {
            info!("═══ PACKED (pre-parsed) ═══");
            analyze_packed(mask, &sod, &dg1, &dg2, &dg3, &dg4, &dg14, &csca);
            info!("");
            info!("═══ STRUCT (baseline) ═══");
            analyze_struct(mask, &sod, &dg1, &dg2, &dg3, &dg4, &dg14, &csca);
            info!("");
            info!("═══ AGE CHECK ═══");
            analyze_age(&sod, &dg1, &csca);
            if let (Some(sod_ec), Some(csca_ec)) = (&sod_ecdsa, &csca_ecdsa) {
                info!("");
                info!("═══ AGE CHECK (ECDSA P-256) ═══");
                analyze_age_ecdsa(sod_ec, &dg1, csca_ec);
            }
        }
        other => panic!("Unknown variant '{other}'. Use: packed, struct, age, nationality, age-ecdsa, nationality-ecdsa, or analyze"),
    }
}

fn analyze_packed(mask: u8, sod: &[u8], dg1: &[u8], dg2: &[u8], dg3: &[u8], dg4: &[u8], dg14: &[u8], csca: &[u8]) {
    let (buf, dgs) = pack_preparsed_passport(sod, dg1, dg2, dg3, dg4, dg14, csca);
    info!("Pre-parsed buffer: {} bytes (+ DGs as separate struct)", buf.len());
    let summary = guest::analyze_verify_passport_packed(mask, PrivateInput::new(buf), PrivateInput::new(dgs));
    info!("TRACE LENGTH: {}", summary.trace_len());
    summary.write_to_file("summary-packed.txt".into()).expect("write");
    info!("Written to summary-packed.txt");
}

fn analyze_struct(mask: u8, sod: &[u8], dg1: &[u8], dg2: &[u8], dg3: &[u8], dg4: &[u8], dg14: &[u8], csca: &[u8]) {
    let passport = make_passport(sod, dg1, dg2, dg3, dg4, dg14, csca);
    let summary = guest::analyze_verify_passport_struct(mask, PrivateInput::new(passport));
    info!("TRACE LENGTH: {}", summary.trace_len());
    summary.write_to_file("summary-struct.txt".into()).expect("write");
    info!("Written to summary-struct.txt");
}

fn analyze_age(sod: &[u8], dg1: &[u8], csca: &[u8]) {
    let (buf, _) = pack_preparsed_passport(sod, dg1, &[], &[], &[], &[], csca);
    let current_date: [u8; 6] = *b"260312"; // 2026-03-12
    let summary = guest::analyze_check_age(
        18, current_date,
        PrivateInput::new(buf), PrivateInput::new(dg1.to_vec()),
    );
    info!("TRACE LENGTH: {}", summary.trace_len());
    summary.write_to_file("summary-age.txt".into()).expect("write");
    info!("Written to summary-age.txt");
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

fn run_age_check(sod: &[u8], dg1: &[u8], csca: &[u8]) {
    let (buf, _) = pack_preparsed_passport(sod, dg1, &[], &[], &[], &[], csca);
    let current_date: [u8; 6] = *b"260312"; // 2026-03-12
    let min_age: u8 = 18;

    let target_dir = "/tmp/jolt-guest-targets";
    let mut program = guest::compile_check_age(target_dir);
    let shared = guest::preprocess_shared_check_age(&mut program);
    let prover_prep = guest::preprocess_prover_check_age(shared.clone());
    let blindfold_setup = prover_prep.blindfold_setup();
    let verifier_prep = guest::preprocess_verifier_check_age(
        shared,
        prover_prep.generators.to_verifier_setup(),
        Some(blindfold_setup),
    );
    let prove = guest::build_prover_check_age(program, prover_prep);
    let verify = guest::build_verifier_check_age(verifier_prep);

    info!("Proving (age check, min_age={min_age}, date={})...", std::str::from_utf8(&current_date).unwrap());
    let t = Instant::now();
    let (output, proof, io) = prove(
        min_age, current_date,
        PrivateInput::new(buf), PrivateInput::new(dg1.to_vec()),
    );
    info!("Prover runtime: {:.2}s", t.elapsed().as_secs_f64());

    let is_valid = verify(min_age, current_date, output.clone(), io.panic, proof);
    info!("Chain valid:      {}", output.valid);
    info!("Age >= {min_age}:        {}", output.predicate);
    info!("CSCA pubkey hash: {}", hex::encode(output.csca_pubkey_hash));
    info!("Proof valid:      {is_valid}");
    assert!(!io.panic, "guest panicked");
    assert!(output.valid, "Passport verification failed");
    assert!(is_valid, "Jolt proof verification failed");
}

fn run_nationality_check(sod: &[u8], dg1: &[u8], csca: &[u8]) {
    let (buf, _) = pack_preparsed_passport(sod, dg1, &[], &[], &[], &[], csca);

    // Allowed nationalities: D<< (Germany — matches BSI test data)
    let mut allowed = [0u8; 30];
    allowed[0..3].copy_from_slice(b"D<<");
    let allowed_count: u8 = 1;

    let target_dir = "/tmp/jolt-guest-targets";
    let mut program = guest::compile_check_nationality(target_dir);
    let shared = guest::preprocess_shared_check_nationality(&mut program);
    let prover_prep = guest::preprocess_prover_check_nationality(shared.clone());
    let blindfold_setup = prover_prep.blindfold_setup();
    let verifier_prep = guest::preprocess_verifier_check_nationality(
        shared,
        prover_prep.generators.to_verifier_setup(),
        Some(blindfold_setup),
    );
    let prove = guest::build_prover_check_nationality(program, prover_prep);
    let verify = guest::build_verifier_check_nationality(verifier_prep);

    info!("Proving (nationality check, allowed=D<<)...");
    let t = Instant::now();
    let (output, proof, io) = prove(
        allowed, allowed_count,
        PrivateInput::new(buf), PrivateInput::new(dg1.to_vec()),
    );
    info!("Prover runtime: {:.2}s", t.elapsed().as_secs_f64());

    let is_valid = verify(allowed, allowed_count, output.clone(), io.panic, proof);
    info!("Chain valid:         {}", output.valid);
    info!("Nationality allowed: {}", output.predicate);
    info!("CSCA pubkey hash:    {}", hex::encode(output.csca_pubkey_hash));
    info!("Proof valid:         {is_valid}");
    assert!(!io.panic, "guest panicked");
    assert!(output.valid, "Passport verification failed");
    assert!(is_valid, "Jolt proof verification failed");
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

fn analyze_age_ecdsa(sod: &[u8], dg1: &[u8], csca: &[u8]) {
    let (buf, _) = pack_preparsed_passport(sod, dg1, &[], &[], &[], &[], csca);
    let current_date: [u8; 6] = *b"260312";
    let summary = guest::analyze_check_age_ecdsa(
        18, current_date,
        PrivateInput::new(buf), PrivateInput::new(dg1.to_vec()),
    );
    info!("TRACE LENGTH: {}", summary.trace_len());
    summary.write_to_file("summary-age-ecdsa.txt".into()).expect("write");
    info!("Written to summary-age-ecdsa.txt");
}

fn run_age_check_ecdsa(sod: &[u8], dg1: &[u8], csca: &[u8]) {
    let (buf, _) = pack_preparsed_passport(sod, dg1, &[], &[], &[], &[], csca);
    let current_date: [u8; 6] = *b"260312";
    let min_age: u8 = 18;

    let target_dir = "/tmp/jolt-guest-targets";
    let mut program = guest::compile_check_age_ecdsa(target_dir);
    let shared = guest::preprocess_shared_check_age_ecdsa(&mut program);
    let prover_prep = guest::preprocess_prover_check_age_ecdsa(shared.clone());
    let blindfold_setup = prover_prep.blindfold_setup();
    let verifier_prep = guest::preprocess_verifier_check_age_ecdsa(
        shared,
        prover_prep.generators.to_verifier_setup(),
        Some(blindfold_setup),
    );
    let prove = guest::build_prover_check_age_ecdsa(program, prover_prep);
    let verify = guest::build_verifier_check_age_ecdsa(verifier_prep);

    info!("Proving (ECDSA P-256 age check, min_age={min_age}, date={})...", std::str::from_utf8(&current_date).unwrap());
    let t = Instant::now();
    let (output, proof, io) = prove(
        min_age, current_date,
        PrivateInput::new(buf), PrivateInput::new(dg1.to_vec()),
    );
    info!("Prover runtime: {:.2}s", t.elapsed().as_secs_f64());

    let is_valid = verify(min_age, current_date, output.clone(), io.panic, proof);
    info!("Chain valid:      {}", output.valid);
    info!("Age >= {min_age}:        {}", output.predicate);
    info!("CSCA pubkey hash: {}", hex::encode(output.csca_pubkey_hash));
    info!("Proof valid:      {is_valid}");
    assert!(!io.panic, "guest panicked");
    assert!(output.valid, "Passport verification failed");
    assert!(is_valid, "Jolt proof verification failed");
}

fn run_nationality_check_ecdsa(sod: &[u8], dg1: &[u8], csca: &[u8]) {
    let (buf, _) = pack_preparsed_passport(sod, dg1, &[], &[], &[], &[], csca);

    let mut allowed = [0u8; 30];
    allowed[0..3].copy_from_slice(b"D<<");
    let allowed_count: u8 = 1;

    let target_dir = "/tmp/jolt-guest-targets";
    let mut program = guest::compile_check_nationality_ecdsa(target_dir);
    let shared = guest::preprocess_shared_check_nationality_ecdsa(&mut program);
    let prover_prep = guest::preprocess_prover_check_nationality_ecdsa(shared.clone());
    let blindfold_setup = prover_prep.blindfold_setup();
    let verifier_prep = guest::preprocess_verifier_check_nationality_ecdsa(
        shared,
        prover_prep.generators.to_verifier_setup(),
        Some(blindfold_setup),
    );
    let prove = guest::build_prover_check_nationality_ecdsa(program, prover_prep);
    let verify = guest::build_verifier_check_nationality_ecdsa(verifier_prep);

    info!("Proving (ECDSA P-256 nationality check, allowed=D<<)...");
    let t = Instant::now();
    let (output, proof, io) = prove(
        allowed, allowed_count,
        PrivateInput::new(buf), PrivateInput::new(dg1.to_vec()),
    );
    info!("Prover runtime: {:.2}s", t.elapsed().as_secs_f64());

    let is_valid = verify(allowed, allowed_count, output.clone(), io.panic, proof);
    info!("Chain valid:         {}", output.valid);
    info!("Nationality allowed: {}", output.predicate);
    info!("CSCA pubkey hash:    {}", hex::encode(output.csca_pubkey_hash));
    info!("Proof valid:         {is_valid}");
    assert!(!io.panic, "guest panicked");
    assert!(output.valid, "Passport verification failed");
    assert!(is_valid, "Jolt proof verification failed");
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
