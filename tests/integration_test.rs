use std::fs;
use std::io::Write; // Added to allow writing to stdin
use std::process::{Command, ExitStatus, Stdio}; // Added Stdio
use std::sync::atomic::{AtomicUsize, Ordering};

static TEST_COUNTER: AtomicUsize = AtomicUsize::new(0);

fn get_unique_dir(test_name: &str) -> String {
    let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = format!("target/tmp_{}_{}", test_name, id);
    let _ = fs::create_dir_all(&dir);
    dir
}

fn run_tlpsign(args: &[&str]) -> (String, String, ExitStatus) {
    let bin_path = env!("CARGO_BIN_EXE_tlpsign");

    // Configure Stdio::piped() to prevent the command from hijacking the terminal's stdin
    let mut child = Command::new(bin_path)
        .args(args)
        .env("TLPSIGN_TEST_FAST_RSA", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to execute tlpsign");

    // Automatically feed "y\n" so if tlpsign triggers a confirmation prompt
    // (like warning about 99999 seconds), it proceeds automatically without hanging.
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(b"y\n");
    }

    let output = child.wait_with_output().expect("Failed to wait on child");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    (stdout, stderr, output.status)
}

fn extract_revocation_key(stdout: &str) -> String {
    for line in stdout.lines() {
        if line.starts_with("[OK] Revocation key: R=") {
            return line
                .trim_start_matches("[OK] Revocation key: R=")
                .to_string();
        }
    }
    panic!("Could not find revocation key in stdout:\n{}", stdout);
}

#[test]
fn test_nominal_workflow() {
    let dir = get_unique_dir("nominal");
    let doc_path = format!("{}/doc.txt", dir);
    let bundle_path = format!("{}/bundle.json", dir);

    fs::write(&doc_path, "Secret Document Content").unwrap();

    // 1. Sign
    let (stdout, _, status) = run_tlpsign(&[
        "sign",
        "--document",
        &doc_path,
        "--delay",
        "1s",
        "--multiplier",
        "1",
        "--output",
        &bundle_path,
    ]);
    assert!(status.success(), "Sign command failed");
    assert!(stdout.contains("[OK] Bundle created:"));

    // 2. Verify
    let (stdout, _, status) =
        run_tlpsign(&["verify", "--bundle", &bundle_path, "--document", &doc_path]);
    assert!(status.success(), "Verify command failed");
    assert!(stdout.contains("[OK] Signature valid. Document authenticated."));
}

#[test]
fn test_revocation_workflow() {
    let dir = get_unique_dir("revocation");
    let doc_path = format!("{}/doc.txt", dir);
    let bundle_path = format!("{}/bundle.json", dir);

    fs::write(&doc_path, "Secret Document Content").unwrap();

    // 1. Sign
    let (stdout, _, status) = run_tlpsign(&[
        "sign",
        "--document",
        &doc_path,
        "--delay",
        "1s",
        "--multiplier",
        "1",
        "--output",
        &bundle_path,
    ]);
    assert!(status.success(), "Sign command failed");

    let rev_key = extract_revocation_key(&stdout);

    // 2. Revoke
    let (stdout, _, status) = run_tlpsign(&[
        "revoke",
        "--bundle",
        &bundle_path,
        "--revocation-key",
        &rev_key,
    ]);
    assert!(status.success(), "Revoke command failed");
    assert!(stdout.contains("Revocation verified (R matches the commitment)"));

    // 3. Verify - should fail with REVOKED status (exit code 2 as per verify_cmd.rs)
    let (stdout, _, status) =
        run_tlpsign(&["verify", "--bundle", &bundle_path, "--document", &doc_path]);

    assert_eq!(
        status.code(),
        Some(2),
        "Expected exit code 2 for revoked bundle"
    );
    assert!(stdout.contains("[REVOKED]"), "Expected REVOKED message");
}

#[test]
fn test_tamper_resistance() {
    let dir = get_unique_dir("tamper");
    let doc_path = format!("{}/doc.txt", dir);
    let bundle_path = format!("{}/bundle.json", dir);

    fs::write(&doc_path, "Secret Document Content").unwrap();

    // 1. Sign
    let (stdout, _, status) = run_tlpsign(&[
        "sign",
        "--document",
        &doc_path,
        "--delay",
        "1s",
        "--multiplier",
        "1",
        "--output",
        &bundle_path,
    ]);
    assert!(status.success(), "Sign command failed");

    // Fixed Warning: Actually assert on the stdout instead of leaving it unused
    assert!(stdout.contains("[OK] Bundle created:"));

    // 2. Modify informative field
    let mut bundle_data = fs::read_to_string(&bundle_path).unwrap();
    bundle_data = bundle_data.replace(
        "\"estimated_seconds_own_hardware\": 1",
        "\"estimated_seconds_own_hardware\": 99999",
    );
    fs::write(&bundle_path, &bundle_data).unwrap();

    // 3. Verify - should succeed despite informative field change
    let (stdout, _, status) =
        run_tlpsign(&["verify", "--bundle", &bundle_path, "--document", &doc_path]);
    assert!(
        status.success(),
        "Verify command failed after modifying informative field. Output: {}",
        stdout
    );
    assert!(stdout.contains("[OK] Signature valid. Document authenticated."));

    // 4. Modify cryptographic metadata (document_hash)
    let mut bundle_data = fs::read_to_string(&bundle_path).unwrap();
    bundle_data = bundle_data.replace("\"document_hash\": \"", "\"document_hash\": \"00");
    fs::write(&bundle_path, &bundle_data).unwrap();

    // 5. Verify - should fail with exit code 1
    let (stdout, _, status) =
        run_tlpsign(&["verify", "--bundle", &bundle_path, "--document", &doc_path]);
    assert_eq!(
        status.code(),
        Some(1),
        "Expected exit code 1 for tampered bundle"
    );
    assert!(
        stdout.contains("Document hash does not match bundle metadata"),
        "Expected specific failure message"
    );
}
