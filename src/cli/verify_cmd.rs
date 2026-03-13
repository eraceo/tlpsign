use crate::protocol::verify::verify_bundle;
use crate::types::Bundle;
use std::fs;

pub fn execute(bundle_path: &str, document_path: &str) -> Result<(), String> {
    let bundle_data = fs::read_to_string(bundle_path)
        .map_err(|_| format!("Failed to read bundle at {}", bundle_path))?;

    let bundle: Bundle = serde_json::from_str(&bundle_data).map_err(|_| {
        "Failed to parse bundle JSON. Ensure it is a valid V1.0 bundle.".to_string()
    })?;

    let doc_bytes = fs::read(document_path)
        .map_err(|_| format!("Failed to read document at {}", document_path))?;

    println!("[SOLVING] Resolving the puzzle in progress...");
    println!("[SOLVING] This duration is strictly proportional to t_iterations. Please wait.");

    match verify_bundle(&bundle, &doc_bytes) {
        Ok(_) => {
            println!("\n[OK] Signature valid. Document authenticated.");
            println!("[INFO] Verification key (vk) verified against commitment — puzzle integrity confirmed.");
            Ok(())
        }
        Err(e) => {
            if e.contains("REVOKED") {
                println!("\n[REVOKED] {}", e);
                println!("[REVOKED] Document is invalidated.");
                std::process::exit(2);
            } else {
                println!("\n[FAIL] {}", e);
                println!("[FAIL] Document modified, bundle corrupted, or puzzle unsolved.");
                std::process::exit(1);
            }
        }
    }
}
