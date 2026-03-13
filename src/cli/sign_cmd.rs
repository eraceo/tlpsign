use crate::protocol::sign::sign_document;
use std::fs;

pub fn execute(
    document_path: &str,
    delay_seconds: u64,
    multiplier: u32,
    output_path: &str,
    hardware_note: &str,
) -> Result<(), String> {
    println!("[INFO] Reading document...");
    let doc_bytes = fs::read(document_path)
        .map_err(|_| format!("Failed to read document at {}", document_path))?;

    println!("[INFO] Generating cryptographic material and calibrating Time-Lock Puzzle...");
    println!("[INFO] This may take a few seconds to find safe primes for the RSA modulus.");

    let (bundle, revocation_key) =
        sign_document(&doc_bytes, delay_seconds, multiplier, hardware_note)?;

    let bundle_json = serde_json::to_string_pretty(&bundle)
        .map_err(|_| "Failed to serialize bundle to JSON".to_string())?;

    fs::write(output_path, bundle_json)
        .map_err(|_| format!("Failed to write bundle to {}", output_path))?;

    println!("\n[OK] Bundle created: {}", output_path);
    println!("[OK] Revocation key: R={}", revocation_key);
    println!("\n[ACTION] Note R now — it will not be displayed again.");
    println!("         Destroy R = permanently disable the kill switch.");
    println!("         Keep R    = retain ability to revoke before expiration.");
    println!(
        "\n[INFO] Target delay: {} seconds | Multiplier: {}x",
        delay_seconds, multiplier
    );
    println!(
        "[INFO] Estimated resolution: ~{} seconds for an adversary {}x faster",
        delay_seconds, multiplier
    );
    println!(
        "[INFO] Estimated resolution: ~{} seconds on hardware equivalent to yours",
        delay_seconds * (multiplier as u64)
    );
    println!("\n[WARN] Secret key (sk) and verification key (vk) have been securely zeroized.");
    println!("[WARN] This operation is now irreversible.");

    Ok(())
}
