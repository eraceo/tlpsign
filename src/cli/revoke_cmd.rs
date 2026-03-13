use crate::protocol::revoke::apply_revocation;
use crate::types::Bundle;
use std::fs;

pub fn execute(bundle_path: &str, revocation_key_hex: &str) -> Result<(), String> {
    let bundle_data = fs::read_to_string(bundle_path)
        .map_err(|_| format!("Failed to read bundle at {}", bundle_path))?;

    let mut bundle: Bundle = serde_json::from_str(&bundle_data)
        .map_err(|_| "Failed to parse bundle JSON".to_string())?;

    apply_revocation(&mut bundle, revocation_key_hex)?;

    let updated_json = serde_json::to_string_pretty(&bundle)
        .map_err(|_| "Failed to serialize updated bundle".to_string())?;

    fs::write(bundle_path, updated_json)
        .map_err(|_| format!("Failed to save revoked bundle back to {}", bundle_path))?;

    println!("\n[OK] Revocation verified (R matches the commitment).");
    println!("[WARN] The local bundle has been updated, but this is NOT enough.");
    println!("\n[ACTION REQUIRED] Republish the bundle on the EXACT same distribution channel");
    println!("                  as the original bundle for the revocation to be effective.");
    println!("\n[INFO] Without republication, holders of the original bundle will not know about this revocation.");

    Ok(())
}
