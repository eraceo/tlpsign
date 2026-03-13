use crate::protocol::timelock::{sequential_square, solve_payload};
use crate::types::Bundle;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::Engine;
use num_bigint::BigUint;
use num_traits::Num;
use serde::Serialize;
use std::fs;
use zeroize::Zeroizing;

#[derive(Serialize)]
struct ResolvedOutput {
    pub document_hash: String,
    pub verification_key_hex: String,
    pub signature_hex: String,
}

pub fn execute(bundle_path: &str, output_path: &str) -> Result<(), String> {
    let bundle_data = fs::read_to_string(bundle_path)
        .map_err(|_| format!("Failed to read bundle at {}", bundle_path))?;

    let bundle: Bundle = serde_json::from_str(&bundle_data)
        .map_err(|_| "Failed to parse bundle JSON".to_string())?;

    println!("[SOLVING] Resolving puzzle to extract cryptographic material...");

    let n = BigUint::from_str_radix(&bundle.timelock_puzzle.n, 16)
        .map_err(|_| "Invalid RSA modulus hex")?;
    let t = bundle.timelock_puzzle.t_iterations;

    let w = sequential_square(2, t, &n);

    let k_tlp = Zeroizing::new(
        solve_payload(&w, &n, &bundle.timelock_puzzle.payload).map_err(|e| e.to_string())?,
    );

    let cipher = Aes256Gcm::new_from_slice(&*k_tlp).map_err(|_| "Invalid AES key size")?;

    let nonce_bytes = base64::engine::general_purpose::STANDARD
        .decode(&bundle.sigma_encrypted.nonce)
        .map_err(|_| "Invalid base64 nonce")?;
    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(&bundle.sigma_encrypted.ciphertext)
        .map_err(|_| "Invalid base64 ciphertext")?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext = Zeroizing::new(
        cipher
            .decrypt(nonce, ciphertext.as_slice())
            .map_err(|_| "AES-GCM decryption failed. The puzzle was likely solved incorrectly.")?,
    );

    if plaintext.len() != 96 {
        return Err("Decrypted payload has invalid length (expected 96 bytes)".to_string());
    }

    let vk_hex = hex::encode(&plaintext[0..32]);
    let sig_hex = hex::encode(&plaintext[32..96]);

    let resolved = ResolvedOutput {
        document_hash: bundle.document_hash.clone(),
        verification_key_hex: vk_hex,
        signature_hex: sig_hex,
    };

    let resolved_json = serde_json::to_string_pretty(&resolved)
        .map_err(|_| "Failed to serialize resolved payload".to_string())?;

    fs::write(output_path, resolved_json)
        .map_err(|_| format!("Failed to write resolved payload to {}", output_path))?;

    println!("\n[OK] Puzzle resolved successfully.");
    println!(
        "[OK] Verification key and signature extracted and saved to: {}",
        output_path
    );

    Ok(())
}
