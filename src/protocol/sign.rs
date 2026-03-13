use crate::crypto::{
    commitment::{create_commitment, hash_document},
    keygen::{generate_32_bytes, generate_rsa_modulus},
};
use crate::protocol::timelock::{
    build_payload, calibrate_iterations_per_second, sequential_square,
};
use crate::types::{
    Bundle, BundleVersion, Commitments, EncryptedSignature, SecretMaterial, TimeLockPuzzle,
};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::Engine;
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroizing;

/// Creates a tlpsign bundle for a given document.
/// Returns the public Bundle and the private Revocation Key (hex string).
pub fn sign_document(
    document: &[u8],
    delay_seconds: u64,
    multiplier: u32,
    hardware_note: &str,
) -> Result<(Bundle, String), String> {
    // 1. & 2. Generate all key materials (strictly independent)
    let sk_bytes = generate_32_bytes();
    let k_tlp_bytes = generate_32_bytes();
    let rev_key_bytes = generate_32_bytes();

    // Encapsulate in Zeroize-on-drop struct immediately
    let secrets = SecretMaterial::new(sk_bytes, k_tlp_bytes, rev_key_bytes);

    // Derive verification key
    let signing_key = SigningKey::from_bytes(&secrets.sk);
    let vk_bytes = signing_key.verifying_key().to_bytes();

    // 3. Sign the document
    let signature = signing_key.sign(document);

    // 4. Encrypt (vk || signature) using AES-256-GCM and K_tlp
    // Payload is exactly 32 (vk) + 64 (sig) = 96 bytes
    let mut plaintext = Zeroizing::new(vec![0u8; 96]);
    plaintext[0..32].copy_from_slice(&vk_bytes);
    plaintext[32..96].copy_from_slice(&signature.to_bytes());

    let cipher = Aes256Gcm::new_from_slice(&secrets.k_tlp).map_err(|e| e.to_string())?;
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_slice())
        .map_err(|e| e.to_string())?;

    let sigma_encrypted = EncryptedSignature {
        ciphertext: base64::engine::general_purpose::STANDARD.encode(ciphertext),
        nonce: base64::engine::general_purpose::STANDARD.encode(nonce_bytes),
    };

    // 5. Build Time-Lock Puzzle (TLP)
    let n = generate_rsa_modulus();
    let ips = calibrate_iterations_per_second(&n);
    let t_iterations = ips * delay_seconds * (multiplier as u64);

    let w = sequential_square(2, t_iterations, &n);

    // Extract payload (XOR K_tlp)
    let tlp_payload = build_payload(&w, &n, &secrets.k_tlp);

    // 6. Create Commitments
    let commitments = Commitments {
        vk: create_commitment(&vk_bytes),
        revocation: create_commitment(&secrets.revocation_key),
    };

    // 7. Assemble Bundle
    let bundle = Bundle {
        version: BundleVersion::V1_0,
        document_hash: hex::encode(hash_document(document)),
        sigma_encrypted,
        timelock_puzzle: TimeLockPuzzle {
            n: n.to_str_radix(16),
            a: "2".to_string(),
            t_iterations,
            payload: hex::encode(tlp_payload),
            conservative_multiplier: multiplier,
            benchmark_ms_per_million: if ips > 0 { 1_000_000_000 / ips } else { 0 },
            estimated_seconds_own_hardware: delay_seconds,
            estimated_seconds_5x_adversary: delay_seconds / 5,
            hardware_note: hardware_note.to_string(),
        },
        commitments,
        revocation: None,
        created_at: Utc::now().to_rfc3339(),
    };

    // Export revocation key as hex for the user
    let revocation_hex = hex::encode(secrets.revocation_key);

    // 'secrets' is dropped here -> sk, K_tlp, and R memory is strictly zeroized.
    // 'w' was dropped -> zeroized inside build_payload.
    // 'plaintext' is dropped -> zeroized.
    Ok((bundle, revocation_hex))
}
