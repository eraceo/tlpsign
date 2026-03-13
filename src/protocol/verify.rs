use crate::crypto::commitment::{create_commitment, hash_document};
use crate::protocol::timelock::{sequential_square, solve_payload};
use crate::types::{Bundle, BundleVersion};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use num_bigint::BigUint;
use num_traits::Num;
use zeroize::Zeroizing;

/// Verifies a tlpsign bundle against a document.
/// Always executes the full time-lock puzzle sequentially.
pub fn verify_bundle(bundle: &Bundle, document: &[u8]) -> Result<(), String> {
    // 1. Strict version checking
    if bundle.version != BundleVersion::V1_0 {
        return Err("Unsupported bundle version".to_string());
    }

    // 2. Check if bundle was explicitly revoked
    if let Some(rev_hex) = &bundle.revocation {
        let rev_bytes = hex::decode(rev_hex).map_err(|_| "Invalid revocation hex")?;
        let computed_commitment = create_commitment(&rev_bytes);
        if computed_commitment == bundle.commitments.revocation {
            return Err("REVOKED: This bundle has been validly revoked by the signer.".to_string());
        }
    }

    // 3. Verify document integrity pre-TLP solving
    let computed_doc_hash = hex::encode(hash_document(document));
    if computed_doc_hash != bundle.document_hash {
        return Err("FAIL: Document hash does not match bundle metadata.".to_string());
    }

    // 4. Resolve Time-Lock Puzzle
    // WARNING: Strict source of truth. We ONLY read t_iterations.
    let n = BigUint::from_str_radix(&bundle.timelock_puzzle.n, 16)
        .map_err(|_| "Invalid RSA modulus hex")?;
    let t = bundle.timelock_puzzle.t_iterations;

    let w = sequential_square(2, t, &n);

    // K_tlp is heavily sensitive, zeroize after decryption
    let k_tlp = Zeroizing::new(
        solve_payload(&w, &n, &bundle.timelock_puzzle.payload).map_err(|e| e.to_string())?,
    );

    // 5. Decrypt signature payload
    let cipher = Aes256Gcm::new_from_slice(&*k_tlp).map_err(|_| "Invalid AES key size")?;

    let nonce_bytes = base64::engine::general_purpose::STANDARD
        .decode(&bundle.sigma_encrypted.nonce)
        .map_err(|_| "Invalid base64 nonce")?;
    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(&bundle.sigma_encrypted.ciphertext)
        .map_err(|_| "Invalid base64 ciphertext")?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext =
        Zeroizing::new(cipher.decrypt(nonce, ciphertext.as_slice()).map_err(|_| {
            "AES-GCM decryption failed. TLP resolution likely yielded wrong K_tlp."
        })?);

    if plaintext.len() != 96 {
        return Err("Decrypted payload has invalid length (expected 96 bytes)".to_string());
    }

    // 6. Extract vk and sigma
    let mut vk_bytes = [0u8; 32];
    vk_bytes.copy_from_slice(&plaintext[0..32]);
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(&plaintext[32..96]);

    // 7. Verify vk integrity (prevents vk tampering during transit)
    let computed_vk_commitment = create_commitment(&vk_bytes);
    if computed_vk_commitment != bundle.commitments.vk {
        return Err("FAIL: Verification key integrity check failed.".to_string());
    }

    // 8. Verify the cryptographic signature
    let vk = VerifyingKey::from_bytes(&vk_bytes).map_err(|_| "Invalid Ed25519 public key")?;
    let signature = Signature::from_bytes(&sig_bytes);

    vk.verify(document, &signature)
        .map_err(|_| "FAIL: Signature verification failed.".to_string())?;

    Ok(())
}
