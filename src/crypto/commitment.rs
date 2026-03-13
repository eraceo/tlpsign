use sha3::{Digest, Sha3_256};

/// Computes the SHA3-256 hash of a given document.
/// Returns the raw 32 bytes.
pub fn hash_document(document: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(document);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Creates a hex-encoded SHA3-256 commitment from raw data.
/// Used for vk (Verification Key) and R (Revocation Key).
pub fn create_commitment(data: &[u8]) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    let result = hasher.finalize();
    hex::encode(result)
}
