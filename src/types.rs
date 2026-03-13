use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Represents the version of the tlpsign bundle format.
/// Enforces strict versioning as mandated by the protocol.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum BundleVersion {
    #[serde(rename = "1.0")]
    V1_0,
}

/// Encrypted signature data using AES-GCM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedSignature {
    /// Base64 encoded ciphertext.
    pub ciphertext: String,
    /// Base64 encoded 12-byte nonce.
    pub nonce: String,
}

/// Time-Lock Puzzle parameters based on RSA Sequential Squaring (RSW-96).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeLockPuzzle {
    /// RSA modulus N (2048-bit hex).
    pub n: String,
    /// Base 'a', fixed to 2 by the protocol.
    pub a: String,
    /// Total number of modular squarings.
    pub t_iterations: u64,
    /// Payload: w[0..32] XOR K_tlp (hex).
    pub payload: String,
    /// Operational safety multiplier against faster hardware.
    pub conservative_multiplier: u32,
    /// Performance metric: milliseconds per million iterations.
    pub benchmark_ms_per_million: u64,
    /// Estimated time to solve on the original hardware (seconds).
    pub estimated_seconds_own_hardware: u64,
    /// Estimated time for an adversary with 5x faster hardware (seconds).
    pub estimated_seconds_5x_adversary: u64,
    /// Metadata about the environment where the bundle was created.
    pub hardware_note: String,
}

/// SHA3-256 commitments for integrity and revocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Commitments {
    /// Commitment to the verification key (vk) for post-resolution integrity.
    pub vk: String,
    /// Commitment to the revocation key (R).
    pub revocation: String,
}

/// The main tlpsign bundle structure.
/// This is the public container distributed to third parties.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bundle {
    /// Protocol version.
    pub version: BundleVersion,
    /// SHA3-256 hash of the original document.
    pub document_hash: String,
    /// The encrypted Ed25519 signature.
    pub sigma_encrypted: EncryptedSignature,
    /// The time-lock puzzle parameters.
    pub timelock_puzzle: TimeLockPuzzle,
    /// Integrity and revocation commitments.
    pub commitments: Commitments,
    /// Optional revocation key R (hex), populated only after revocation.
    pub revocation: Option<String>,
    /// ISO 8601 creation timestamp.
    pub created_at: String,
}

/// Sensitive material that must be zeroized after use.
/// This struct is used internally during the signing process.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SecretMaterial {
    /// Ed25519 Secret Key.
    pub sk: [u8; 32],
    /// Ephemeral TLP key (K_tlp).
    pub k_tlp: [u8; 32],
    /// Independent Revocation Key (R).
    pub revocation_key: [u8; 32],
}

impl SecretMaterial {
    /// Creates a new container for secret materials.
    pub fn new(sk: [u8; 32], k_tlp: [u8; 32], revocation_key: [u8; 32]) -> Self {
        Self {
            sk,
            k_tlp,
            revocation_key,
        }
    }
}
