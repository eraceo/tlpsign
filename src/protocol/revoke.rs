use crate::crypto::commitment::create_commitment;
use crate::types::Bundle;

/// Verifies a provided revocation key against the bundle's commitment.
/// If valid, mutates the bundle to include the revocation.
pub fn apply_revocation(bundle: &mut Bundle, revocation_key_hex: &str) -> Result<(), String> {
    let rev_bytes = hex::decode(revocation_key_hex).map_err(|_| "Invalid revocation hex format")?;

    if rev_bytes.len() != 32 {
        return Err("Revocation key must be exactly 32 bytes (64 hex characters)".to_string());
    }

    let computed_commitment = create_commitment(&rev_bytes);

    if computed_commitment != bundle.commitments.revocation {
        return Err(
            "FAIL: Revocation key does not match the commitment in the bundle.".to_string(),
        );
    }

    // Valid revocation, record it in the bundle.
    bundle.revocation = Some(revocation_key_hex.to_string());

    Ok(())
}
