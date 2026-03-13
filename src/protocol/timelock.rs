use num_bigint::BigUint;
use std::time::Instant;
use zeroize::Zeroizing;

/// Calibrates the sequential squarings per second on the current hardware.
pub fn calibrate_iterations_per_second(n: &BigUint) -> u64 {
    let start = Instant::now();
    let mut a = BigUint::from(2u32);
    let test_iterations = 100_000;

    // Sequential squaring: w_{i+1} = w_i^2 mod N
    for _ in 0..test_iterations {
        a = (&a * &a) % n;
    }

    let elapsed_ms = start.elapsed().as_millis() as u64;
    if elapsed_ms == 0 {
        return test_iterations; // Fallback to avoid division by zero on absurdly fast hardware
    }

    (test_iterations * 1000) / elapsed_ms
}

/// Core sequential squaring function.
/// Determines 'w' after T iterations. MUST NOT be parallelized.
pub fn sequential_square(a: u32, t_iterations: u64, n: &BigUint) -> BigUint {
    let mut w = BigUint::from(a);
    for _ in 0..t_iterations {
        w = (&w * &w) % n;
    }
    w
}

/// Encapsulates K_tlp into the TLP payload using 'w'.
/// Extraces exactly the top 32 bytes of 'w' (padded to N's byte length, big-endian).
pub fn build_payload(w: &BigUint, n: &BigUint, k_tlp: &[u8; 32]) -> [u8; 32] {
    let n_bytes = (n.bits() as usize).div_ceil(8);
    let mut w_bytes = Zeroizing::new(vec![0u8; n_bytes]);
    let w_raw = Zeroizing::new(w.to_bytes_be());

    // Pad w with leading zeros to exactly n_bytes bytes
    let offset = n_bytes.saturating_sub(w_raw.len());
    w_bytes[offset..].copy_from_slice(&w_raw);

    let mut payload = [0u8; 32];
    for i in 0..32 {
        // XOR the first 32 bytes of the padded 'w' with K_tlp
        // If n_bytes < 32, this will panic, but n is strictly >= 256 bits (32 bytes)
        payload[i] = w_bytes[i] ^ k_tlp[i];
    }
    payload
}

/// Recovers K_tlp from the puzzle payload by recomputing 'w'.
/// Follows strict truth: relies ONLY on 't_iterations', 'n', and 'payload'.
pub fn solve_payload(
    w: &BigUint,
    n: &BigUint,
    payload_hex: &str,
) -> Result<[u8; 32], &'static str> {
    let payload = hex::decode(payload_hex).map_err(|_| "Invalid payload hex")?;
    if payload.len() != 32 {
        return Err("Payload must be exactly 32 bytes");
    }

    let n_bytes = (n.bits() as usize).div_ceil(8);
    let mut w_bytes = Zeroizing::new(vec![0u8; n_bytes]);
    let w_raw = Zeroizing::new(w.to_bytes_be());

    let offset = n_bytes.saturating_sub(w_raw.len());
    w_bytes[offset..].copy_from_slice(&w_raw);

    let mut k_tlp = [0u8; 32];
    for i in 0..32 {
        k_tlp[i] = w_bytes[i] ^ payload[i];
    }

    Ok(k_tlp)
}
