use num_bigint::{BigUint, RandBigInt};
use num_traits::One;
use rand::{rngs::OsRng, RngCore};

/// Generates exactly 32 bytes of cryptographically secure random data.
/// Used for sk, K_tlp, and R.
pub fn generate_32_bytes() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

/// Miller-Rabin primality test.
/// k=40 gives a 2^-80 probability of a false prime, which is cryptographically sound.
fn is_probably_prime(n: &BigUint, k: usize) -> bool {
    if n <= &BigUint::from(3u32) {
        return n > &BigUint::one();
    }
    if !n.bit(0) {
        return false; // Even number
    }

    let one = BigUint::one();
    let n_minus_one = n - &one;

    let mut d = n_minus_one.clone();
    let mut s = 0;
    while !d.bit(0) {
        d >>= 1;
        s += 1;
    }

    let mut rng = OsRng;
    for _ in 0..k {
        // Random a in [2, n - 2]
        let a = rng.gen_biguint_range(&BigUint::from(2u32), &(&n_minus_one - &one));
        let mut x = a.modpow(&d, n);

        if x == one || x == n_minus_one {
            continue;
        }

        let mut composite = true;
        for _ in 0..(s - 1) {
            x = x.modpow(&BigUint::from(2u32), n);
            if x == n_minus_one {
                composite = false;
                break;
            }
        }

        if composite {
            return false;
        }
    }
    true
}

const SMALL_PRIMES: [u32; 100] = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
    101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
    197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307,
    311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421,
    431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541,
];

/// Generates a Safe Prime (p = 2q + 1, where q is also prime).
/// Note: Safe prime generation can be slow, but it guarantees maximum resistance
/// for the RSA modulus used in the time-lock puzzle.
fn generate_safe_prime(bits: usize) -> BigUint {
    let mut rng = OsRng;
    loop {
        let mut q = rng.gen_biguint(bits as u64 - 1);
        q.set_bit(0, true);
        q.set_bit(bits as u64 - 2, true);

        for _ in 0..10000 {
            let mut is_composite = false;
            for &p in &SMALL_PRIMES[1..] {
                if &q % p == BigUint::from(0u32) {
                    is_composite = true;
                    break;
                }
            }

            if !is_composite {
                let p: BigUint = (&q << 1) + BigUint::one();
                let mut p_composite = false;
                for &pr in &SMALL_PRIMES[1..] {
                    if &p % pr == BigUint::from(0u32) {
                        p_composite = true;
                        break;
                    }
                }

                if !p_composite && is_probably_prime(&q, 20) && is_probably_prime(&p, 20) {
                    return p;
                }
            }
            q += BigUint::from(2u32);
        }
    }
}

/// Generates a 2048-bit RSA modulus (N = p * q) using two 1024-bit safe primes.
/// NEVER reuse an N between two puzzles.
pub fn generate_rsa_modulus() -> BigUint {
    #[cfg(debug_assertions)]
    if std::env::var("TLPSIGN_TEST_FAST_RSA").is_ok() {
        // Fast path strictly for tests to avoid timeouts.
        // ONLY compiled in debug mode.
        let p = generate_safe_prime(128);
        let q = generate_safe_prime(128);
        return p * q;
    }
    let p = generate_safe_prime(1024);
    let q = generate_safe_prime(1024);
    p * q
}
