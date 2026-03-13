# tlpsign 

[![Crates.io](https://img.shields.io/crates/v/tlpsign.svg)](https://crates.io/crates/tlpsign)
[![Docs.rs](https://docs.rs/tlpsign/badge.svg)](https://docs.rs/tlpsign)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust 1.75+](https://img.shields.io/badge/rust-1.75%2B-blue.svg)](https://www.rust-lang.org)

A cryptographic protocol for time-locked signature verification with an optional revocation mechanism, requiring no trusted third party.

---

## Overview

tlpsign allows a signer to produce a document signature whose verifiability is deferred until a future point in time. Until that point, the signature cannot be verified by anyone, including the signer. After expiration, verification becomes possible for any party who resolves the time-lock puzzle embedded in the bundle.

An optional revocation key allows the signer to invalidate the signature before expiration. Destroying the revocation key makes the eventual disclosure unconditional.

This design is intended for scenarios where a document must be authenticated at a future date regardless of what happens to its author — whistleblowing with a safety window, cryptographic dead man's switches, and deferred proof of prior knowledge.

---

## Security properties

**Guaranteed**

- Pre-T confidentiality: the signature is not verifiable before puzzle resolution
- Post-T authenticity: any party can verify the signature after resolution
- Post-T non-repudiation: the signer cannot deny authorship after disclosure
- Pre-T revocation: the signer can invalidate the signature using the revocation key
- Coercion resistance: destroying the revocation key makes disclosure unstoppable, including under duress

**Not guaranteed**

- Signer anonymity — tlpsign is not an anonymity tool
- Provable key destruction — this is an operational guarantee, not a cryptographic one
- Exact timing — the time-lock duration is a hardware-dependent estimate, not a hard bound

---

## Protocol

```
T=0  Generate (sk, vk)               ed25519 keypair
     Generate K_tlp                  32-byte ephemeral symmetric key (CSPRNG)
     Generate R                      32-byte revocation key (CSPRNG, independent of sk)
     Compute  T = benchmark_ips * delay_seconds * multiplier
     Compute  w = 2^(2^T) mod N      sequential squaring, T iterations
                                     w_0 = 2, w_{i+1} = w_i^2 mod N
     Compute  payload = w[0..32] XOR K_tlp   (big-endian, 32 bytes)
     Compute  sig = Sign(sk, D)
     Compute  sig_enc = AES-GCM(K_tlp, sig)
     Zeroize  w, then K_tlp          in that order, after sig_enc is written
     Publish  { D, sig_enc, {N, 2, T, payload}, SHA3-256(vk), SHA3-256(R) }
     Destroy  sk, vk
     Save or destroy R

T=0..T
     To revoke: publish updated bundle on the same channel as the original
                SHA3-256(R) in the bundle allows any verifier to validate R

T    Recompute w = 2^(2^T) mod N     deterministic, same result
     K_tlp = w[0..32] XOR payload
     sig = AES-GCM-Decrypt(K_tlp, sig_enc)
     Check SHA3-256(vk) == commitment.vk
     Verify(vk, sig, D)
     If valid and no revocation -> document authenticated
```

`w` is the result of exactly T sequential modular squarings starting from `a=2`. The first 32 bytes in big-endian representation are XORed with K_tlp to form the payload. Both `solve` and `verify` must recompute w using this exact definition. Any divergence in implementation — endianness, truncation length — produces a wrong K_tlp and fails silently.

---

## Usage

```bash
# Sign a document with a 180-day disclosure delay and a 5x adversary multiplier
tlpsign sign --document report.pdf --delay 180d --multiplier 5 --output bundle.tlpsign

# Verify (always attempts full puzzle resolution, no clock-based shortcut)
tlpsign verify --bundle bundle.tlpsign --document report.pdf

# Revoke before expiration
tlpsign revoke --bundle bundle.tlpsign --revocation-key <R>

# Solve the puzzle and export for distribution
tlpsign solve --bundle bundle.tlpsign --output bundle.resolved.tlpsign
```

`--multiplier` defaults to 3. For sensitive use cases, use 5 or higher. A multiplier of 5 means an adversary with hardware 5x faster than the signing machine will still need the full intended delay to resolve the puzzle.

Revocation modifies the local bundle. The updated bundle must be redistributed on the exact same channel as the original. There is no centralized revocation registry.

---

## Bundle format

```json
{
  "version": "1.0",
  "document_hash": "<sha3-256 hex>",
  "sigma_encrypted": {
    "ciphertext": "<base64>",
    "nonce": "<base64, 12 bytes>"
  },
  "timelock_puzzle": {
    "n": "<RSA modulus, 2048-bit hex>",
    "a": "2",
    "t_iterations": 1000000000,
    "payload": "<w XOR K_tlp, hex>",
    "benchmark_ms_per_million": 450,
    "estimated_seconds": 450000,
    "hardware_note": "<CPU model and clock speed used for calibration>"
  },
  "commitments": {
    "vk": "<sha3-256 hex — post-resolution integrity check only>",
    "revocation": "<sha3-256 hex>"
  },
  "revocation": null,
  "created_at": "<ISO 8601>"
}
```

---

## Cryptographic primitives

| Purpose | Primitive |
|---|---|
| Signature | Ed25519 (deterministic, RFC 8032) |
| Symmetric encryption | AES-256-GCM |
| Time-lock | RSA sequential squaring, 2048-bit modulus |
| Commitments | SHA3-256 |
| Key generation | OS CSPRNG |

---

## Building

```bash
git clone https://github.com/yourname/tlpsign
cd tlpsign
cargo build --release
```

Requires Rust 1.75 or later.

---

## Dependencies

```
ed25519-dalek     Signature
aes-gcm           Symmetric encryption
num-bigint        Big integer arithmetic for TLP
sha3              Hashing and commitments
zeroize           Guaranteed memory erasure
serde / serde_json  Bundle serialization
rand / rand_core  Cryptographic randomness
clap              CLI
```

---

## Limitations

**Revocation requires redistribution.** Revoking a bundle only takes effect if the updated bundle reaches the same parties who hold the original. If the original was distributed on a Tor hidden service and the revocation is published on a public server, holders of the original bundle will never see the revocation and the document will authenticate at expiration. Note the distribution channel at signing time. If you are uncertain you will be able to redistribute, destroy R and treat disclosure as unconditional.

**Time-lock duration is an estimate.** The delay is calibrated against the signing machine's hardware. The `--multiplier` flag is the primary control against a faster adversary: `t_iterations = benchmark_ips * delay_seconds * multiplier`. With multiplier=5, an adversary running hardware 5x faster still needs the full intended delay. For whistleblowing or dead man's switch scenarios, use multiplier=5 or higher and document the assumed adversary in the bundle's hardware note.

**No signer anonymity.** The bundle contains a commitment to the signer's verification key. All bundles produced by the same keypair are linkable. If anonymity is required, combine with ring signatures or zero-knowledge constructions as a separate layer.

**No formal audit.** This implementation has not been independently reviewed. Do not deploy it in contexts where failure has serious consequences until an audit has been completed.

---

## References

- Rivest, Shamir, Wagner — *Time-lock puzzles and timed-release crypto*, MIT/LCS/TR-684, 1996
- Boneh, Naor — *Timed Commitments*, CRYPTO 2000
- Boneh, Franklin — *Identity-Based Encryption from the Weil Pairing*, CRYPTO 2001

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
