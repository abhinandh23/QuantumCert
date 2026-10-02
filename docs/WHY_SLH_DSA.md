# Why SLH-DSA?

## The threat
RSA and elliptic-curve signatures (ECDSA, Ed25519) rely on factoring and discrete logarithms. Shor's algorithm solves both efficiently on a large quantum computer. A degree certificate is a **long-lived document**: it should still verify, and still be unforgeable, decades after it is issued. A signature that a future quantum computer can forge would let anyone mint "genuine" certificates retroactively.

## Why SLH-DSA in particular
**SLH-DSA** (Stateless Hash-based Digital Signature Algorithm, NIST **FIPS 205**, August 2024) is the standardised form of SPHINCS+.

- **Security rests only on hash functions.** It assumes nothing beyond SHA-256 (or SHAKE) behaving like a good hash function: no lattice problems, no number theory. This is the most conservative and best-understood assumption in public-key cryptography. Quantum computers give only a generic (Grover-type) speed-up against hashes, and the parameter sets account for it.
- **It is stateless.** Older hash-based schemes (XMSS, LMS) are stateful: the signer must never reuse a one-time key, and a restored backup or a crash can silently break security. SLH-DSA has no such state, which makes it practical for a web server.
- **It complements the lattice-based standard.** ML-DSA (FIPS 204) is faster and smaller, but its security relies on newer lattice assumptions. NIST standardised SLH-DSA precisely as a hedge in case those assumptions fall.

## The trade-off: large signatures and slow signing

| Scheme | Public key | Signature | Sign | Verify | Security basis |
|---|---|---|---|---|---|
| **SLH-DSA-SHA2-128s** (ours) | 32 B | **7,856 B** | ~180 ms* | ~0.2 ms* | hash functions only |
| SLH-DSA-SHA2-128f | 32 B | 17,088 B | ~9 ms* | ~0.55 ms* | hash functions only |
| ML-DSA-44 (FIPS 204) | 1,312 B | 2,420 B | < 1 ms | < 1 ms | module lattices |
| Ed25519 (not PQ) | 32 B | 64 B | < 0.1 ms | < 0.1 ms | elliptic curves (broken by Shor) |

\* Measured in the day-1 spike on the development laptop ([spike/spike_slhdsa.py](../spike/spike_slhdsa.py)).

**Why 128s rather than 128f:**
- 128f signs about 20× faster, but its signatures are more than twice as large.
- Certificates are issued rarely, by one admin, so slow signing (0.2 s) costs nothing.
- Signature size, by contrast, ends up in every PDF and every database row, so the "small" variant wins.

**Consequences of the size:**
- The 7.8 KB signature is too big for a QR code. That is why the QR holds only the certificate ID and a 32-byte SHA-256 digest.
- The signature travels in the PDF attachment and in the issuer's database instead.

## How we use it safely
- **We never implement SLH-DSA ourselves.** The project uses `pqcrypto` 1.0.0, a Rust implementation exposed to Python, behind a single wrapper module ([app/crypto/slhdsa.py](../app/crypto/slhdsa.py)).
- **The library is checked against the standard.** The day-1 spike confirmed:
  - all 14 NIST ACVP `SLH-DSA-sigVer-FIPS205` test vectors for SHA2-128s pure mode with context strings, which a pre-standard SPHINCS+ implementation would fail;
  - cross-implementation interoperability with `@noble/post-quantum`, in both directions.
- **Pure mode with a fixed context string.** We sign in pure mode with ctx `QuantumCert-v1`, so signatures can't be confused with those of another application or a future format version.
- **Trust comes from the keystore, not the document.** Only public keys in the trusted keystore are accepted. A forger can generate their own perfectly valid SLH-DSA key and signature, and the verifier rejects it because that key is not trusted (demo scenario 5).
