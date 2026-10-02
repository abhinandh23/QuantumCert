# Threat model

QuantumCert is an **academic prototype**. This document states what it defends against, how, and what it deliberately does not cover.

## Assets and trust anchor
- **Issuer private key** (SLH-DSA-SHA2-128s secret key).
  - Stored only at `keys/private/<key_id>.sk.json`, encrypted with AES-256-GCM under a key derived by scrypt from `QC_KEY_PASSPHRASE`. The AAD binds the key_id and algorithm.
  - Gitignored, never served, and never returned by any endpoint. A test audits every route and response for it.
- **Trusted keystore** `keys/trusted_keys.json`.
  - Holds public keys only. It is the **only** source of keys used for verification.
  - It is a config file rather than a DB table, so that write access to the database cannot add a trusted key.
  - Retired keys stay in the file so that old certificates keep verifying.
- **Issuer database** (SQLite). It holds:
  - the exact signed bytes, digest and signature of every certificate;
  - revocation status;
  - verification history.

## Attacker capabilities assumed
The attacker can:
- edit any PDF arbitrarily: text, attachments, QR code;
- generate their own SLH-DSA keys;
- copy QR codes and IDs between documents;
- upload arbitrary files;
- call the public API.

They do **not** have the issuer's private key or passphrase.

## Covered: each of these is an automated test and a demo sample

| # | Attack | Detected by | Verdict |
|---|---|---|---|
| 1 | Edit printed CGPA, name, degree or date (regenerated PDF, or a white-box overlay) | Check 4: printed text ≠ signed payload. An overlay heuristic also flags filled shapes, extra images and annotations. | INVALID |
| 1b | Append a forged extra page (e.g. a fake “transcript” claiming CGPA 9.99) to a genuine certificate | Check 1: only single-page PDFs are accepted, because the printed-text and overlay checks inspect page 1 only | INVALID (HTTP 400) |
| 2 | Edit the embedded `quantumcert.json` | Check 5: digest ≠ QR and record. Check 6: signature fails. | INVALID |
| 3 | Edit the payload, recompute the digest and print a new QR | Check 6: signature fails (can't be recomputed without sk). Digest ≠ record. | INVALID |
| 4 | Flip signature bytes | Check 6 | INVALID |
| 5 | Sign a fake certificate with the attacker's own SLH-DSA key, under the attacker's key_id or claiming the issuer's | Check 6: key_id not trusted, or signature fails under the trusted key. Keys inside documents are ignored. | INVALID |
| 6 | Paste a genuine QR onto a fake certificate | Check 5: QR cert_id / digest ≠ the document's signed data | INVALID |
| 7 | Change the cert_id: in the payload, the QR only, or the print only; or look up a random ID | Signature / integrity / printed-text checks; a random ID → no record | INVALID / UNKNOWN |
| 8 | Present a genuine certificate that was later revoked | Check 8. The signature is still reported **valid**. | REVOKED |
| 9 | Present a genuine certificate after its expiry date | Check 9 (expiry date is signed) | EXPIRED |
| 10 | Upload a non-PDF, truncated, encrypted, > 5 MB or multi-page file, or a scanned copy without the attachment | Check 1 or 3. Rejected with a clear message, never a crash. | INVALID (HTTP 400/413) |
| – | Edit a stored record directly in the database | Check 7 / record signature check: the stored signature no longer verifies | INVALID |
| – | Scan a QR code whose digest doesn't match the record | QR/record mismatch check | INVALID |

**Other measures:**
- **Admin pages:**
  - argon2id password hashes;
  - signed session cookie (HttpOnly, SameSite=Strict);
  - a CSRF token on every state-changing form;
  - throttling after 5 failed logins.
- **Hostile uploads:** upload size cap, page cap, encrypted PDFs refused, image decompression-bomb limit, and all parser exceptions mapped to INVALID.
- **Unicode spoofing:** NFC normalisation, and control or bidi-override characters rejected.
- **ID enumeration:** certificate IDs are random (60 bits), not sequential, so records can't be enumerated by guessing.
- **Webcam frames:** frames sent to `/verify/scan-frame` are decoded in memory and discarded. They are never stored or written to the verification history, and each is capped at 3 MB.
- **Browser hardening:** a CSP with no inline scripts, `X-Frame-Options: DENY`, and `nosniff`.

## Not covered (out of scope for this prototype)
- **Compromise of the issuer server or private key.**
  - Anyone holding sk plus the passphrase can issue genuine certificates.
  - Mitigation in production would be an HSM, key ceremonies and short-lived signing keys, none of which are in scope.
  - Key rotation exists (`python -m cli.keys rotate`), but there is no "key compromised, distrust everything after date X" mechanism.
- **A database attacker un-revoking a certificate.**
  - Revocation status is not signed: it lives in the DB and is checked online only.
  - A production system would publish signed revocation lists or use OCSP-style responses.
- **Offline revocation.** The offline CLI cannot know about revocations and says so explicitly.
- **Identity binding.** A genuine certificate shown by the wrong person ("this is my degree") cannot be detected. The certificate binds a name and register number, not a biometric or ID document. The verifier must compare them with the person.
- **Pixel-level edits the heuristic misses.**
  - The printed-text check compares the PDF's *text objects*. An attacker who rasterises the whole page and redraws it would remove the embedded attachment, which is caught (scanned-copy case) but must then be checked by ID.
  - Clever vector edits that both delete the original text and avoid filled shapes, images and annotations would still fail, because the new text no longer matches the signed payload. Pure visual tricks (e.g. clipping paths hiding text) are not exhaustively detected.
- **QR/ID-only verification checks the record, not the paper.** The UI says so and asks the verifier to compare the shown data, or upload the PDF.
- **Denial of service.** There is only basic size and page limits; no rate limiting on public verification.
- **Transport security.** The demo runs on `http://localhost`. A real deployment needs HTTPS (then `https_only` session cookies are enabled automatically).
- **Library assurance.** `pqcrypto` (Rust) is not formally audited. We mitigate with the NIST ACVP vectors in the test suite and a cross-check against an independent implementation (`@noble/post-quantum`) in the spike.
- **Long-term hash agility.** If SHA-256 were ever weakened, both the digest and SLH-DSA-SHA2 would need migrating. `schema_version` and `alg` fields exist to make such a migration possible.
