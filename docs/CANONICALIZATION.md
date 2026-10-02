# Canonicalization: exactly what gets signed

The signature covers **canonical certificate data**, not the PDF file. A PDF cannot contain a QR code holding a hash of its own bytes: adding the QR changes the bytes.

## 1. Payload schema (`schema_version` 1)

The payload is a JSON object containing **exactly** these 11 keys. Every key is always present, extra keys are rejected, and there are no floats.

| key | JSON type | rule |
|---|---|---|
| `schema_version` | integer | `1` (a real integer: not `"1"`, not `true`) |
| `cert_id` | string | `QC-` + 12 Crockford base32 chars `[0-9A-HJKMNP-TV-Z]`, random (60 bits) |
| `recipient_id` | string | `[A-Za-z0-9/_-]{1,64}` (register/roll number) |
| `recipient_name` | string | 1–150 chars, canonical text (see §2) |
| `program` | string | 1–150 chars, canonical text |
| `institution` | string | 1–150 chars, canonical text |
| `grade` | string or null | `[0-9]{1,2}\.[0-9]{2}`, e.g. `"8.20"`; `null` if not applicable |
| `issue_date` | string | `YYYY-MM-DD`, a real calendar date |
| `expiry_date` | string or null | `YYYY-MM-DD` ≥ `issue_date`; `null` = never expires |
| `issuer_key_id` | string | 16 lowercase hex = first 16 hex chars of SHA-256(public key) |
| `alg` | string | `"SLH-DSA-SHA2-128s"` |

The CGPA is stored as a **string** (`"8.20"`) so that float formatting can never differ between implementations.

## 2. Text normalisation: at issuance only

When the admin submits the form, every text field is:

1. normalised to Unicode **NFC** (so `e` + U+0301 and the precomposed `é` give the same bytes);
2. whitespace runs (spaces, tabs, newlines) collapsed to a single space and trimmed;
3. rejected if it still contains control characters (Unicode category Cc) or bidi override/isolate characters (U+202A–E, U+2066–9, the "Trojan Source" characters).

The CGPA input is accepted as `8`, `8.2` or `8.20` and stored as exactly two decimals.

**The verifier never normalises.** It *checks* that each string is already canonical and fails otherwise. If it silently re-normalised, it would vouch for bytes that differ from what is displayed.

Implementation: [app/core/payload.py](../app/core/payload.py), [app/core/canonical.py](../app/core/canonical.py).

## 3. Canonical bytes

```
canonical_bytes = JCS(payload)        # RFC 8785 JSON Canonicalization Scheme
```

- Keys are sorted, with no insignificant whitespace, encoded as UTF-8. Non-ASCII characters appear literally, not as `\u` escapes.
- Because the payload only contains strings, the integer `1` and `null`, the JCS number-serialisation rules never come into play.
- Implemented with the `rfc8785` package.

Golden example (one line, 329 bytes; this is also a unit test):

```
{"alg":"SLH-DSA-SHA2-128s","cert_id":"QC-7K2M9Q4XHT3B","expiry_date":null,"grade":"8.20","institution":"Example Institute of Technology","issue_date":"2026-06-30","issuer_key_id":"3f9a1c0be47d2a56","program":"B.Tech Computer Science and Engineering","recipient_id":"2023BCS0041","recipient_name":"Asha Ménon","schema_version":1}
```

`SHA-256 = 3fb51ec1d2334507571c3419ae41693e92a1e779f67617f1cd3876be55454b53`. You can reproduce it with `printf '%s' '<the line>' | sha256sum`.

## 4. Digest and signature

```
digest    = SHA-256(canonical_bytes)                                   # 32 bytes
signature = SLH-DSA-SHA2-128s.Sign(sk, M = canonical_bytes, ctx = "QuantumCert-v1")   # 7,856 bytes
```

- This is FIPS 205 **pure** mode (not HashSLH-DSA). Inside the library, FIPS 205 signs `M' = 0x00 ‖ 0x0E ‖ "QuantumCert-v1" ‖ canonical_bytes`, where `0x0E` = 14 = len(ctx). The context string binds signatures to this application and version.
- The **digest** is used for the QR code and for fast comparison. It is not a substitute for the signature.

## 5. Where the pieces live

| Where | Content |
|---|---|
| QR code | `{base_url}/verify/{cert_id}?d={base64url(digest)}` (43-char `d`, no padding). The QR never holds the signature: 7.8 KB won't fit in a practical QR code. |
| PDF attachment `quantumcert.json` | `{"format":"quantumcert/1","payload":{…},"signature":"<base64>","key_id":"…","alg":"…","ctx":"QuantumCert-v1"}`. `key_id`, `alg` and `ctx` are **unsigned** convenience copies; the verifier requires them to equal the signed values. |
| PDF page | Each signed field is printed on one line inside a fixed box, so the verifier can compare the printed text with the signed payload. |
| Database `certificates.payload_canonical` | The exact signed bytes, plus `digest` and `signature`, for record-level checks and tamper detection. |
