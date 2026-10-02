# QuantumCert

Post-quantum signed PDF certificates. A mini project for the Cryptography & Network Security course.

QuantumCert issues degree certificates as PDFs signed with **SLH-DSA-SHA2-128s** (NIST **FIPS 205**, pure mode, context `QuantumCert-v1`). Each PDF carries:
- a QR code for lookup;
- an embedded `quantumcert.json` (signed payload + signature) for offline verification.

Anyone can verify a certificate, without an account, in three ways:
- upload the PDF;
- scan its QR code with the laptop webcam;
- enter its certificate ID.

> Academic prototype: not production PKI. See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Setup (Ubuntu 22.04+, Python 3.11+)

```bash
# if your system Python has no pip/venv:  sudo apt install python3-venv python3-pip
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env            # then edit: set QC_KEY_PASSPHRASE and QC_SESSION_SECRET
python -m cli.keys generate     # issuer key pair → keys/trusted_keys.json (public), keys/private/ (encrypted)
python -m cli.create_admin registrar
uvicorn app.main:app --port 8000
```

Open **http://localhost:8000**. Use `localhost`, not the LAN IP: browsers only allow webcam access on `https://` or `http://localhost`.

- **Issuer:**
  1. Log in via *Issuer login* → *Issue*.
  2. Fill in the form → *Sign & issue*.
  3. Preview the certificate → *Download PDF*.
  4. From the dashboard you can search and filter, view details (canonical bytes, digest, signature), revoke with a reason, and view the verification history.
- **Verifier:** go to *Verify a certificate*, then upload a PDF, start the webcam scanner and hold the certificate's QR code up to the camera, or type the ID.

## Live demo

```bash
python -m demo.make_samples     # issues 3 real certificates (one revoked, one expired) + 21 forged PDFs
python -m demo.run_demo -v      # verifies them all and prints a verdict table with reasons
python -m demo.run_demo --offline
python -m cli.verify demo/samples/00_genuine.pdf --pubkey keys/issuer.pub   # no server involved
```

Upload any file from `demo/samples/` at `/verify` to show the same results in the browser. The files are:

| Sample | Attack | Expected |
|---|---|---|
| `00_genuine` | untouched | VALID |
| `01a/b/c` | printed CGPA edited / name white-boxed and retyped / date and degree edited | INVALID |
| `01d` | forged second page appended to a genuine certificate | INVALID (rejected: more than 1 page) |
| `02` | embedded JSON edited | INVALID |
| `03` | payload edited, digest recomputed, new QR | INVALID |
| `04` | signature bytes flipped | INVALID |
| `05a/b` | attacker signs with their own SLH-DSA key (own key_id / claims the issuer's) | INVALID |
| `06` | genuine QR pasted on a fake | INVALID |
| `07a/b/c` | cert_id changed everywhere / in the QR only / in print only | INVALID |
| `08` | genuine, later revoked | REVOKED (signature still valid) |
| `09` | genuine, past expiry | EXPIRED (signature still valid) |
| `10a–f` | PNG renamed .pdf, truncated, encrypted, > 5 MB, 3 pages, scanned copy | INVALID (rejected safely) |

## How verification works

**PDF upload (full check).** Each step reports PASS / FAIL / N/A with a reason:
1. Format: a real PDF, ≤ 5 MB, exactly 1 page (extra pages would not be covered by the checks), not encrypted.
2. QR: the page is rendered and the QR decoded (OpenCV), giving `cert_id` and digest `d`.
3. Embedded data: `quantumcert.json` is present, its payload is well-formed, and it is already canonical.
4. Printed text: every field box on the page equals the signed payload, with no overlay shapes or extra images.
5. Integrity: SHA-256(canonical bytes) = QR digest = issuer record digest.
6. Signature: SLH-DSA verifies under the **trusted** key for `issuer_key_id`. Keys inside documents are ignored.
7. Record: the certificate exists in the issuer DB, and the stored record's own signature verifies.
8. Not revoked.
9. Not expired (UTC).

**Verdict precedence:** INVALID > UNKNOWN > REVOKED > EXPIRED > VALID. The signature result is always shown separately from the status.

**Webcam scanning.** The verify page opens the laptop webcam at HD resolution and shows a viewfinder square. About 8 times a second it sends a full-resolution crop around the square to `POST /verify/scan-frame`; every 3rd frame it sends the whole picture instead. The server decodes the frame with zxing-cpp, which handles small, blurry and low-contrast codes much better than browser-side JavaScript decoders, then discards it. Frames are never stored or logged. The PDF's QR uses error-correction level L, which keeps it at version 5 (37×37 modules), so each module is larger on camera.

**QR scan / ID (record-level check).** The server re-verifies the stored record's signature, compares the QR digest, and checks revocation and expiry. It then shows the signed data so the verifier can compare it with the paper copy.

## Project layout

```
app/crypto/slhdsa.py     the only module touching the SLH-DSA library (pqcrypto)
app/crypto/keys.py       key_id, encrypted private key, trusted keystore, rotation
app/core/payload.py      payload schema, normalisation, strict validation
app/core/canonical.py    RFC 8785 canonical bytes, SHA-256, base64url
app/core/pdfgen.py       fixed PDF template + embedded quantumcert.json
app/core/pdfread.py      upload limits, attachment, printed text, overlay heuristic
app/core/qr.py           verify URL, QR render/decode
app/core/verifier.py     the verification pipeline (pure; shared by web + offline CLI)
app/services/            issuance/revocation, DB lookup + verification history
app/routers/             public verify pages, JSON API, admin, auth
cli/                     keys, create_admin, offline verify
demo/tamper.py           every attack from the brief, as code
spike/                   day-1 library spike (NIST vectors, noble interop)
tests/                   124 tests (pytest)
docs/                    CANONICALIZATION, THREAT_MODEL, WHY_SLH_DSA
```

## Tests

```bash
pytest          # ~15 s
```

The suite covers:
- NIST ACVP SLH-DSA sigVer vectors;
- the context-string and pure-mode binding;
- key encryption and rotation;
- golden canonical bytes and digest, plus Unicode normalisation edge cases;
- PDF/QR round trips;
- **all 10 tamper scenarios, online and offline**;
- DB-tampering detection;
- the HTTP flow (auth, CSRF, issue → verify → revoke);
- an audit confirming no route or response leaks the private key.

## Library choice (day-1 spike)

`pqcrypto` 1.0.0 was chosen because:
- it exposes FIPS 205 SLH-DSA with a context string;
- it installs from a prebuilt wheel, with no compiler or cmake needed;
- it passes all 14 NIST ACVP sigVer vectors for SHA2-128s pure mode;
- its signatures interoperate with `@noble/post-quantum` in both directions.

`liboqs-python` was the fallback, but it needs cmake to build liboqs. To re-run the spike:
```bash
python spike/spike_slhdsa.py
cd spike && npm i @noble/post-quantum@0.7.1 && node noble_verify.mjs && cd .. && python spike/spike_slhdsa.py
```

See [docs/WHY_SLH_DSA.md](docs/WHY_SLH_DSA.md) for why a hash-based post-quantum signature was chosen, and its trade-offs.

## Configuration (`.env`)

| Variable | Default | Purpose |
|---|---|---|
| `QC_BASE_URL` | `http://localhost:8000` | Base of the URL printed in QR codes |
| `QC_DB_URL` | `sqlite:///./quantumcert.db` | Database |
| `QC_KEYS_DIR` | `keys` | Keystore + encrypted private keys |
| `QC_KEY_PASSPHRASE` | — | Decrypts the issuer key. Without it, issuing is disabled but verification still works. |
| `QC_SESSION_SECRET` | random per start | Signs admin session cookies |

