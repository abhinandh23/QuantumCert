"""Day-1 library spike: does pqcrypto expose FIPS 205 SLH-DSA-SHA2-128s with a context string?

Checks (a) sizes, (b) ctx round trip, (c) timings, (d) NIST ACVP sigVer vectors,
and writes spike/out/* so noble_verify.mjs can cross-check (e) against @noble/post-quantum.
"""
import json
import statistics
import sys
import time
from pathlib import Path

from pqcrypto.sign import slh_dsa_sha2_128s as slh

HERE = Path(__file__).parent
CTX = b"QuantumCert-v1"
ok = True


def check(name, cond):
    global ok
    ok &= bool(cond)
    print(f"[{'PASS' if cond else 'FAIL'}] {name}")


def verifies(pk, msg, sig, ctx):
    try:
        slh.verify(pk, msg, sig, ctx)
        return True
    except Exception:
        return False


# (a) sizes
pk, sk = slh.keygen()
check(f"sizes pk={len(pk)} sk={len(sk)} (expect 32/64)", (len(pk), len(sk)) == (32, 64))

# (b) context round trip
msg = b'{"hello":"world"}'
sig = slh.sign(sk, msg, CTX)
check(f"sig size {len(sig)} (expect 7856)", len(sig) == 7856)
check("verify with ctx QuantumCert-v1", verifies(pk, msg, sig, CTX))
check("verify with wrong ctx fails", not verifies(pk, msg, sig, b"QuantumCert-v2"))
check("verify with empty ctx fails", not verifies(pk, msg, sig, b""))
check("verify with modified msg fails", not verifies(pk, msg + b" ", sig, CTX))
check("signing is randomized (hedged) by default", slh.sign(sk, msg, CTX) != sig)

# (c) timings
def timeit(fn, n=5):
    ts = []
    for _ in range(n):
        t = time.perf_counter()
        fn()
        ts.append(time.perf_counter() - t)
    return statistics.median(ts) * 1000

print(f"  keygen median {timeit(slh.keygen):.1f} ms")
t_sign = timeit(lambda: slh.sign(sk, msg, CTX))
print(f"  sign   median {t_sign:.1f} ms")
print(f"  verify median {timeit(lambda: slh.verify(pk, msg, sig, CTX)):.2f} ms")
check("sign under 2 s", t_sign < 2000)

# (d) NIST ACVP sigVer vectors (SLH-DSA-SHA2-128s, external interface, pure)
vec = json.loads((HERE / "vectors" / "slhdsa_sha2_128s_sigver_pure.json").read_text())
grp = vec["group"]
bad = 0
for t in grp["tests"]:
    got = verifies(bytes.fromhex(t["pk"]), bytes.fromhex(t["message"]),
                   bytes.fromhex(t["signature"]), bytes.fromhex(t["context"]))
    if got != t["testPassed"]:
        bad += 1
        print(f"    tcId {t['tcId']}: expected {t['testPassed']} got {got} ({t['reason']})")
check(f"NIST ACVP sigVer {grp['parameterSet']} {grp['preHash']}: "
      f"{len(grp['tests']) - bad}/{len(grp['tests'])} match", bad == 0)

# (e) write artefacts for the noble cross-check
out = HERE / "out"
out.mkdir(exist_ok=True)
(out / "py.json").write_text(json.dumps({"pk": pk.hex(), "msg": msg.hex(), "sig": sig.hex(), "ctx": CTX.hex()}))
print("  wrote spike/out/py.json for noble_verify.mjs")

# if noble already produced a signature, verify it here
noble = out / "noble.json"
if noble.exists():
    n = json.loads(noble.read_text())
    check("noble signature verifies in pqcrypto",
          verifies(bytes.fromhex(n["pk"]), bytes.fromhex(n["msg"]), bytes.fromhex(n["sig"]), bytes.fromhex(n["ctx"])))

print("\nSPIKE", "PASSED" if ok else "FAILED")
sys.exit(0 if ok else 1)
