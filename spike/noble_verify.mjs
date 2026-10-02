// Cross-implementation check: verify a pqcrypto (Rust) signature with @noble/post-quantum,
// then produce a noble signature for spike_slhdsa.py to verify.
import { readFileSync, writeFileSync } from 'node:fs';
import { slh_dsa_sha2_128s as slh } from '@noble/post-quantum/slh-dsa.js';

const hex = (s) => Uint8Array.from(Buffer.from(s, 'hex'));
const toHex = (b) => Buffer.from(b).toString('hex');

const py = JSON.parse(readFileSync(new URL('./out/py.json', import.meta.url)));
const ok = slh.verify(hex(py.sig), hex(py.msg), hex(py.pk), { context: hex(py.ctx) });
const wrongCtx = slh.verify(hex(py.sig), hex(py.msg), hex(py.pk), { context: new TextEncoder().encode('other') });
console.log(`[${ok ? 'PASS' : 'FAIL'}] pqcrypto signature verifies in noble`);
console.log(`[${!wrongCtx ? 'PASS' : 'FAIL'}] noble rejects it under a different ctx`);

const keys = slh.keygen();
const msg = new TextEncoder().encode('signed by noble');
const sig = slh.sign(msg, keys.secretKey, { context: hex(py.ctx) });
writeFileSync(new URL('./out/noble.json', import.meta.url),
  JSON.stringify({ pk: toHex(keys.publicKey), msg: toHex(msg), sig: toHex(sig), ctx: py.ctx }));
console.log('wrote spike/out/noble.json; re-run spike_slhdsa.py to verify it in pqcrypto');
process.exit(ok && !wrongCtx ? 0 : 1);
