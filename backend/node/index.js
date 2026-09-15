#!/usr/bin/env node
// Required CI/desktop parity backend. One JSON request per line.
const readline = require('readline');
const crypto = require('crypto');

function analyze(data) {
  const counts = new Array(256).fill(0); let printable = 0;
  for (const b of data) { counts[b]++; if ((b >= 0x20 && b <= 0x7e) || b === 9 || b === 10 || b === 13) printable++; }
  let entropy = 0;
  if (data.length) for (const c of counts) if (c) { const p = c / data.length; entropy -= p * Math.log2(p); }
  return { sha256: crypto.createHash('sha256').update(data).digest('hex'), bytes: data.length,
    entropy, printable: data.length ? printable * 100 / data.length : 0,
    binary: data.length > 0 && printable / data.length < 0.18 };
}

const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
rl.on('line', line => {
  try {
    const req = JSON.parse(line); const data = Buffer.from(req.dataBase64 || '', 'base64');
    if (!['analyze', 'sha256'].includes(req.op)) throw new Error('unsupported operation');
    const r = analyze(data);
    process.stdout.write(JSON.stringify(req.op === 'sha256' ? {sha256:r.sha256, bytes:r.bytes} : r) + '\n');
  } catch (e) { process.stdout.write(JSON.stringify({error: String(e.message || e)}) + '\n'); }
});
