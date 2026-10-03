import assert from "node:assert/strict";
import { readFileSync, unlinkSync } from "node:fs";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import test from "node:test";
import { PyRandom, MODELS, generate } from "../docs/lib/teletype.mjs";

const sha256 = bytes => createHash("sha256").update(bytes).digest("hex");

test("PyRandom reproduces Python's random.Random(1234)", () => {
  const r = new PyRandom(1234);
  assert.deepEqual([r.getrandbits(32), r.getrandbits(32), r.getrandbits(32)], [4150886329, 3342196574, 1892932127]);
  assert.equal(r.random().toFixed(17), "0.11685051774599753".slice(0, 19));
  assert.equal(r.randint(0, 99999), 11880);
  assert.equal(r.choice("ABCDEFGH"), "A");
});

// Reference SHA-256 of the patched tools/*.py output, captured for fixed seeds.
const REFERENCE = [
  { model: "asr33", seed: 1, size: 1048576, width: 72, parity: "space", sha256: "814124d0c79ba5c97d7b1e30c17998cf5584211af5175b5df0df7437b1471b30" },
  { model: "asr37", seed: 1, size: 1048576, width: 72, parity: "space", sha256: "d31fa9f8acd529aea990869bb16eb36716019339549be9e61282ef10fb347ab2" },
  { model: "asr33", seed: 42, size: 262144, width: 72, parity: "space", sha256: "16c477f6e62257187edb10401a39a37f68e8ff34755787c126900bf2472706a5" },
  { model: "asr37", seed: 42, size: 262144, width: 80, parity: "even", sha256: "0ec87faada870c42a0300c97a7686e15240c03486ffd177bc0120541607cf124" }
];

for (const c of REFERENCE) {
  test(`generate ${c.model} seed=${c.seed} matches the Python reference byte-for-byte`, () => {
    const { bytes } = generate(c.model, { seed: c.seed, size: c.size, width: c.width, parity: c.parity });
    assert.equal(bytes.length, c.size);
    assert.equal(sha256(bytes), c.sha256);
  });
}

test("every byte is 7-bit with space parity; even parity sets bit 8 correctly", () => {
  const space = generate("asr33", { seed: 7, size: 40000 }).bytes;
  assert.ok(space.every(b => b <= 0x7f), "space parity keeps the leading zero");
  const even = generate("asr33", { seed: 7, size: 40000, parity: "even" }).bytes;
  for (const b of even) {
    let ones = 0; for (let v = b; v; v >>= 1) ones += v & 1;
    assert.equal(ones % 2, 0);
  }
});

test("sessions include the Bisync framing layer, and cover the file", () => {
  for (const model of ["asr33", "asr37"]) {
    const { bytes, sessions } = generate(model, { seed: 3, size: 300000 });
    const types = new Set(sessions.map(s => s.type));
    assert.ok(types.has("bisync_block"), `${model} should emit bisync_block`);
    // a bisync block carries SYN SYN and an SOH header
    const first = sessions.find(s => s.type === "bisync_block");
    const slice = bytes.subarray(first.offset, first.offset + first.length);
    assert.ok(slice.includes(0x16), "SYN present");
    assert.ok(slice.includes(0x01), "SOH present");
    assert.ok(slice.includes(0x02) || slice.includes(0x10), "STX or DLE present");
  }
});

test("bad model, size and width are rejected", () => {
  assert.throws(() => generate("asr99", {}), RangeError);
  assert.throws(() => generate("asr33", { size: 1 }), RangeError);
  assert.throws(() => generate("asr37", { width: 40 }), RangeError);
  assert.equal(Object.keys(MODELS).length, 2);
});

// When Python is available, compare a fresh random seed directly (defence in depth).
const py = (() => { try { execFileSync("python3", ["--version"]); return true; } catch { return false; } })();
test("live parity with the Python scripts", { skip: (!py || !existsSync(new URL("../tools/asr33_gen.py", import.meta.url))) && "python3 or tools/*.py absent" }, () => {
  const seed = Math.floor(Math.random() * 2 ** 32);
  for (const model of ["asr33", "asr37"]) {
    const out = new URL(`../tools/.check_${model}.bin`, import.meta.url);
    execFileSync("python3", [new URL(`../tools/${model}_gen.py`, import.meta.url).pathname, "-o", out.pathname, "--size", "50000", "--seed", String(seed)]);
    const ref = readFileSync(out);
    unlinkSync(out);
    assert.equal(sha256(generate(model, { seed, size: 50000 }).bytes), sha256(ref));
  }
});
