import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const directory = process.argv[2];
const bindings = await import(pathToFileURL(resolve(directory, "nazgul.js")));
bindings.initSync({ module: await readFile(resolve(directory, "nazgul_bg.wasm")) });
assert.equal(bindings.hello(), "Hello from Nazgul!");

const { WasmKeyPair } = bindings;
const generated = WasmKeyPair.generate();
const bytes = WasmKeyPair.fromSecretBytes(generated.toSecretBytes());
const base58 = WasmKeyPair.fromSecretBase58(generated.toSecretBase58());
assert.equal(generated.getPublicBytes().length, 32);
assert.deepEqual(bytes.getPublicBytes(), generated.getPublicBytes());
assert.equal(base58.getPublicBase58(), generated.getPublicBase58());
assert.throws(() => WasmKeyPair.fromSecretBytes(new Uint8Array(31)));
assert.throws(() => WasmKeyPair.fromSecretBase58("!"));

const scalarOne = new Uint8Array(32);
scalarOne[0] = 1;
const basepoint = WasmKeyPair.fromSecretBytes(scalarOne);
assert.equal(
  Buffer.from(basepoint.getPublicBytes()).toString("hex"),
  "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
);
for (const key of [basepoint, base58, bytes, generated]) key.free();
console.log(`Verified the WasmKeyPair API in ${directory}`);
