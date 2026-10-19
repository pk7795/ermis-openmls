// Dummy fixture only. Do not pass production recovery keys or vaults to this tool.
// Usage: node interop.mjs <web-wasm-directory> <native-fixture.json> <web-fixture.json>
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { webcrypto } from 'node:crypto';

const [wasmDirectory, nativeFixture, webFixture] = process.argv.slice(2);
if (!wasmDirectory || !nativeFixture || !webFixture) {
  throw new Error('Required: web WASM directory, native fixture path, web fixture output path');
}
if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'epoch-archive-interop-'));
try {
  const glue = path.join(temporary, 'openmls.mjs');
  fs.copyFileSync(path.join(wasmDirectory, 'openmls_wasm.js'), glue);
  const wasm = await import(pathToFileURL(glue).href);
  wasm.initSync({ module: fs.readFileSync(path.join(wasmDirectory, 'openmls_wasm_bg.wasm')) });
  const provider = new wasm.Provider();
  const fixture = JSON.parse(fs.readFileSync(nativeFixture, 'utf8'));
  const bytes = value => new Uint8Array(value);
  const vault = wasm.WrappedRecoveryKey.from_bytes(new TextEncoder().encode(JSON.stringify(fixture.vault)));
  const privateKey = wasm.unwrap_recovery_private_key(provider, '12345678', vault);
  if (Buffer.compare(Buffer.from(privateKey), Buffer.from(fixture.keys.private_key))) throw new Error('Vault mismatch');
  const adk = wasm.unwrap_archive_data_key_from_parts(provider, privateKey, bytes(fixture.wrap.kem_output), bytes(fixture.wrap.ciphertext), bytes(fixture.wrap.hpke_info));
  const plaintext = wasm.decrypt_archive_blob(provider, adk, bytes(fixture.blob.ciphertext), bytes(fixture.blob.nonce), bytes(fixture.blob.aead_aad));
  if (new TextDecoder().decode(plaintext) !== 'cross-platform-recovery') throw new Error('Archive mismatch');
  const keys = wasm.generate_recovery_keypair(provider);
  const wrappedVault = wasm.wrap_recovery_private_key(provider, '12345678', keys.private_key, keys.public_key, keys.key_id, keys.ciphersuite, 600000);
  const aad = wasm.ArchiveBlobAad.forGeneration('messaging:interop', 3n, 7n, 'group_sponsored', 'web-blob', 'web-snapshot');
  const info = wasm.ArchiveKeyWrapInfo.forGeneration('messaging:interop', 3n, 7n, 'group_sponsored', 'web-blob', 'web-snapshot', keys.key_id);
  const blob = wasm.encrypt_archive_blob(provider, plaintext, aad);
  const wrap = wasm.wrap_archive_data_key(provider, blob.adk, keys.public_key, info);
  fs.writeFileSync(webFixture, JSON.stringify({
    keys: { private_key: [...keys.private_key], public_key: [...keys.public_key], key_id: keys.key_id, ciphersuite: keys.ciphersuite },
    vault: JSON.parse(new TextDecoder().decode(wrappedVault.to_bytes())),
    blob: { ciphertext: [...blob.ciphertext], nonce: [...blob.nonce], aead_aad: [...blob.aead_aad], adk: [...blob.adk] },
    wrap: { kem_output: [...wrap.kem_output], ciphertext: [...wrap.ciphertext], ciphersuite: wrap.ciphersuite, hpke_info: [...wrap.hpke_info] },
  }), { mode: 0o600 });
  console.log('native_to_web_passed');
} finally {
  fs.rmSync(temporary, { recursive: true, force: true });
}
