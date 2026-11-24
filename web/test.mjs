// Prova do core web: node test.mjs -> exit 0.
// Compat com o Python (usado pelo check.py): node test.mjs open ARQ SENHA | node test.mjs make ARQ SENHA
import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { bytesToHex, bytesToNumberLE } from "@noble/curves/utils.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { WIF } from "@scure/btc-signer";
import moneroTs from "monero-ts";
import { addresses, newSecrets, seal, unlock, unseal, withNotes } from "./src/wallet.js";

const KEY_ONE = { btc: "p2wpkh:KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn", eth: `${"00".repeat(31)}01` };

async function checkVectors() {
  const a = await addresses({ ...KEY_ONE, xmr: (await newSecrets()).xmr });
  assert.equal(a.btc, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
  assert.equal(a.eth, "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf");
}

/** Lição Coldcard: as 3 chaves têm que ser exatamente os blocos que crypto.getRandomValues serviu. */
async function checkEntropySource() {
  await newSecrets(); // aquece o WASM do monero-ts antes de interceptar
  const real = crypto.getRandomValues.bind(crypto);
  const served = [];
  crypto.getRandomValues = (arr) => {
    arr.fill(served.length + 1);
    served.push(Uint8Array.from(arr));
    return arr;
  };
  let keys;
  try {
    keys = await newSecrets();
  } finally {
    crypto.getRandomValues = real;
  }
  assert.deepEqual(served.map((b) => b.length), [32, 32, 32], "esperado 3x32 bytes do CSPRNG");
  const spend = await (await moneroTs.createWalletKeys({ networkType: 0, seed: keys.xmr, proxyToWorker: false })).getPrivateSpendKey();
  const reduced = (bytesToNumberLE(served[2]) % ed25519.Point.Fn.ORDER).toString(16);
  assert.equal(bytesToHex(WIF().decode(keys.btc.slice(7))), bytesToHex(served[0]));
  assert.equal(keys.eth, bytesToHex(served[1]));
  assert.equal(BigInt(`0x${Buffer.from(spend, "hex").reverse().toString("hex")}`).toString(16), reduced);
  const again = await newSecrets();
  assert.equal(new Set([...Object.values(keys), ...Object.values(again)]).size, 6, "chaves repetiram");
}

async function checkSeal() {
  const keys = await newSecrets();
  const wallet = await seal(keys, "çenha", "dica", true);
  assert.deepEqual(await unseal(wallet, "çenha"), keys);
  assert.deepEqual(wallet.addresses, await addresses(keys));
  assert.equal(wallet.xmr_view_key.length, 64);
  assert.ok(!JSON.stringify(wallet).includes(keys.xmr) && !JSON.stringify(wallet).includes(keys.eth));
  await assert.rejects(unseal(wallet, "errada"), /senha errada/);
}

async function checkNotes() {
  const keys = await newSecrets();
  const wallet = await seal(keys, "pw", "");
  assert.deepEqual(await unlock(wallet, "pw"), { keys, notes: "" });
  const first = await withNotes(wallet, "pw", "nota ç ✓");
  const second = await withNotes(first, "pw", "nota ç ✓");
  assert.deepEqual(first.aes_gcm, wallet.aes_gcm, "notas não podem mexer nas chaves");
  assert.notEqual(first.notes_gcm.nonce, second.notes_gcm.nonce, "nonce reusado com a mesma chave");
  assert.deepEqual(await unlock(second, "pw"), { keys, notes: "nota ç ✓" });
  await assert.rejects(withNotes(wallet, "errada", "x"), /senha errada/);
}

const [cmd, file, password] = process.argv.slice(2);
if (cmd === "open") {
  console.log(JSON.stringify(await unlock(JSON.parse(readFileSync(file, "utf8")), password)));
} else if (cmd === "make") {
  const made = await seal(await newSecrets(), password, "dica web", true);
  writeFileSync(file, JSON.stringify(await withNotes(made, password, "nota web ç ✓"), null, 2));
} else {
  await checkVectors();
  await checkEntropySource();
  await checkSeal();
  await checkNotes();
  console.log("web OK");
}
process.exit(0);
