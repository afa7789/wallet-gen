// Prova do core web: node test.mjs -> exit 0.
// Compat com o Python (usado pelo check.py): node test.mjs open ARQ SENHA | node test.mjs make ARQ SENHA
import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { bytesToHex, bytesToNumberLE } from "@noble/curves/utils.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import moneroTs from "monero-ts";
import { mnemonicToEntropy } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { addresses, btcFromSeed, newSecrets, seal, unlock, unseal, withNotes } from "./src/wallet.js";

const KEY_ONE = { btc: "p2wpkh:KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn", eth: `${"00".repeat(31)}01` };

async function checkVectors() {
  const a = await addresses({ ...KEY_ONE, xmr: (await newSecrets()).xmr });
  assert.equal(a.btc, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
  assert.equal(a.eth, "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf");
  const bip84 = `${"abandon ".repeat(11)}about`; // vetor oficial do BIP84
  assert.equal(btcFromSeed(bip84), "p2wpkh:KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d");
  assert.equal((await addresses({ ...KEY_ONE, btc: btcFromSeed(bip84), xmr: (await newSecrets()).xmr })).btc,
    "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
}

/** Serve blocos fixos: 32 bytes = entropia (1, 2, 3...); outros tamanhos = valor `blinding`. */
async function generateWith(blinding) {
  const real = crypto.getRandomValues.bind(crypto);
  const served = [];
  crypto.getRandomValues = (arr) => {
    arr.fill(arr.length === 32 ? served.filter((b) => b.length === 32).length + 1 : blinding);
    served.push(Uint8Array.from(arr));
    return arr;
  };
  try {
    return { keys: await newSecrets(), served };
  } finally {
    crypto.getRandomValues = real;
  }
}

/** Lição Coldcard: as 3 chaves têm que ser exatamente os blocos de 32 bytes do CSPRNG.
 * @noble/curves também pede 16 bytes por multiplicação (blinding contra canal lateral): provamos que
 * isso não muda a saída — mesma entropia + blinding diferente = chaves idênticas. */
async function checkEntropySource() {
  await newSecrets(); // aquece o WASM do monero-ts antes de interceptar
  const a = await generateWith(0xaa);
  const b = await generateWith(0x55);
  const entropy = a.served.filter((x) => x.length === 32);
  assert.equal(entropy.length, 3, "esperado 3x32 bytes de entropia do CSPRNG");
  assert.ok(a.served.every((x) => x.length === 32 || x.length === 16), "só 32 (entropia) ou 16 (blinding)");
  assert.deepEqual(a.keys, b.keys, "blinding mudou a chave: a saída não depende só da entropia");
  const { keys } = a;
  const spend = await (await moneroTs.createWalletKeys({ networkType: 0, seed: keys.xmr, proxyToWorker: false })).getPrivateSpendKey();
  const reduced = (bytesToNumberLE(entropy[2]) % ed25519.Point.Fn.ORDER).toString(16);
  assert.equal(bytesToHex(mnemonicToEntropy(keys.btc_seed, wordlist)), bytesToHex(entropy[0]));
  assert.equal(keys.btc_seed.split(" ").length, 24);
  assert.equal(keys.btc, btcFromSeed(keys.btc_seed), "WIF não é a chave da seed");
  assert.equal(keys.eth, bytesToHex(entropy[1]));
  assert.equal(BigInt(`0x${Buffer.from(spend, "hex").reverse().toString("hex")}`).toString(16), reduced);
  const again = await newSecrets();
  assert.equal(new Set([...Object.values(keys), ...Object.values(again)]).size, 8, "chaves repetiram");
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
