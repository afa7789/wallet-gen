// Core da web: mesmo formato de arquivo do app desktop (wallet_gen.py). Sem UI, sem rede.
import { ed25519 } from "@noble/curves/ed25519.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex, bytesToNumberLE, hexToBytes, numberToBytesLE } from "@noble/curves/utils.js";
import { scryptAsync } from "@noble/hashes/scrypt.js";
import { HDKey } from "@scure/bip32";
import { entropyToMnemonic, mnemonicToSeedSync } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { p2wpkh, WIF } from "@scure/btc-signer";
import { addr as ethAddr } from "micro-eth-signer";
import moneroTs from "monero-ts";

export const SCRYPT = { n: 2 ** 17, r: 8, p: 1 };
const XMR_ORDER = ed25519.Point.Fn.ORDER;

/** Única fonte de entropia: CSPRNG do navegador/SO. Teste intercepta esta chamada (lição Coldcard). */
const random = (n) => crypto.getRandomValues(new Uint8Array(n));

function secpKey() {
  const key = random(32);
  if (!secp256k1.utils.isValidSecretKey(key)) throw new Error("chave fora da curva, gere de novo");
  return key;
}

/** Sem worker: funciona também com a página aberta do disco (file://), offline. */
const xmrWallet = (config) =>
  moneroTs.createWalletKeys({ networkType: moneroTs.MoneroNetworkType.MAINNET, proxyToWorker: false, ...config });

/** Seed BIP39 -> BIP84 m/84'/0'/0'/0/0 -> WIF da chave do 1º endereço bc1q (import do Electrum). */
export function btcFromSeed(words) {
  const node = HDKey.fromMasterSeed(mnemonicToSeedSync(words)).derive("m/84'/0'/0'/0/0");
  return `p2wpkh:${WIF().encode(node.privateKey)}`;
}

/** BTC: seed BIP39 24 palavras (Cake/Sparrow) + WIF (Electrum). ETH: hex. XMR: 25 palavras; spend = 32 bytes mod l. */
export async function newSecrets() {
  const btcSeed = entropyToMnemonic(random(32), wordlist);
  const eth = bytesToHex(secpKey());
  const spend = numberToBytesLE(bytesToNumberLE(random(32)) % XMR_ORDER, 32);
  const xmr = await (await xmrWallet({ privateSpendKey: bytesToHex(spend), language: "English" })).getSeed();
  return { btc: btcFromSeed(btcSeed), btc_seed: btcSeed, eth, xmr };
}

export async function addresses(keys) {
  const btcKey = WIF().decode(keys.btc.replace(/^p2wpkh:/, ""));
  const xmr = await xmrWallet({ seed: keys.xmr });
  return {
    btc: p2wpkh(secp256k1.getPublicKey(btcKey, true)).address,
    eth: ethAddr.fromPrivateKey(keys.eth),
    xmr: await xmr.getPrimaryAddress(),
  };
}

const utf8 = (s) => new TextEncoder().encode(s);

async function aesKey(password, kdf) {
  const pw = utf8(password.normalize("NFC"));
  const raw = await scryptAsync(pw, hexToBytes(kdf.salt), { N: kdf.n, r: kdf.r, p: kdf.p, dkLen: 32 });
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}

/** AES-256-GCM, nonce novo (16 bytes) a cada chamada: nunca reusa nonce com a mesma chave. */
async function lock(key, plain) {
  const nonce = random(16);
  const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, plain));
  return { nonce: bytesToHex(nonce), data: bytesToHex(sealed.slice(0, -16)), tag: bytesToHex(sealed.slice(-16)) };
}

async function unlockBox(key, box) {
  const sealed = new Uint8Array([...hexToBytes(box.data), ...hexToBytes(box.tag)]);
  try {
    return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: hexToBytes(box.nonce) }, key, sealed));
  } catch {
    throw new Error("senha errada");
  }
}

export async function seal(keys, password, hint, keepViewKey = false) {
  const kdf = { ...SCRYPT, salt: bytesToHex(random(16)) };
  const box = await lock(await aesKey(password, kdf), utf8(JSON.stringify(keys)));
  const wallet = { hint, created: Math.floor(Date.now() / 1000), addresses: await addresses(keys), scrypt: kdf, aes_gcm: box };
  if (keepViewKey) wallet.xmr_view_key = await (await xmrWallet({ seed: keys.xmr })).getPrivateViewKey();
  return wallet;
}

/** { keys, notes } com uma derivação scrypt. Senha errada -> Error("senha errada"). Sem notas -> "". */
export async function unlock(wallet, password) {
  const key = await aesKey(password, wallet.scrypt);
  const keys = JSON.parse(new TextDecoder().decode(await unlockBox(key, wallet.aes_gcm)));
  const notes = wallet.notes_gcm ? new TextDecoder().decode(await unlockBox(key, wallet.notes_gcm)) : "";
  return { keys, notes };
}

export const unseal = async (wallet, password) => (await unlock(wallet, password)).keys;

/** Vault: notas cifradas com a mesma senha, no mesmo arquivo. Chaves (aes_gcm) intactas. */
export async function withNotes(wallet, password, notes) {
  const key = await aesKey(password, wallet.scrypt);
  await unlockBox(key, wallet.aes_gcm); // senha errada para aqui
  return { ...wallet, notes_gcm: await lock(key, utf8(notes)) };
}

export function fileName(date = new Date()) {
  const p = (n) => String(n).padStart(2, "0");
  const day = `${date.getFullYear()}-${p(date.getMonth() + 1)}-${p(date.getDate())}`;
  return `${day}_${p(date.getHours())}${p(date.getMinutes())}${p(date.getSeconds())}.json`;
}
