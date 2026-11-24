// Core da web: mesmo formato de arquivo do app desktop (wallet_gen.py). Sem UI, sem rede.
import { ed25519 } from "@noble/curves/ed25519.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex, bytesToNumberLE, hexToBytes, numberToBytesLE } from "@noble/curves/utils.js";
import { scryptAsync } from "@noble/hashes/scrypt.js";
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

/** BTC: import Electrum (p2wpkh:WIF). ETH: hex. XMR: seed 25 palavras; spend = 32 bytes aleatórios mod l. */
export async function newSecrets() {
  const btc = `p2wpkh:${WIF().encode(secpKey())}`;
  const eth = bytesToHex(secpKey());
  const spend = numberToBytesLE(bytesToNumberLE(random(32)) % XMR_ORDER, 32);
  const xmr = await (await xmrWallet({ privateSpendKey: bytesToHex(spend), language: "English" })).getSeed();
  return { btc, eth, xmr };
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

async function aesKey(password, kdf, usage) {
  const pw = utf8(password.normalize("NFC"));
  const raw = await scryptAsync(pw, hexToBytes(kdf.salt), { N: kdf.n, r: kdf.r, p: kdf.p, dkLen: 32 });
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, [usage]);
}

export async function seal(keys, password, hint, keepViewKey = false) {
  const kdf = { ...SCRYPT, salt: bytesToHex(random(16)) };
  const nonce = random(16);
  const plain = utf8(JSON.stringify(keys));
  const key = await aesKey(password, kdf, "encrypt");
  const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, plain));
  const box = { nonce: bytesToHex(nonce), data: bytesToHex(sealed.slice(0, -16)), tag: bytesToHex(sealed.slice(-16)) };
  const wallet = { hint, created: Math.floor(Date.now() / 1000), addresses: await addresses(keys), scrypt: kdf, aes_gcm: box };
  if (keepViewKey) wallet.xmr_view_key = await (await xmrWallet({ seed: keys.xmr })).getPrivateViewKey();
  return wallet;
}

/** Senha errada -> Error("senha errada"). */
export async function unseal(wallet, password) {
  const box = wallet.aes_gcm;
  const key = await aesKey(password, wallet.scrypt, "decrypt");
  const sealed = new Uint8Array([...hexToBytes(box.data), ...hexToBytes(box.tag)]);
  try {
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: hexToBytes(box.nonce) }, key, sealed);
    return JSON.parse(new TextDecoder().decode(plain));
  } catch {
    throw new Error("senha errada");
  }
}

export function fileName(date = new Date()) {
  const p = (n) => String(n).padStart(2, "0");
  const day = `${date.getFullYear()}-${p(date.getMonth() + 1)}-${p(date.getDate())}`;
  return `${day}_${p(date.getHours())}${p(date.getMinutes())}${p(date.getSeconds())}.json`;
}
