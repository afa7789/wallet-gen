// UI da página. Conteúdo do arquivo aberto (dica, endereços) só entra via textContent: nunca HTML.
import "./shim.js";
import moneroTs from "monero-ts";
import pkg from "../package.json" with { type: "json" };
import { fillBalances, NODES } from "./nodes.js";
import { addresses, fileName, newSecrets, SCRYPT, seal, unseal } from "./wallet.js";

moneroTs.LibraryUtils.setWorkerDistPath(new URL("monero.worker.js", document.baseURI).href);

const $ = (id) => document.getElementById(id);
const out = $("out");
let opened = null; // { name, wallet }
let screen = 0; // tela atual: saldo antigo não redesenha por cima de outra

function* rows(addrs, keys, balances) {
  for (const [coin, addr] of Object.entries(addrs)) {
    yield ["", coin.toUpperCase(), coin];
    yield ["endereço", addr, ""];
    if (keys) yield ["privada", keys[coin], "secret"];
    if (balances) yield ["saldo", balances[coin] ?? "consultando…", ""];
  }
}

function line(text, cls = "") {
  const div = document.createElement("div");
  div.textContent = text;
  div.className = cls;
  out.append(div);
}

function draw(title, addrs, keys, balances) {
  out.replaceChildren();
  line(title, "dim");
  for (const [label, value, cls] of rows(addrs, keys, balances)) {
    if (label) line(`  ${label.padEnd(9)} ${value}`, cls);
    else line(`\n${value}`, `coin ${cls}`);
  }
}

function render(...args) {
  screen += 1;
  draw(...args);
}

function message(text, cls = "") {
  screen += 1;
  out.replaceChildren();
  line(text, cls);
}

function need() {
  if (!opened) throw new Error('Abra um arquivo primeiro ("Abrir wallet").');
  return opened;
}

async function generate() {
  const pw = $("senha").value;
  if (!pw || pw !== $("confirmar").value) throw new Error("Senha vazia ou diferente da confirmação.");
  message("Gerando e cifrando (scrypt leva alguns segundos)…", "dim");
  const wallet = await seal(await newSecrets(), pw, $("dica").value, $("viewkey").checked);
  const name = fileName();
  const link = Object.assign(document.createElement("a"), {
    href: URL.createObjectURL(new Blob([JSON.stringify(wallet, null, 2)], { type: "application/json" })),
    download: name,
  });
  link.click();
  URL.revokeObjectURL(link.href);
  $("senha").value = $("confirmar").value = "";
  message(`Baixado: ${name}\n\nGuarde esse arquivo: sem ele (e a senha) as chaves se perdem.\nPara ver os endereços, abra o arquivo em "Abrir wallet".`);
}

async function openFile(file) {
  opened = { name: file.name, wallet: JSON.parse(await file.text()) };
  $("dica-aberta").textContent = `Dica: ${opened.wallet.hint || "(sem dica)"}`;
  render(opened.name, opened.wallet.addresses);
}

async function privates() {
  const { name, wallet } = need();
  message("Decifrando…", "dim");
  const keys = await unseal(wallet, $("senha-abrir").value);
  $("senha-abrir").value = "";
  render(name, await addresses(keys), keys);
}

async function balances() {
  const { name, wallet } = need();
  render(name, wallet.addresses, undefined, {});
  const mine = screen;
  await fillBalances(wallet, (found) => screen === mine && draw(name, wallet.addresses, undefined, found));
}

function about() {
  const libs = Object.entries(pkg.dependencies).map(([lib, v]) => `${lib} ${v}`).join(" | ");
  const nodes = Object.entries(NODES).map(([coin, urls]) => `  ${coin.toUpperCase()}  ${urls.join(", ")}`);
  message(
    [
      "wallet-gen (web) — o que gera as chaves",
      "",
      "ENTROPIA",
      "  32 bytes por moeda de crypto.getRandomValues (CSPRNG do navegador/SO). Nada feito à mão.",
      "  XMR: os 32 bytes mod l viram a spend key; monero-ts gera a seed de 25 palavras.",
      "",
      "DERIVAÇÃO",
      "  BTC  @scure/btc-signer: WIF comprimido + P2WPKH bech32 (bc1q...)   curva: @noble/curves",
      "  ETH  micro-eth-signer: keccak256 + checksum EIP-55",
      "  XMR  monero-ts (oficial da comunidade): seed, endereço, view key",
      "",
      "ARQUIVO (mesmo formato do app desktop)",
      `  scrypt N=${SCRYPT.n} r=${SCRYPT.r} p=${SCRYPT.p} (@noble/hashes) -> AES-256-GCM (WebCrypto). Senha NFC.`,
      "  Em aberto: dica, endereços, data e, se marcado, a view key PRIVADA do XMR (vê, não gasta).",
      "",
      "PÓS-QUÂNTICO",
      "  Só cripto simétrica: AES-256 (Grover -> ~128 bits). Limite real: força da senha.",
      "",
      "SALDO (único momento com rede; envia endereços; valor é palavra de terceiro)",
      ...nodes,
      "  XMR: view-only roda aqui no navegador, mostra recebido (não vê gastos).",
      "",
      "LIBS (versões travadas no bun.lock)",
      `  ${libs}`,
    ].join("\n"),
  );
}

function action(fn) {
  return async (event) => {
    for (const b of document.querySelectorAll("button")) b.disabled = true;
    try {
      await fn(event);
    } catch (e) {
      message(e.message ?? String(e), "error");
    } finally {
      for (const b of document.querySelectorAll("button")) b.disabled = false;
    }
  };
}

$("gerar").onclick = action(generate);
$("arquivo").onchange = action((e) => e.target.files[0] && openFile(e.target.files[0]));
$("publicas").onclick = action(() => render(need().name, need().wallet.addresses));
$("privadas").onclick = action(privates);
$("saldo").onclick = action(balances);
$("sobre").onclick = action(about);
