// E2E da página real (dist/) num navegador: node e2e.mjs PASTA_SAIDA [--online]
// Salva os .json baixados em PASTA_SAIDA (senha "senha-e2e") para o check.py abrir no Python.
import assert from "node:assert/strict";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { join, resolve } from "node:path";
import { chromium } from "playwright-core";

const [outDir, flag] = process.argv.slice(2);
const DIST = resolve("dist");
const PASSWORD = "senha-e2e";
const BROWSERS = [
  process.env.BROWSER_PATH,
  "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  "/usr/bin/google-chrome",
  "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
];
const TYPES = { ".html": "text/html", ".js": "text/javascript", ".json": "application/json" };

function serve() {
  const server = createServer((req, res) => {
    const file = join(DIST, decodeURIComponent(req.url.replace(/^\/wallet-gen\//, "/").split("?")[0]));
    const path = file.endsWith("/") ? join(file, "index.html") : file;
    if (!path.startsWith(DIST) || !existsSync(path)) return res.writeHead(404).end();
    res.writeHead(200, { "Content-Type": TYPES[path.slice(path.lastIndexOf("."))] ?? "application/octet-stream" });
    res.end(readFileSync(path));
  });
  return new Promise((ok) => server.listen(0, "127.0.0.1", () => ok(server)));
}

async function openPage(browser, url) {
  const page = await browser.newPage({ acceptDownloads: true });
  const errors = [];
  page.on("pageerror", (e) => errors.push(String(e)));
  page.on("console", (m) => m.type() === "error" && !m.text().includes("favicon") && errors.push(m.text()));
  await page.goto(url);
  return { page, errors, out: () => page.locator("#out").innerText() };
}

async function generate({ page, out }, saveAs) {
  await page.fill("#senha", PASSWORD);
  await page.fill("#confirmar", PASSWORD);
  await page.fill("#dica", "dica e2e");
  await page.check("#viewkey");
  const [download] = await Promise.all([page.waitForEvent("download"), page.click("#gerar")]);
  await download.saveAs(saveAs);
  assert.match(await out(), /Baixado: \d{4}-\d\d-\d\d_\d{6}\.json/);
  assert.equal(await page.inputValue("#senha"), "", "senha deveria ser limpa após gerar");
}

async function fullFlow(ctx) {
  const { page, out } = ctx;
  await page.fill("#senha", "a");
  await page.fill("#confirmar", "b");
  await page.click("#gerar");
  assert.match(await out(), /diferente da confirmação/);
  await page.click("#privadas");
  assert.match(await out(), /Abra um arquivo primeiro/);

  const file = join(outDir, "web-wallet.json");
  await generate(ctx, file);
  const wallet = JSON.parse(readFileSync(file, "utf8"));
  assert.ok(!(await out()).includes(wallet.addresses.btc), "endereço só deve aparecer abrindo o arquivo salvo");

  await page.setInputFiles("#arquivo", file);
  await page.waitForFunction(() => document.querySelector("#out").innerText.includes("XMR"));
  const shown = await out();
  assert.ok(Object.values(wallet.addresses).every((a) => shown.includes(a)) && !shown.includes("privada"));
  assert.equal(await page.innerText("#dica-aberta"), "Dica: dica e2e");

  await page.fill("#senha-abrir", "errada");
  await page.click("#privadas");
  await page.waitForFunction(() => /senha errada/.test(document.querySelector("#out").innerText));
  await page.fill("#senha-abrir", PASSWORD);
  await page.click("#privadas");
  await page.waitForFunction(() => document.querySelector("#out").innerText.includes("privada"));
  assert.match(await out(), /privada +p2wpkh:[KL]\w{51}/);

  assert.equal(await page.isDisabled("#notas"), false, "notas liberadas após Ver privadas");
  await page.fill("#notas", "nota e2e ç ✓");
  const [saved] = await Promise.all([page.waitForEvent("download"), page.click("#salvar-notas")]);
  await saved.saveAs(join(outDir, "web-wallet-notas.json"));
  assert.match(await out(), /Notas salvas/);

  await page.click("#publicas");
  assert.ok(await page.isDisabled("#notas"), "outra tela fecha o vault");
  assert.ok(await page.isDisabled("#salvar-notas"));

  await page.click("#sobre");
  assert.match(await out(), /crypto\.getRandomValues/);
  assert.match(await out(), /monero-ts 0\.11\.22/);
}

async function onlineBalances(ctx) {
  const control = {
    hint: "controle",
    created: Math.floor(Date.now() / 1000) - 7 * 86400,
    addresses: {
      btc: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
      eth: "0x00000000219ab540356cBB839Cbe05303d7705Fa",
      xmr: "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A",
    },
    xmr_view_key: "f359631075708155cc3d92a32b75a7d02a5dcf27756707b47a2b31b21c389501",
  };
  const file = join(outDir, "controle.json");
  writeFileSync(file, JSON.stringify(control));
  await ctx.page.setInputFiles("#arquivo", file);
  await ctx.page.click("#saldo");
  await ctx.page.waitForFunction(() => !document.querySelector("#out").innerText.includes("consultando"), null, {
    timeout: 600_000,
  });
  const lines = (await ctx.out()).split("\n").filter((l) => l.trim().startsWith("saldo"));
  console.log(lines.join("\n"));
  assert.equal(lines.length, 3);
  for (const l of lines) assert.ok(Number.parseFloat(l.trim().split(/\s+/)[1]) > 0, l);
}

const executablePath = BROWSERS.find((p) => p && existsSync(p));
assert.ok(executablePath, "nenhum Chrome/Brave encontrado (defina BROWSER_PATH)");
const browser = await chromium.launch({ executablePath, headless: true });
const server = await serve();
try {
  const http = await openPage(browser, `http://127.0.0.1:${server.address().port}/wallet-gen/`);
  await fullFlow(http);
  if (flag === "--online") await onlineBalances(http);
  assert.deepEqual(http.errors, [], "erros no console");

  const offline = await openPage(browser, `file://${join(DIST, "index.html")}`);
  await generate(offline, join(outDir, "web-wallet-offline.json"));
  assert.deepEqual(offline.errors, [], "erros no console (file://)");
  console.log("e2e OK");
} finally {
  await browser.close();
  server.close();
}
