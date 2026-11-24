// bun build.mjs -> dist/ (estático: GitHub Pages ou abrir local). Deps só do bun.lock, nada de CDN.
import { createHash } from "node:crypto";
import { cpSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
// Bug do polyfill node:assert do Bun (default vira o namespace): usa o pacote npm "assert" (CJS).
const assertCjs = {
  name: "assert-cjs",
  setup(build) {
    build.onResolve({ filter: /^(node:)?assert$/ }, () => ({ path: require.resolve("assert/") }));
  },
};

rmSync("dist", { recursive: true, force: true });
const result = await Bun.build({
  entrypoints: ["src/app.js"],
  outdir: "dist",
  target: "browser",
  format: "iife", // script clássico: <script type=module> é bloqueado em file:// (página offline)
  minify: true,
  external: ["child_process"], // só usado pelo MoneroWalletRpc (Node), nunca chamado no navegador
  plugins: [assertCjs],
});
if (!result.success) {
  console.error(result.logs.map(String).join("\n"));
  process.exit(1);
}
cpSync("index.html", "dist/index.html");
cpSync("node_modules/monero-ts/dist/monero.worker.js", "dist/monero.worker.js");
const sums = readdirSync("dist")
  .sort()
  .map((f) => `${createHash("sha256").update(readFileSync(`dist/${f}`)).digest("hex")}  ${f}`);
writeFileSync("dist/SHA256SUMS", `${sums.join("\n")}\n`);
console.log(sums.join("\n"));
