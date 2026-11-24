// Saldo via nós públicos com CORS + https (o navegador exige os dois). Sai: endereços BTC/ETH.
// XMR: wallet view-only do monero-ts roda aqui no navegador; o nó só serve blocos.
import moneroTs from "monero-ts";

export const NODES = {
  btc: ["https://mempool.space/api", "https://blockstream.info/api"],
  eth: [
    "https://ethereum-rpc.publicnode.com",
    "https://eth.drpc.org",
    "https://rpc.flashbots.net",
    "https://eth-mainnet.public.blastapi.io", // da lista do Cake Wallet
  ],
  xmr: ["https://xmr-node.cakewallet.com:18081", "https://node.sethforprivacy.com:443"],
};
const XMR_BLOCK_SECONDS = 120;
const XMR_MARGIN_BLOCKS = 720 * 3; // ~3 dias antes da criação

async function getJson(url, body) {
  const init = body && { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) };
  const res = await fetch(url, init);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

async function rpc(url, method, params = {}) {
  const reply = await getJson(url, { jsonrpc: "2.0", id: 1, method, params });
  if (reply.error) throw new Error(reply.error.message ?? JSON.stringify(reply.error));
  return reply.result;
}

export function amount(units, decimals) {
  const digits = BigInt(units).toString().padStart(decimals + 1, "0");
  const frac = digits.slice(-decimals).replace(/0+$/, "");
  return frac ? `${digits.slice(0, -decimals)}.${frac}` : digits.slice(0, -decimals);
}

async function btc(base, addr) {
  const { chain_stats: chain, mempool_stats: pool } = await getJson(`${base}/address/${addr}`);
  const pending = pool.funded_txo_sum - pool.spent_txo_sum;
  const confirmed = `${amount(chain.funded_txo_sum - chain.spent_txo_sum, 8)} BTC`;
  return pending ? `${confirmed} (+${amount(pending, 8)} pendente)` : confirmed;
}

async function eth(url, addr) {
  return `${amount(BigInt(await rpc(url, "eth_getBalance", [addr, "latest"])), 18)} ETH`;
}

async function xmr(node, wallet) {
  const { height } = await rpc(`${node}/json_rpc`, "get_info");
  const age = Math.floor((Date.now() / 1000 - wallet.created) / XMR_BLOCK_SECONDS);
  const restoreHeight = Math.max(0, height - age - XMR_MARGIN_BLOCKS);
  const view = await moneroTs.createWalletFull({
    networkType: moneroTs.MoneroNetworkType.MAINNET,
    password: "view-only",
    primaryAddress: wallet.addresses.xmr,
    privateViewKey: wallet.xmr_view_key,
    restoreHeight,
    server: { uri: node },
  });
  try {
    await view.sync();
    return `${amount(await view.getBalance(), 12)} XMR recebido (view-only não vê gastos; desde bloco ${restoreHeight})`;
  } finally {
    await view.close();
  }
}

export async function firstOk(fn, nodes, arg) {
  const errors = [];
  for (const node of nodes) {
    try {
      return `${await fn(node, arg)}  · via ${node}`;
    } catch (e) {
      errors.push(`${node}: ${e.message ?? e}`);
    }
  }
  return `falhou em todos: ${errors.join(" | ")}`;
}

const xmrLine = (wallet) =>
  "xmr_view_key" in wallet
    ? firstOk(xmr, NODES.xmr, wallet)
    : Promise.resolve("sem view key no arquivo (marque 'guardar view key XMR' ao gerar)");

/** Chama onUpdate a cada moeda que termina (BTC/ETH em segundos, XMR em minutos). */
export async function fillBalances(wallet, onUpdate) {
  const found = {};
  const done = (coin) => (text) => onUpdate({ ...Object.assign(found, { [coin]: text }) });
  await Promise.all([
    firstOk(btc, NODES.btc, wallet.addresses.btc).then(done("btc")),
    firstOk(eth, NODES.eth, wallet.addresses.eth).then(done("eth")),
    xmrLine(wallet).then(done("xmr")),
  ]);
}
