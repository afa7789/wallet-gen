"""Saldo via nós públicos. Sai da máquina: endereços BTC/ETH. XMR: view key fica local
(monero-wallet-rpc roda aqui), o nó remoto só serve blocos.

Cada moeda tenta os nós em ordem (os do config.json primeiro); falha em todos -> "falhou".
"""

import atexit
import json
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request
from decimal import Decimal

DEFAULT_NODES = {
    "btc": ["https://mempool.space/api", "https://blockstream.info/api", "https://mempool.emzy.de/api"],
    "eth": [
        "https://ethereum-rpc.publicnode.com",
        "https://eth.drpc.org",
        "https://eth.merkle.io",
        "https://rpc.flashbots.net",
        "https://eth-mainnet.public.blastapi.io",  # da lista do Cake Wallet
    ],
    "xmr": [
        "xmr-node.cakewallet.com:18081",
        "node.sethforprivacy.com:18089",
        "node.monerodevs.org:18089",
        "nodes.hashvault.pro:18081",
        "xmr.stormycloud.org:18089",
        "monero.stackwallet.com:18081",
        "node2.monerodevs.org:18089",  # node2/node3: da lista do Cake Wallet
        "node3.monerodevs.org:18089",
    ],
}
TIMEOUT = 20
XMR_BLOCK_SECONDS = 120
XMR_MARGIN_BLOCKS = 720 * 3  # ~3 dias antes da criação: altura estimada nunca passa do 1º depósito


def _fetch(url: str, body: dict | None = None, timeout: float = TIMEOUT) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data, {"Content-Type": "application/json", "User-Agent": "wallet-gen"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


def _rpc(url: str, method: str, params: dict | list | None = None, timeout: float = TIMEOUT):
    reply = _fetch(url, {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}, timeout)
    if "error" in reply:
        raise RuntimeError(reply["error"].get("message", reply["error"]))
    return reply["result"]


def _amount(units: int, decimals: int) -> str:
    return f"{Decimal(units).scaleb(-decimals).normalize():f}"


def btc(base: str, addr: str) -> str:
    stats = _fetch(f"{base}/address/{addr}")
    chain, mempool = stats["chain_stats"], stats["mempool_stats"]
    confirmed = chain["funded_txo_sum"] - chain["spent_txo_sum"]
    pending = mempool["funded_txo_sum"] - mempool["spent_txo_sum"]
    return f"{_amount(confirmed, 8)} BTC" + (f" (+{_amount(pending, 8)} pendente)" if pending else "")


def eth(url: str, addr: str) -> str:
    return f"{_amount(int(_rpc(url, 'eth_getBalance', [addr, 'latest']), 16), 18)} ETH"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _restore_height(node: str, created: float) -> int:
    height = _rpc(f"http://{node}/json_rpc", "get_info")["height"]
    return max(0, height - int((time.time() - created) / XMR_BLOCK_SECONDS) - XMR_MARGIN_BLOCKS)


_RUNNING: dict[subprocess.Popen, str] = {}  # wallet-rpc vivo -> pasta temp (tem a view key)


def _stop(proc: subprocess.Popen, tmp: str) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill()
    shutil.rmtree(tmp, ignore_errors=True)
    _RUNNING.pop(proc, None)


@atexit.register
def _stop_all() -> None:
    """Fechar a janela no meio do sync: thread daemon morre sem finally; aqui nada fica órfão."""
    for proc, tmp in list(_RUNNING.items()):
        _stop(proc, tmp)


def xmr(node: str, wallet: dict) -> str:
    """View-only via monero-wallet-rpc oficial + nó remoto. Não vê gastos: mostra recebido."""
    restore = _restore_height(node, wallet["created"])
    port = _free_port()
    rpc = f"http://127.0.0.1:{port}/json_rpc"
    tmp = tempfile.mkdtemp()
    cmd = ["monero-wallet-rpc", "--daemon-address", node, "--rpc-bind-port", str(port), "--disable-rpc-login"]
    cmd += ["--wallet-dir", tmp, "--log-file", f"{tmp}/rpc.log", "--non-interactive"]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    _RUNNING[proc] = tmp
    try:
        _wait_ready(rpc, proc)
        keys = {"address": wallet["addresses"]["xmr"], "viewkey": wallet["xmr_view_key"]}
        _rpc(rpc, "generate_from_keys", {"filename": "v", "password": "", "restore_height": restore, **keys})
        _rpc(rpc, "refresh", {"start_height": restore}, timeout=1800)
        received = _rpc(rpc, "get_balance", {"account_index": 0})["balance"]
    finally:
        _stop(proc, tmp)
    return f"{_amount(received, 12)} XMR recebido (view-only não vê gastos; desde bloco {restore})"


def _wait_ready(rpc: str, proc: subprocess.Popen) -> None:
    for _ in range(60):
        if proc.poll() is not None:
            raise RuntimeError(f"monero-wallet-rpc saiu com código {proc.returncode}")
        try:
            _rpc(rpc, "get_version", timeout=2)
            return
        except OSError:
            time.sleep(0.5)
    raise RuntimeError("monero-wallet-rpc não respondeu")


def first_ok(fn, nodes: list[str], arg) -> str:
    errors = []
    for node in nodes:
        try:
            return f"{fn(node, arg)}  · via {node}"
        except Exception as e:  # qualquer falha de nó -> tenta o próximo
            errors.append(f"{node}: {e}")
    return "falhou em todos: " + " | ".join(errors)


def xmr_unavailable(wallet: dict) -> str | None:
    if "xmr_view_key" not in wallet:
        return "sem view key no arquivo (ative guardar_view_key_xmr no config.json e gere novo conjunto)"
    if not shutil.which("monero-wallet-rpc"):
        return "instale o monero oficial (brew install monero) para ver XMR"
    return None


def fill_balances(wallet: dict, nodes: dict, out: dict) -> None:
    """Preenche out[coin] conforme cada consulta termina (BTC/ETH rápidos, XMR por último)."""
    addrs = wallet["addresses"]
    out["btc"] = first_ok(btc, nodes["btc"], addrs["btc"])
    out["eth"] = first_ok(eth, nodes["eth"], addrs["eth"])
    out["xmr"] = xmr_unavailable(wallet) or first_ok(xmr, nodes["xmr"], wallet)
