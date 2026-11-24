# /// script
# requires-python = "==3.12.*"
# dependencies = ["bip_utils==2.13.0"]
# ///
"""Gera 3 wallets (BTC, ETH, XMR) e salva as chaves privadas cifradas com senha.

Rodar: uv run wallet_gen.py                 (GUI)
       uv run wallet_gen.py --help          (CLI: gerar, lista, publicas, privadas, saldo, sobre)
Cada "Gerar novo" cria wallets/<data_hora>.json. Ver públicas / privadas / saldo escolhe qual ver.
Detalhes e disclosure: README.md.
"""

import argparse
import getpass
import json
import os
import platform
import secrets
import sys
import threading
import time
import tkinter as tk
import unicodedata
from importlib import metadata
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk

from bip_utils import (
    EthAddrEncoder,
    Monero,
    MoneroMnemonicGenerator,
    MoneroSeedGenerator,
    MoneroWordsNum,
    P2WPKHAddrEncoder,
    Secp256k1PrivateKey,
    WifDecoder,
    WifEncoder,
)
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt

import nodes


def _home() -> Path:
    """Executável one-file roda de pasta temporária: wallets lá sumiriam. Por isso:
    WALLET_GEN_HOME -> executável: ~/wallet-gen -> script: pasta do projeto."""
    if env := os.environ.get("WALLET_GEN_HOME"):
        return Path(env)
    if getattr(sys, "frozen", False):
        return Path.home() / "wallet-gen"
    return Path(__file__).resolve().parent


HOME = _home()
WALLETS_DIR = HOME / "wallets"
CONFIG_PATH = HOME / "config.json"
SCRYPT = {"n": 2**17, "r": 8, "p": 1}
CRYPTO_DEPS = ("bip_utils", "coincurve", "PyNaCl", "pycryptodome")
ABOUT = """wallet-gen — o que gera as chaves

ENTROPIA
  BTC  32 bytes   secrets.token_bytes -> os.urandom (CSPRNG do sistema operacional)
  ETH  32 bytes   secrets.token_hex   -> os.urandom
  XMR  256 bits   bip_utils MoneroEntropyGenerator -> os.urandom
  Não usa random/Math.random, mt19937, relógio como seed nem seed de 32 bits.
  Cada moeda tem chave própria e independente (sem BIP32/BIP39).

DERIVAÇÃO
  BTC  WIF comprimido mainnet -> P2WPKH bech32 (bc1q...)  secp256k1: coincurve (libsecp256k1)
  ETH  keccak256(pubkey)[12:] + checksum EIP-55          secp256k1: coincurve (libsecp256k1)
  XMR  seed legacy 25 palavras (inglês)                   ed25519: PyNaCl (libsodium)
       spend = sc_reduce32(seed), view = sc_reduce32(keccak256(spend))

ARQUIVO
  scrypt N={n} r={r} p={p}, sal 16 bytes -> AES-256-GCM, nonce 16 bytes (os.urandom)
  Senha normalizada NFC. Em texto aberto: dica, endereços, data de criação, parâmetros e,
  só se guardar_view_key_xmr=true no config.json, a view key PRIVADA do XMR (vê, não gasta).

PÓS-QUÂNTICO
  Arquivo usa só cripto simétrica: AES-256 (Grover -> ~128 bits pós-quântico) + scrypt.
  Não há etapa de chave pública no arquivo: ML-KEM e afins não teriam o que substituir.
  Limite real: força da senha. As moedas em si (secp256k1/ed25519) não são pós-quânticas.

SALDO (botão Ver saldo — único momento com rede)
  BTC  Esplora, envia o endereço
       {btc_nodes}
  ETH  eth_getBalance, envia o endereço
       {eth_nodes}
  XMR  monero-wallet-rpc oficial local + nó público; view key fica local
       {xmr_nodes}
       View-only: mostra recebido, não vê gastos.
  Nós do config.json vêm antes dos padrão; falhou um, tenta o próximo.
  Valor é palavra de terceiro. Consultar as 3 do mesmo IP liga elas entre si.

VERIFICAÇÃO (uv run check.py)
  Fonte: intercepta os.urandom e exige que as 3 chaves sejam os 3 blocos servidos (lição Coldcard).
  BTC/ETH contra vetores públicos (chave = 1). XMR contra lib independente monero-python.

EM USO AGORA
  Python {python} — {os}
  {versions}
  Pasta: {home}
"""


def about() -> str:
    versions = " | ".join(f"{dep} {metadata.version(dep)}" for dep in CRYPTO_DEPS)
    nos = {f"{coin}_nodes": ", ".join(urls) for coin, urls in load_config()["nos"].items()}
    return ABOUT.format(
        **SCRYPT,
        **nos,
        python=platform.python_version(),
        os=platform.platform(),
        versions=versions,
        home=HOME,
    )


def load_config() -> dict:
    """config.json opcional e tolerante: inválido ou ausente -> padrão (view key off, nós de nodes.py)."""
    try:
        user = json.loads(CONFIG_PATH.read_text())
        extra = user.get("nos", {})
        keep_view_key = user.get("guardar_view_key_xmr", False) is True
        nos = {coin: list(extra.get(coin, [])) + urls for coin, urls in nodes.DEFAULT_NODES.items()}
    except (OSError, ValueError, AttributeError, TypeError):
        keep_view_key, nos = False, nodes.DEFAULT_NODES
    return {"guardar_view_key_xmr": keep_view_key, "nos": nos}


def new_secrets() -> dict:
    """BTC: WIF no formato de import do Electrum. ETH: hex. XMR: seed de 25 palavras."""
    wif = WifEncoder.Encode(secrets.token_bytes(32))
    xmr = MoneroMnemonicGenerator().FromWordsNumber(MoneroWordsNum.WORDS_NUM_25)
    return {"btc": f"p2wpkh:{wif}", "eth": secrets.token_hex(32), "xmr": xmr.ToStr()}


def _xmr(keys: dict) -> Monero:
    return Monero.FromSeed(MoneroSeedGenerator(keys["xmr"]).Generate())


def addresses(keys: dict) -> dict:
    btc_key, _ = WifDecoder.Decode(keys["btc"].removeprefix("p2wpkh:"))
    btc_pub = Secp256k1PrivateKey.FromBytes(btc_key).PublicKey()
    eth_pub = Secp256k1PrivateKey.FromBytes(bytes.fromhex(keys["eth"])).PublicKey()
    return {
        "btc": P2WPKHAddrEncoder.EncodeKey(btc_pub, hrp="bc"),
        "eth": EthAddrEncoder.EncodeKey(eth_pub),
        "xmr": str(_xmr(keys).PrimaryAddress()),
    }


def _aes_key(password: str, kdf: dict) -> bytes:
    pw = unicodedata.normalize("NFC", password).encode()
    return scrypt(pw, bytes.fromhex(kdf["salt"]), 32, N=kdf["n"], r=kdf["r"], p=kdf["p"])


def seal(keys: dict, password: str, hint: str, keep_view_key: bool = False) -> dict:
    kdf = {**SCRYPT, "salt": secrets.token_hex(16)}
    cipher = AES.new(_aes_key(password, kdf), AES.MODE_GCM)
    data, tag = cipher.encrypt_and_digest(json.dumps(keys).encode())
    box = {"nonce": cipher.nonce.hex(), "data": data.hex(), "tag": tag.hex()}
    wallet = {
        "hint": hint,
        "created": int(time.time()),
        "addresses": addresses(keys),
        "scrypt": kdf,
        "aes_gcm": box,
    }
    if keep_view_key:  # opt-in: permite ver XMR recebido sem senha; não permite gastar
        wallet["xmr_view_key"] = _xmr(keys).PrivateViewKey().Raw().ToHex()
    return wallet


def unseal(wallet: dict, password: str) -> dict:
    """Senha errada -> ValueError."""
    box = {k: bytes.fromhex(v) for k, v in wallet["aes_gcm"].items()}
    cipher = AES.new(_aes_key(password, wallet["scrypt"]), AES.MODE_GCM, nonce=box["nonce"])
    return json.loads(cipher.decrypt_and_verify(box["data"], box["tag"]))


def save(wallet: dict, folder: Path = WALLETS_DIR) -> Path:
    folder.mkdir(mode=0o700, exist_ok=True)
    stem = time.strftime("%Y-%m-%d_%H%M%S")
    for n in range(1000):  # mesmo segundo -> -1, -2...; O_EXCL: nunca sobrescreve
        path = folder / (f"{stem}-{n}.json" if n else f"{stem}.json")
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            continue
        with os.fdopen(fd, "w") as f:
            json.dump(wallet, f, indent=2)
        return path
    raise FileExistsError(f"{folder}/{stem}*")


def rows(addrs: dict, keys: dict | None = None, balances: dict | None = None):
    """Mesmo layout na GUI e na CLI: (rótulo, valor, tag); rótulo vazio = cabeçalho da moeda."""
    for coin, addr in addrs.items():
        yield "", coin.upper(), coin
        yield "endereço", addr, "plain"
        if keys:
            yield "privada", keys[coin], "secret"
        if balances:
            yield "saldo", balances[coin], "plain"


COIN_COLORS = {"btc": "#f7931a", "eth": "#8a9cff", "xmr": "#ff6b2b"}


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("wallet-gen")
        self.screen = 0
        box = ttk.Frame(self, padding=20)
        box.pack(fill="both", expand=True)
        box.columnconfigure(1, weight=1)
        ttk.Label(box, text="wallet-gen", font=("Helvetica", 20, "bold")).grid(
            row=0, column=0, columnspan=3, sticky="w"
        )
        ttk.Label(
            box, text="BTC · ETH · XMR — chaves privadas cifradas com sua senha", foreground="gray"
        ).grid(row=1, column=0, columnspan=3, sticky="w", pady=(0, 14))
        self.fields = {}
        for row, (label, mask) in enumerate([("Senha", "•"), ("Confirmar", "•"), ("Dica", "")], start=2):
            ttk.Label(box, text=label).grid(row=row, column=0, sticky="e", padx=(0, 10), pady=4)
            self.fields[label] = ttk.Entry(box, show=mask, width=50)
            self.fields[label].grid(row=row, column=1, columnspan=2, sticky="we", pady=4)
        buttons = ttk.Frame(box)
        buttons.grid(row=5, column=1, columnspan=2, sticky="e", pady=(10, 14))
        ttk.Button(buttons, text="Sobre", command=self.view_about).pack(side="right", padx=(8, 0))
        ttk.Button(buttons, text="Ver saldo", command=self.view_balance).pack(side="right", padx=(8, 0))
        ttk.Button(buttons, text="Ver privadas", command=self.view_private).pack(side="right")
        ttk.Button(buttons, text="Ver públicas", command=self.view_public).pack(side="right", padx=8)
        ttk.Button(buttons, text="Gerar novo", command=self.generate, default="active").pack(side="right")
        self.out = tk.Text(
            box,
            width=100,
            height=16,
            wrap="word",
            font=("Menlo", 12),
            relief="flat",
            bg="#1e1e1e",
            fg="#e6e6e6",
            insertbackground="#e6e6e6",
            padx=14,
            pady=12,
        )
        self.out.grid(row=6, column=0, columnspan=3, sticky="nsew")
        box.rowconfigure(6, weight=1)
        self.out.tag_configure("dim", foreground="#8a8a8a")
        self.out.tag_configure("secret", foreground="#ff7b7b")
        for coin, color in COIN_COLORS.items():
            self.out.tag_configure(coin, foreground=color, font=("Menlo", 13, "bold"))

    def _clear(self) -> None:
        self.screen += 1  # tela nova: poll de saldo antigo para de redesenhar
        self.out.delete("1.0", "end")

    def show(self, title: str, addrs: dict, keys: dict | None = None, balances: dict | None = None) -> None:
        self._clear()
        self.out.insert("end", f"{title}\n", "dim")
        for label, value, tag in rows(addrs, keys, balances):
            if not label:
                self.out.insert("end", f"\n{value}\n", tag)
                continue
            self.out.insert("end", f"  {label:<9} ", "dim")
            self.out.insert("end", f"{value}\n", tag)

    def generate(self) -> None:
        pw = self.fields["Senha"].get()
        if not pw or pw != self.fields["Confirmar"].get():
            messagebox.showerror("Erro", "Senha vazia ou diferente da confirmação.")
            return
        keep_view_key = load_config()["guardar_view_key_xmr"]
        wallet = seal(new_secrets(), pw, self.fields["Dica"].get(), keep_view_key)
        note = " (view key XMR guardada em aberto)" if keep_view_key else ""
        self.show(f"Salvo em {save(wallet)}{note}", wallet["addresses"])

    def view_balance(self) -> None:
        if not (picked := self.pick()):
            return
        path, wallet = picked
        found: dict = {}
        args = (wallet, load_config()["nos"], found)
        threading.Thread(target=nodes.fill_balances, args=args, daemon=True).start()
        self._poll(path, wallet["addresses"], found, -1, self.screen)

    def _poll(self, path: str, addrs: dict, found: dict, shown: int, screen: int) -> None:
        """Rede roda em thread; a GUI só redesenha aqui, no thread do Tk, e só se a tela ainda é dela."""
        if screen != self.screen:
            return
        if len(found) != shown:
            self.show(path, addrs, balances={coin: found.get(coin, "consultando…") for coin in addrs})
        if len(found) < len(addrs):
            self.after(300, self._poll, path, addrs, found, len(found), self.screen)

    def view_about(self) -> None:
        self._clear()
        self.out.insert("end", about())

    def pick(self) -> tuple[str, dict] | None:
        path = filedialog.askopenfilename(initialdir=WALLETS_DIR, filetypes=[("wallets", "*.json")])
        return (path, json.loads(Path(path).read_text())) if path else None

    def view_public(self) -> None:
        if picked := self.pick():
            path, wallet = picked
            self.show(path, wallet["addresses"])

    def view_private(self) -> None:
        if not (picked := self.pick()):
            return
        path, wallet = picked
        pw = simpledialog.askstring("Senha", f"Dica: {wallet['hint']}\n\nSenha:", show="*", parent=self)
        if pw is None:
            return
        try:
            keys = unseal(wallet, pw)
        except ValueError:
            messagebox.showerror("Erro", "Senha errada.")
            return
        self.show(path, addresses(keys), keys)


def _ask(prompt: str) -> str:
    """Terminal: getpass (não ecoa). Pipe: lê uma linha do stdin (getpass trava no Windows com pipe).
    Senha nunca vai em argumento: ficaria no histórico do shell e na lista de processos."""
    if sys.stdin.isatty():
        return getpass.getpass(prompt)
    print(prompt, end="", file=sys.stderr, flush=True)
    line = sys.stdin.readline()
    if not line:
        raise SystemExit("erro: senha não recebida")
    return line.rstrip("\r\n")


def _open(name: str) -> tuple[Path, dict]:
    path = Path(name) if Path(name).exists() else WALLETS_DIR / name
    if not path.exists():
        raise SystemExit(f"erro: não achei {name} (nem em {WALLETS_DIR})")
    return path, json.loads(path.read_text())


def _print(title: str, addrs: dict, keys: dict | None = None, balances: dict | None = None) -> None:
    print(title)
    for label, value, _tag in rows(addrs, keys, balances):
        print(f"  {label:<9} {value}" if label else f"\n{value}")


def cmd_gerar(args) -> None:
    pw = _ask("Senha: ")
    if not pw or pw != _ask("Confirmar: "):
        raise SystemExit("erro: senha vazia ou diferente da confirmação")
    keep_view_key = load_config()["guardar_view_key_xmr"]
    wallet = seal(new_secrets(), pw, args.dica, keep_view_key)
    note = " (view key XMR guardada em aberto)" if keep_view_key else ""
    _print(f"Salvo em {save(wallet)}{note}", wallet["addresses"])


def cmd_lista(args) -> None:
    files = sorted(WALLETS_DIR.glob("*.json"))
    print("\n".join(f.name for f in files) if files else f"nenhuma wallet em {WALLETS_DIR}")


def cmd_publicas(args) -> None:
    path, wallet = _open(args.arquivo)
    _print(str(path), wallet["addresses"])


def cmd_privadas(args) -> None:
    path, wallet = _open(args.arquivo)
    print(f"Dica: {wallet['hint']}", file=sys.stderr)
    try:
        keys = unseal(wallet, _ask("Senha: "))
    except ValueError:
        raise SystemExit("erro: senha errada") from None
    _print(str(path), addresses(keys), keys)


def cmd_saldo(args) -> None:
    path, wallet = _open(args.arquivo)
    print("consultando nós públicos…", file=sys.stderr)
    found: dict = {}
    nodes.fill_balances(wallet, load_config()["nos"], found)
    _print(str(path), wallet["addresses"], balances=found)


def cmd_sobre(args) -> None:
    print(about())


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="wallet-gen", description="Wallets BTC/ETH/XMR. Sem comando: GUI.")
    parser.add_argument("--about", action="store_true", help="igual a 'sobre'")
    sub = parser.add_subparsers(metavar="comando")
    gerar = sub.add_parser("gerar", help="gera novo conjunto (pede a senha 2x)")
    gerar.add_argument("--dica", default="", help="dica da senha (fica em aberto no arquivo)")
    gerar.set_defaults(run=cmd_gerar)
    sub.add_parser("lista", help=f"lista as wallets em {WALLETS_DIR}").set_defaults(run=cmd_lista)
    for name, run, helptext in [
        ("publicas", cmd_publicas, "mostra endereços (sem senha)"),
        ("privadas", cmd_privadas, "mostra chaves privadas (pede a senha)"),
        ("saldo", cmd_saldo, "saldo via nós públicos (sem senha)"),
    ]:
        cmd = sub.add_parser(name, help=helptext)
        cmd.add_argument("arquivo", help="nome dentro de wallets/ ou caminho do .json")
        cmd.set_defaults(run=run)
    sub.add_parser("sobre", help="o que gera as chaves + versões em uso").set_defaults(run=cmd_sobre)
    args = parser.parse_args(argv)
    if args.about:
        args.run = cmd_sobre
    if hasattr(args, "run"):
        args.run(args)
    else:
        App().mainloop()


if __name__ == "__main__":
    main()
