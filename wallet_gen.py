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
    Bip39MnemonicGenerator,
    Bip39SeedGenerator,
    Bip44Changes,
    Bip84,
    Bip84Coins,
    EthAddrEncoder,
    Monero,
    MoneroMnemonicGenerator,
    MoneroSeedGenerator,
    MoneroWordsNum,
    P2WPKHAddrEncoder,
    Secp256k1PrivateKey,
    WifDecoder,
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
  BTC  32 bytes   secrets.token_bytes -> os.urandom (CSPRNG do sistema operacional) = seed BIP39
  ETH  32 bytes   secrets.token_hex   -> os.urandom
  XMR  256 bits   bip_utils MoneroEntropyGenerator -> os.urandom
  Não usa random/Math.random, mt19937, relógio como seed nem seed de 32 bits.
  Cada moeda tem chave própria e independente (sem BIP32/BIP39).

DERIVAÇÃO
  BTC  seed BIP39 24 palavras -> BIP84 m/84'/0'/0'/0/0 -> P2WPKH bc1q...  secp256k1: coincurve
       arquivo guarda a seed (Cake, Sparrow) e a WIF da mesma chave (Electrum: p2wpkh:...)
  ETH  keccak256(pubkey)[12:] + checksum EIP-55          secp256k1: coincurve (libsecp256k1)
  XMR  seed legacy 25 palavras (inglês)                   ed25519: PyNaCl (libsodium)
       spend = sc_reduce32(seed), view = sc_reduce32(keccak256(spend))

ARQUIVO
  scrypt N={n} r={r} p={p}, sal 16 bytes -> AES-256-GCM, nonce 16 bytes (os.urandom)
  Senha normalizada NFC. Em texto aberto: dica, endereços, data de criação, parâmetros e,
  só se guardar_view_key_xmr=true no config.json, a view key PRIVADA do XMR (vê, não gasta).
  Notas (vault): mesma chave da senha, nonce novo a cada gravação; chaves nunca regravadas.

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


def btc_from_seed(words: str) -> str:
    """Seed BIP39 -> BIP84 m/84'/0'/0'/0/0 -> WIF da chave do 1º endereço bc1q (import do Electrum)."""
    seed = Bip39SeedGenerator(words).Generate()
    node = Bip84.FromSeed(seed, Bip84Coins.BITCOIN).Purpose().Coin().Account(0)
    return f"p2wpkh:{node.Change(Bip44Changes.CHAIN_EXT).AddressIndex(0).PrivateKey().ToWif()}"


def new_secrets() -> dict:
    """BTC: seed BIP39 24 palavras (Cake/Sparrow) + WIF da mesma chave (Electrum). ETH: hex. XMR: 25."""
    btc_seed = Bip39MnemonicGenerator().FromEntropy(secrets.token_bytes(32)).ToStr()
    xmr = MoneroMnemonicGenerator().FromWordsNumber(MoneroWordsNum.WORDS_NUM_25)
    return {
        "btc": btc_from_seed(btc_seed),
        "btc_seed": btc_seed,
        "eth": secrets.token_hex(32),
        "xmr": xmr.ToStr(),
    }


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


def _lock(key: bytes, plain: bytes) -> dict:
    """AES-256-GCM com nonce novo (16 bytes, os.urandom) a cada chamada: nunca reusa nonce."""
    cipher = AES.new(key, AES.MODE_GCM)
    data, tag = cipher.encrypt_and_digest(plain)
    return {"nonce": cipher.nonce.hex(), "data": data.hex(), "tag": tag.hex()}


def _unlock_box(key: bytes, box: dict) -> bytes:
    raw = {k: bytes.fromhex(v) for k, v in box.items()}
    return AES.new(key, AES.MODE_GCM, nonce=raw["nonce"]).decrypt_and_verify(raw["data"], raw["tag"])


def seal(keys: dict, password: str, hint: str, keep_view_key: bool = False) -> dict:
    kdf = {**SCRYPT, "salt": secrets.token_hex(16)}
    wallet = {
        "hint": hint,
        "created": int(time.time()),
        "addresses": addresses(keys),
        "scrypt": kdf,
        "aes_gcm": _lock(_aes_key(password, kdf), json.dumps(keys).encode()),
    }
    if keep_view_key:  # opt-in: permite ver XMR recebido sem senha; não permite gastar
        wallet["xmr_view_key"] = _xmr(keys).PrivateViewKey().Raw().ToHex()
    return wallet


def unlock(wallet: dict, password: str) -> tuple[dict, str]:
    """(chaves, notas) com uma derivação scrypt só. Senha errada -> ValueError. Sem notas -> ""."""
    key = _aes_key(password, wallet["scrypt"])
    keys = json.loads(_unlock_box(key, wallet["aes_gcm"]))
    notes = _unlock_box(key, wallet["notes_gcm"]).decode() if "notes_gcm" in wallet else ""
    return keys, notes


def unseal(wallet: dict, password: str) -> dict:
    return unlock(wallet, password)[0]


def with_notes(wallet: dict, password: str, notes: str) -> dict:
    """Vault: notas cifradas com a mesma senha, no mesmo arquivo. Chaves (aes_gcm) intactas."""
    key = _aes_key(password, wallet["scrypt"])
    _unlock_box(key, wallet["aes_gcm"])  # senha errada para aqui, antes de gravar qualquer coisa
    return {**wallet, "notes_gcm": _lock(key, notes.encode())}


def rewrite(path: Path, wallet: dict) -> None:
    """Atualiza arquivo existente de forma atômica (tmp 0600 + rename): queda no meio não corrompe."""
    tmp = path.with_name(f".{path.name}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(wallet, f, indent=2)
    os.replace(tmp, path)


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
        if keys and keys.get(f"{coin}_seed"):  # BTC de conjuntos novos: seed BIP39 (arquivos antigos: só WIF)
            yield "seed", keys[f"{coin}_seed"], "secret"
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
            height=13,
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
        hint = "Notas (cifradas com a mesma senha, no mesmo arquivo) — liberadas em Ver privadas"
        ttk.Label(box, text=hint, foreground="gray").grid(
            row=7, column=0, columnspan=3, sticky="w", pady=(12, 4)
        )
        self.notes = tk.Text(
            box, width=100, height=6, wrap="word", font=("Menlo", 12), relief="flat", padx=14
        )
        self.notes.grid(row=8, column=0, columnspan=3, sticky="nsew")
        self.save_notes_btn = ttk.Button(box, text="Salvar notas", command=self.save_notes)
        self.save_notes_btn.grid(row=9, column=2, sticky="e", pady=(8, 0))
        self.vault: tuple[Path, str] | None = None  # (arquivo, senha) só enquanto as privadas estão abertas
        self._lock_notes()

    def _lock_notes(self) -> None:
        self.vault = None
        self.notes.configure(state="normal")
        self.notes.delete("1.0", "end")
        self.notes.configure(state="disabled")
        self.save_notes_btn.configure(state="disabled")

    def _open_notes(self, path: str, password: str, notes: str) -> None:
        self.vault = (Path(path), password)
        self.notes.configure(state="normal")
        self.notes.insert("1.0", notes)
        self.save_notes_btn.configure(state="normal")

    def save_notes(self) -> None:
        if not self.vault:
            return
        path, password = self.vault
        rewrite(path, with_notes(json.loads(path.read_text()), password, self.notes.get("1.0", "end-1c")))
        self.out.insert("end", f"\nNotas salvas (cifradas) em {path}\n", "dim")

    def _clear(self) -> None:
        self.screen += 1  # tela nova: poll de saldo antigo para de redesenhar
        self._lock_notes()  # qualquer outra tela fecha o vault
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
        self._lock_notes()  # outro arquivo: vault anterior fecha antes de pedir senha
        pw = simpledialog.askstring("Senha", f"Dica: {wallet['hint']}\n\nSenha:", show="*", parent=self)
        if pw is None:
            return
        try:
            keys, notes = unlock(wallet, pw)
        except ValueError:
            messagebox.showerror("Erro", "Senha errada.")
            return
        self.show(path, addresses(keys), keys)
        self._open_notes(path, pw, notes)


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


def _text(title: str, addrs: dict, keys: dict | None = None, balances: dict | None = None) -> str:
    lines = [title]
    for label, value, _tag in rows(addrs, keys, balances):
        lines.append(f"  {label:<9} {value}" if label else f"\n{value}")
    return "\n".join(lines)


def _emit(args, data: dict, human: str) -> None:
    """--json: um objeto JSON por comando no stdout (para agentes/scripts). Senão: texto legível."""
    print(json.dumps(data, ensure_ascii=False) if args.json else human)


def _unlock_cli(args) -> tuple[Path, dict, str, dict, str]:
    path, wallet = _open(args.arquivo)
    print(f"Dica: {wallet['hint']}", file=sys.stderr)
    password = _ask("Senha: ")
    try:
        keys, notes = unlock(wallet, password)
    except ValueError:
        raise SystemExit("erro: senha errada") from None
    return path, wallet, password, keys, notes


def cmd_gerar(args) -> None:
    pw = _ask("Senha: ")
    if not pw or pw != _ask("Confirmar: "):
        raise SystemExit("erro: senha vazia ou diferente da confirmação")
    keep_view_key = args.guardar_view_key or load_config()["guardar_view_key_xmr"]
    wallet = seal(new_secrets(), pw, args.dica, keep_view_key)
    path = save(wallet)
    data = {"arquivo": str(path), "enderecos": wallet["addresses"], "view_key_guardada": keep_view_key}
    note = " (view key XMR guardada em aberto)" if keep_view_key else ""
    _emit(args, data, _text(f"Salvo em {path}{note}", wallet["addresses"]))


def cmd_lista(args) -> None:
    files = [f.name for f in sorted(WALLETS_DIR.glob("*.json"))]
    _emit(
        args,
        {"pasta": str(WALLETS_DIR), "arquivos": files},
        "\n".join(files) or f"nenhuma wallet em {WALLETS_DIR}",
    )


def cmd_publicas(args) -> None:
    path, wallet = _open(args.arquivo)
    data = {"arquivo": str(path), "dica": wallet["hint"], "enderecos": wallet["addresses"]}
    _emit(args, data, _text(str(path), wallet["addresses"]))


def cmd_privadas(args) -> None:
    path, _wallet, _pw, keys, notes = _unlock_cli(args)
    addrs = addresses(keys)
    data = {"arquivo": str(path), "enderecos": addrs, "privadas": keys, "notas": notes}
    _emit(args, data, _text(str(path), addrs, keys) + (f"\n\nNOTAS\n{notes}" if notes else ""))


def cmd_notas(args) -> None:
    path, wallet, password, _keys, notes = _unlock_cli(args)
    if args.gravar:  # notas novas = resto do stdin, depois da linha da senha
        if sys.stdin.isatty():
            print("Digite as notas; Ctrl-D (Ctrl-Z Enter no Windows) para salvar:", file=sys.stderr)
        notes = sys.stdin.read()
        rewrite(path, with_notes(wallet, password, notes))
    data = {"arquivo": str(path), "notas": notes, "gravou": args.gravar}
    _emit(args, data, f"Notas salvas (cifradas) em {path}" if args.gravar else notes)


def cmd_saldo(args) -> None:
    path, wallet = _open(args.arquivo)
    print("consultando nós públicos…", file=sys.stderr)
    found: dict = {}
    nodes.fill_balances(wallet, load_config()["nos"], found)
    data = {"arquivo": str(path), "enderecos": wallet["addresses"], "saldo": found}
    _emit(args, data, _text(str(path), wallet["addresses"], balances=found))


def cmd_sobre(args) -> None:
    text = about()
    _emit(args, {"texto": text}, text)


HELP = """Wallets BTC/ETH/XMR. Sem comando: abre a janela.
Agentes/scripts: --json (um objeto JSON no stdout; erro = {"erro": ...} e exit 1).
Senha nunca como argumento: no terminal é pedida; em pipe vai na 1a linha do stdin."""


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wallet-gen", description=HELP, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--about", action="store_true", help="igual a 'sobre'")
    parser.add_argument("--json", action="store_true", help="saída JSON (para agentes e scripts)")
    common = argparse.ArgumentParser(add_help=False)  # --json também depois do comando
    common.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    sub = parser.add_subparsers(metavar="comando")
    gerar = sub.add_parser("gerar", parents=[common], help="gera novo conjunto (pede a senha 2x)")
    gerar.add_argument("--dica", default="", help="dica da senha (fica em aberto no arquivo)")
    gerar.add_argument("--guardar-view-key", action="store_true", help="guarda view key XMR em aberto")
    gerar.set_defaults(run=cmd_gerar)
    sub.add_parser("lista", parents=[common], help=f"lista as wallets em {WALLETS_DIR}").set_defaults(
        run=cmd_lista
    )
    for name, run, helptext in [
        ("publicas", cmd_publicas, "mostra endereços (sem senha)"),
        ("privadas", cmd_privadas, "mostra chaves privadas + notas (pede a senha)"),
        ("notas", cmd_notas, "mostra as notas cifradas; --gravar substitui pelo stdin"),
        ("saldo", cmd_saldo, "saldo via nós públicos (sem senha)"),
    ]:
        cmd = sub.add_parser(name, parents=[common], help=helptext)
        cmd.add_argument("arquivo", help="nome dentro de wallets/ ou caminho do .json")
        cmd.set_defaults(run=run)
        if name == "notas":
            cmd.add_argument("--gravar", action="store_true", help="lê as notas novas do stdin e salva")
    sub.add_parser("sobre", parents=[common], help="o que gera as chaves + versões em uso").set_defaults(
        run=cmd_sobre
    )
    return parser


def _utf8_stdio() -> None:
    """Pipe no Windows é cp1252 (quebra com ✓, emoji...). Contrato da CLI: stdin/stdout/stderr em UTF-8."""
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")


def main(argv: list[str] | None = None) -> None:
    _utf8_stdio()
    args = _parser().parse_args(argv)
    if args.about:
        args.run = cmd_sobre
    if not hasattr(args, "run"):
        App().mainloop()
        return
    try:
        args.run(args)
    except SystemExit as e:
        if not (args.json and isinstance(e.code, str)):
            raise
        print(json.dumps({"erro": e.code.removeprefix("erro: ")}, ensure_ascii=False))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
