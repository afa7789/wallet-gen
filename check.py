# /// script
# requires-python = "==3.12.*"
# dependencies = ["bip_utils==2.13.0", "monero==1.1.1"]
# ///
"""Prova offline: uv run check.py -> exit 0.  Nós públicos reais: uv run check.py --online.

Wallets de teste vão para pasta temporária; rede é bloqueada no modo offline.
"""

import json
import os
import random
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from decimal import Decimal
from importlib import metadata
from pathlib import Path

from bip_utils import MoneroMnemonicDecoder, WifDecoder, WifEncoder
from monero.seed import Seed  # implementação independente do Monero

import nodes
import wallet_gen as w

KEY_ONE = {"btc": "p2wpkh:KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn", "eth": "00" * 31 + "01"}
BTC_GENESIS = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
ETH_DEPOSIT_CONTRACT = "0x00000000219ab540356cBB839Cbe05303d7705Fa"
XMR_GENERAL_FUND = {  # view-only publicado em getmonero.org/get-started/contributing
    "addresses": {
        "xmr": "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A"  # noqa: E501
    },
    "xmr_view_key": "f359631075708155cc3d92a32b75a7d02a5dcf27756707b47a2b31b21c389501",
}


def assert_private(path: Path) -> None:
    """POSIX: 0600. Windows não tem modo Unix: protege pelo ACL da pasta do usuário."""
    assert os.name == "nt" or stat.S_IMODE(path.stat().st_mode) == 0o600, oct(path.stat().st_mode)


def expect(exc, fn, *args) -> None:
    try:
        fn(*args)
    except exc:
        return
    sys.exit(f"{fn.__name__} deveria lançar {exc.__name__}")


def check_entropy_source() -> None:
    """Lição Coldcard: não basta o RNG existir, tem que provar que É ELE que gera a chave.
    Intercepta os.urandom (bip_utils) e random._urandom (secrets): as 3 chaves têm que ser
    exatamente os 3 blocos de 32 bytes servidos — nenhum fallback, nenhuma outra fonte."""
    served = []

    def fake_urandom(n: int) -> bytes:
        served.append(bytes([len(served) + 1]) * n)
        return served[-1]

    real = os.urandom, random._urandom
    os.urandom = random._urandom = fake_urandom
    try:
        keys = w.new_secrets()
    finally:
        os.urandom, random._urandom = real
    assert [len(b) for b in served] == [32, 32, 32], f"esperado 3x32 bytes do SO, veio {served}"
    used = {
        WifDecoder.Decode(keys["btc"].removeprefix("p2wpkh:"))[0],
        bytes.fromhex(keys["eth"]),
        MoneroMnemonicDecoder().Decode(keys["xmr"]),
    }
    assert used == set(served), "alguma chave não veio do os.urandom"
    assert len(set(w.new_secrets().values()) | set(keys.values())) == 6, "chaves repetiram entre chamadas"


def check_vectors() -> None:
    a = w.addresses({**KEY_ONE, "xmr": w.new_secrets()["xmr"]})
    assert a["btc"] == "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", a["btc"]
    assert a["eth"] == "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf", a["eth"]
    assert WifEncoder.Encode(bytes(31) + b"\x01") == KEY_ONE["btc"].removeprefix("p2wpkh:")
    for _ in range(5):
        seed = w.new_secrets()["xmr"]
        assert len(seed.split()) == 25
        assert w.addresses({**KEY_ONE, "xmr": seed})["xmr"] == str(Seed(seed).public_address()), seed
        assert w.seal({**KEY_ONE, "xmr": seed}, "x", "", True)["xmr_view_key"] == Seed(seed).secret_view_key()


def check_file(folder: Path) -> None:
    keys = w.new_secrets()
    wallet = w.seal(keys, "çenha forte", "dica x")
    path = w.save(wallet, folder)
    raw = path.read_text()
    assert_private(path)
    assert all(k not in raw for k in keys.values()) and "xmr_view_key" not in raw
    loaded = json.loads(raw)
    assert w.unseal(loaded, "çenha forte") == keys
    assert loaded["addresses"] == w.addresses(keys) and abs(loaded["created"] - time.time()) < 60
    expect(ValueError, w.unseal, loaded, "errada")
    path.unlink()

    opted = w.seal(keys, "x", "", keep_view_key=True)
    assert len(opted["xmr_view_key"]) == 64 and keys["xmr"] not in json.dumps(opted)

    real_strftime = w.time.strftime
    w.time.strftime = lambda fmt: "mesmo-segundo"
    first = w.save(wallet, folder)
    before = first.read_text()
    second = w.save(opted, folder)
    w.time.strftime = real_strftime
    assert (first.name, second.name) == ("mesmo-segundo.json", "mesmo-segundo-1.json")
    assert first.read_text() == before, "save sobrescreveu arquivo existente"
    first.unlink()
    second.unlink()


def check_notes(folder: Path) -> None:
    """Vault: mesma senha e arquivo; chaves intactas; nonce novo por gravação; senha errada não grava."""
    keys = w.new_secrets()
    wallet = w.seal(keys, "pw", "")
    assert w.unlock(wallet, "pw") == (keys, ""), "arquivo sem notas -> notas vazias"
    first = w.with_notes(wallet, "pw", "nota ç")
    second = w.with_notes(first, "pw", "nota ç")
    assert first["aes_gcm"] == wallet["aes_gcm"] and w.unlock(second, "pw") == (keys, "nota ç")
    assert first["notes_gcm"]["nonce"] != second["notes_gcm"]["nonce"], "nonce reusado com a mesma chave"
    assert first["notes_gcm"]["nonce"] != wallet["aes_gcm"]["nonce"]
    expect(ValueError, w.with_notes, wallet, "errada", "x")
    path = folder / "vault.json"
    w.rewrite(path, first)
    w.rewrite(path, second)
    assert_private(path)
    assert json.loads(path.read_text()) == second
    assert [p.name for p in folder.iterdir()] == ["vault.json"], "sobrou arquivo temporário"
    path.unlink()


def check_config() -> None:
    assert w.load_config() == {"guardar_view_key_xmr": False, "nos": nodes.DEFAULT_NODES}  # ausente
    for broken in ("{nao json", "[1, 2]", '{"nos": 5}'):
        w.CONFIG_PATH.write_text(broken)
        assert w.load_config()["nos"] == nodes.DEFAULT_NODES, broken
    w.CONFIG_PATH.write_text(json.dumps({"guardar_view_key_xmr": True, "nos": {"xmr": ["meu.no:18089"]}}))
    cfg = w.load_config()
    assert cfg["guardar_view_key_xmr"] is True
    assert cfg["nos"]["xmr"] == ["meu.no:18089", *nodes.DEFAULT_NODES["xmr"]]
    assert cfg["nos"]["btc"] == nodes.DEFAULT_NODES["btc"]
    w.CONFIG_PATH.unlink()


def check_fallback() -> None:
    def fn(node, arg):
        if node.startswith("morto"):
            raise OSError("caiu")
        return f"ok {arg}"

    assert nodes.first_ok(fn, ["morto1", "vivo", "morto2"], 7) == "ok 7  · via vivo"
    assert nodes.first_ok(fn, ["morto1", "morto2"], 7).startswith("falhou em todos: morto1: caiu")
    assert nodes._amount(0, 18) == "0" and nodes._amount(4582344, 8) == "0.04582344"

    old_format, out = {"addresses": {"btc": "a", "eth": "b", "xmr": "c"}}, {}  # sem created nem view key
    nodes.fill_balances(old_format, nodes.DEFAULT_NODES, out)  # real, rede bloqueada
    assert out["btc"].startswith("falhou") and out["eth"].startswith("falhou"), "falha nunca vira 0"
    assert "sem view key" in out["xmr"], out


def check_about() -> None:
    text = w.about()
    assert "os.urandom" in text and "PÓS-QUÂNTICO" in text
    assert all(f"{d} {metadata.version(d)}" in text for d in w.CRYPTO_DEPS)
    assert all(url in text for urls in nodes.DEFAULT_NODES.values() for url in urls)
    cli = subprocess.run([sys.executable, w.__file__, "--about"], capture_output=True, text=True)
    assert cli.returncode == 0 and cli.stdout.strip() == text.strip(), cli.stderr


def cli(home: Path, *args: str, stdin: str = "", exe: list[str] | None = None) -> subprocess.CompletedProcess:
    cmd = (exe or [sys.executable, w.__file__]) + list(args)
    env = {**os.environ, "WALLET_GEN_HOME": str(home)}
    return subprocess.run(cmd, input=stdin, capture_output=True, text=True, env=env, timeout=300)


def check_cli(home: Path, exe: list[str] | None = None) -> None:
    """Todo comando via subprocesso, como o usuário roda. exe=None: script; senão o executável."""
    bad = cli(home, "gerar", stdin="abc\nabd\n", exe=exe)
    assert bad.returncode != 0 and "diferente" in bad.stderr and not (home / "wallets").exists(), bad
    made = cli(home, "gerar", "--dica", "minha dica", stdin="çenha\nçenha\n", exe=exe)
    assert made.returncode == 0, made.stderr
    [path] = (home / "wallets").iterdir()
    assert f"Salvo em {path}" in made.stdout, made.stdout
    saved = json.loads(path.read_text())
    keys = w.unseal(saved, "çenha")  # arquivo do CLI/executável abre no código-fonte
    assert w.addresses(keys) == saved["addresses"] and saved["hint"] == "minha dica"

    assert cli(home, "lista", exe=exe).stdout.strip() == path.name
    pub = cli(home, "publicas", path.name, exe=exe)
    assert pub.returncode == 0 and all(a in pub.stdout for a in saved["addresses"].values()), pub
    assert "privada" not in pub.stdout
    priv = cli(home, "privadas", path.name, stdin="çenha\n", exe=exe)
    assert priv.returncode == 0 and all(k in priv.stdout for k in keys.values()), priv.stderr
    assert "Dica: minha dica" in priv.stderr
    wrong = cli(home, "privadas", str(path), stdin="errada\n", exe=exe)
    assert wrong.returncode != 0 and "senha errada" in wrong.stderr and keys["eth"] not in wrong.stdout
    assert cli(home, "publicas", "nao-existe.json", exe=exe).returncode != 0

    notes = "cofre: ç ✓\nlinha 2\n"
    put = cli(home, "notas", path.name, "--gravar", stdin=f"çenha\n{notes}", exe=exe)
    assert put.returncode == 0 and "Notas salvas" in put.stdout, put.stderr
    assert cli(home, "notas", path.name, stdin="çenha\n", exe=exe).stdout == notes + "\n"
    assert json.loads(path.read_text())["aes_gcm"] == saved["aes_gcm"], "notas não podem mexer nas chaves"
    refused = cli(home, "notas", path.name, "--gravar", stdin="errada\nlixo", exe=exe)
    assert refused.returncode != 0 and w.unlock(json.loads(path.read_text()), "çenha")[1] == notes

    sobre = cli(home, "sobre", exe=exe)
    assert sobre.returncode == 0 and "os.urandom" in sobre.stdout and f"Pasta: {home}" in sobre.stdout
    assert cli(home, "--about", exe=exe).stdout == sobre.stdout
    helptext = cli(home, "--help", exe=exe).stdout
    assert all(c in helptext for c in ("gerar", "lista", "publicas", "privadas", "notas", "saldo", "sobre"))
    check_cli_json(home, path, keys, notes, exe)
    for f in (home / "wallets").iterdir():
        f.unlink()
    (home / "wallets").rmdir()


def check_cli_json(home: Path, path: Path, keys: dict, notes: str, exe: list[str] | None) -> None:
    """Agentes: --json (antes/depois do comando) = 1 objeto JSON; erro = {"erro"} + exit 1."""

    def as_json(*args: str, stdin: str = "") -> dict:
        done = cli(home, *args, stdin=stdin, exe=exe)
        return {"exit": done.returncode, **json.loads(done.stdout)}

    made = as_json("--json", "gerar", "--guardar-view-key", "--dica", "agente", stdin="s\ns\n")
    assert made["exit"] == 0 and made["view_key_guardada"] is True and Path(made["arquivo"]).exists()
    assert json.loads(Path(made["arquivo"]).read_text())["addresses"] == made["enderecos"]
    assert set(as_json("lista", "--json")["arquivos"]) == {path.name, Path(made["arquivo"]).name}
    assert as_json("publicas", path.name, "--json")["dica"] == "minha dica"
    priv = as_json("privadas", path.name, "--json", stdin="çenha\n")
    assert priv["privadas"] == keys and priv["notas"] == notes and priv["enderecos"] == w.addresses(keys)
    assert as_json("notas", path.name, "--json", stdin="çenha\n")["notas"] == notes
    assert as_json("--json", "privadas", path.name, stdin="errada\n") == {"exit": 1, "erro": "senha errada"}
    assert "os.urandom" in as_json("sobre", "--json")["texto"]


def walk(widget):
    yield widget
    for child in widget.winfo_children():
        yield from walk(child)


def pump(app, until) -> None:
    for _ in range(100):
        app.update()
        if until():
            return
        time.sleep(0.05)
    sys.exit("GUI não chegou no estado esperado")


def check_gui(folder: Path) -> None:
    real_save, errors, answers = w.save, [], {}
    w.save = lambda wallet: real_save(wallet, folder)
    w.messagebox.showerror = lambda *a, **k: errors.append(a)
    w.filedialog.askopenfilename = lambda **k: answers["path"]
    w.simpledialog.askstring = lambda *a, **k: answers["pw"]
    app = w.App()
    btn = {b.cget("text"): b for b in walk(app) if b.winfo_class() == "TButton"}
    assert set(btn) == {"Gerar novo", "Ver públicas", "Ver privadas", "Ver saldo", "Sobre", "Salvar notas"}, (
        btn
    )

    def text() -> str:
        return app.out.get("1.0", "end")

    app.fields["Senha"].insert(0, "abc")
    app.fields["Confirmar"].insert(0, "abd")
    btn["Gerar novo"].invoke()
    assert len(errors) == 1 and not list(folder.iterdir()), "confirmação errada deveria falhar sem arquivo"

    app.fields["Confirmar"].delete(0, "end")
    app.fields["Confirmar"].insert(0, "abc")
    btn["Gerar novo"].invoke()
    [path] = folder.iterdir()
    saved = json.loads(path.read_text())
    keys = w.unseal(saved, "abc")
    assert all(a in text() for a in saved["addresses"].values()) and "privada" not in text()
    assert "xmr_view_key" not in saved, "padrão: view key desligada"

    w.CONFIG_PATH.write_text(json.dumps({"guardar_view_key_xmr": True}))
    btn["Gerar novo"].invoke()  # mesmo segundo: vira -1, não quebra
    [opted] = set(folder.iterdir()) - {path, w.CONFIG_PATH}
    assert len(json.loads(opted.read_text())["xmr_view_key"]) == 64 and "view key XMR guardada" in text()
    opted.unlink()
    w.CONFIG_PATH.unlink()

    assert app.notes.cget("state") == "disabled", "notas fechadas antes de Ver privadas"
    answers.update(path=str(path), pw="abc")
    btn["Ver privadas"].invoke()
    assert all(k in text() for k in keys.values()) and len(errors) == 1

    assert app.notes.cget("state") == "normal" and app.notes.get("1.0", "end-1c") == ""
    app.notes.insert("1.0", "seed do cofre: ç ✓\nlinha 2")
    btn["Salvar notas"].invoke()
    vaulted = json.loads(path.read_text())
    assert vaulted["aes_gcm"] == saved["aes_gcm"] and "seed do cofre" not in path.read_text()
    assert w.unlock(vaulted, "abc") == (keys, "seed do cofre: ç ✓\nlinha 2") and "Notas salvas" in text()
    btn["Ver públicas"].invoke()
    assert app.notes.cget("state") == "disabled" and app.vault is None, "outra tela fecha o vault"
    btn["Ver privadas"].invoke()
    assert app.notes.get("1.0", "end-1c") == "seed do cofre: ç ✓\nlinha 2", "notas reabrem"

    app.out.delete("1.0", "end")
    answers["pw"] = "errada"
    btn["Ver privadas"].invoke()
    assert len(errors) == 2 and "privada" not in text()

    answers["pw"] = None  # cancelar senha -> nada
    btn["Ver privadas"].invoke()
    assert text().strip() == "" and len(errors) == 2

    old = folder / "formato-antigo.json"  # arquivos de antes do Ver saldo: sem created/xmr_view_key
    old.write_text(json.dumps({k: saved[k] for k in ("hint", "addresses", "scrypt", "aes_gcm")}))
    answers.update(path=str(old), pw="abc")
    btn["Ver privadas"].invoke()
    assert all(k in text() for k in keys.values()) and len(errors) == 2, "formato antigo não abriu"
    old.unlink()
    answers["path"] = str(path)

    w.simpledialog.askstring = lambda *a, **k: sys.exit("Ver públicas/saldo pediu senha")
    btn["Ver públicas"].invoke()
    assert all(a in text() for a in saved["addresses"].values()) and "privada" not in text()

    btn["Sobre"].invoke()
    assert text().strip() == w.about().strip()

    release = threading.Event()

    def fake_fill(wallet, nos, out):
        out["btc"] = "1 BTC"
        release.wait(5)
        out.update(eth="2 ETH", xmr="3 XMR")

    w.nodes.fill_balances = fake_fill
    btn["Ver saldo"].invoke()
    pump(app, lambda: "1 BTC" in text())
    assert "consultando" in text(), "saldo parcial deveria mostrar o que falta"
    release.set()
    pump(app, lambda: "3 XMR" in text())
    assert "consultando" not in text() and "privada" not in text()

    release.clear()
    btn["Ver saldo"].invoke()
    pump(app, lambda: "1 BTC" in text())
    btn["Sobre"].invoke()  # usuário muda de tela no meio do sync
    release.set()
    for _ in range(20):
        app.update()
        time.sleep(0.05)
    assert text().strip() == w.about().strip(), "poll velho redesenhou por cima de outra tela"
    app.destroy()
    path.unlink()


def check_online() -> None:
    """Controles positivos (saldo > 0 garantido). Nó público oscila: exige o resultado com fallback."""
    for fn, coin, addr in [(nodes.btc, "btc", BTC_GENESIS), (nodes.eth, "eth", ETH_DEPOSIT_CONTRACT)]:
        for node in nodes.DEFAULT_NODES[coin]:
            print(f"  {coin} {node}: {nodes.first_ok(fn, [node], addr)[:60]}")
    control = {
        **XMR_GENERAL_FUND,
        "addresses": {"btc": BTC_GENESIS, "eth": ETH_DEPOSIT_CONTRACT, **XMR_GENERAL_FUND["addresses"]},
        "created": time.time() - 7 * 86400,
    }
    out = {}
    nodes.fill_balances(control, nodes.DEFAULT_NODES, out)  # caminho real do botão Ver saldo
    for coin, result in out.items():
        assert Decimal(result.split()[0]) > 0, result
        print(f"{coin}: {result}")


def check_no_orphan() -> None:
    """Sai do programa no meio do sync XMR: atexit tem que matar o monero-wallet-rpc."""
    wallet = {**XMR_GENERAL_FUND, "created": time.time() - 30 * 86400}
    code = (
        "import threading, time, nodes\n"
        f"args = (nodes.DEFAULT_NODES['xmr'][0], {wallet!r})\n"
        "threading.Thread(target=nodes.xmr, args=args, daemon=True).start()\n"
        "time.sleep(8)\n"
        "print(*[p.pid for p in nodes._RUNNING])\n"
    )
    here = Path(__file__).resolve().parent
    run = subprocess.run([sys.executable, "-c", code], cwd=here, capture_output=True, text=True, timeout=120)
    pids = [int(p) for p in run.stdout.split()]
    assert pids, f"wallet-rpc não estava rodando: atexit não exercitado {run.stderr[-300:]}"
    for pid in pids:
        expect(ProcessLookupError, os.kill, pid, 0)
    print("sem órfão:", pids)


WEB = Path(__file__).resolve().parent / "web"


def run_web(*cmd: str) -> str:
    done = subprocess.run(list(cmd), cwd=WEB, capture_output=True, text=True, timeout=900)
    assert done.returncode == 0, f"{cmd}: {done.stdout[-800:]} {done.stderr[-800:]}"
    return done.stdout


def assert_opens_in_python(path: Path, password: str) -> None:
    wallet = json.loads(path.read_text())
    keys = w.unseal(wallet, password)
    assert w.addresses(keys) == wallet["addresses"], path
    assert wallet["xmr_view_key"] == w.seal(keys, "x", "", True)["xmr_view_key"], path


def check_web(online: bool) -> None:
    """Web = mesmo formato: arquivo da web abre no Python e vice-versa; E2E num navegador real."""
    run_web("node", "test.mjs")
    with tempfile.TemporaryDirectory() as d:
        keys = w.new_secrets()
        py_file = Path(d) / "python.json"
        py_file.write_text(json.dumps(w.with_notes(w.seal(keys, "çenha", "dica py"), "çenha", "nota py ç ✓")))
        opened = json.loads(run_web("node", "test.mjs", "open", str(py_file), "çenha"))
        assert opened == {"keys": keys, "notes": "nota py ç ✓"}, opened
        js_file = Path(d) / "js.json"
        run_web("node", "test.mjs", "make", str(js_file), "çenha")
        assert_opens_in_python(js_file, "çenha")
        assert w.unlock(json.loads(js_file.read_text()), "çenha")[1] == "nota web ç ✓"
        run_web("bun", "build.mjs")
        print(run_web("node", "e2e.mjs", d, *(["--online"] if online else [])).strip())
        for name in ("web-wallet.json", "web-wallet-offline.json", "web-wallet-notas.json"):
            assert_opens_in_python(Path(d) / name, "senha-e2e")
        notas = json.loads((Path(d) / "web-wallet-notas.json").read_text())
        assert w.unlock(notas, "senha-e2e")[1] == "nota e2e ç ✓", "notas salvas na página não abrem no Python"
    print("web OK: compat Python<->web nos dois sentidos")


def check_exe(exe: Path) -> None:
    """Executável pronto: mesma bateria da CLI + GUI abre e fica de pé (sem crash de import/Tk)."""
    with tempfile.TemporaryDirectory() as home:
        check_cli(Path(home), [str(exe)])
        windows = os.name == "nt"
        flags = (
            {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if windows else {"start_new_session": True}
        )
        env = {**os.environ, "WALLET_GEN_HOME": home}
        gui = subprocess.Popen([str(exe)], env=env, stderr=subprocess.PIPE, text=True, **flags)
        try:
            gui.wait(10)
            sys.exit(f"GUI do executável fechou sozinha: {gui.stderr.read()[-500:]}")
        except subprocess.TimeoutExpired:
            pass
        finally:  # one-file = bootloader + filho: mata a árvore inteira
            if windows:
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(gui.pid)], capture_output=True)
            else:
                os.killpg(gui.pid, 15)
            gui.wait(10)
    print(f"executável OK: {exe}")


if __name__ == "__main__":
    if "--online" in sys.argv:
        check_online()
        check_no_orphan()
    elif "--exe" in sys.argv:
        check_exe(Path(sys.argv[sys.argv.index("--exe") + 1]).resolve())
    elif "--web" in sys.argv:
        check_web(online="--web-online" in sys.argv)
    else:

        def offline(*a, **k):
            raise AssertionError("rede usada no modo offline")

        urllib.request.urlopen = offline
        with tempfile.TemporaryDirectory() as d:
            w.CONFIG_PATH = Path(d) / "config.json"  # nunca lê/escreve o config.json do usuário
            check_entropy_source()
            check_vectors()
            check_fallback()
            check_about()
            check_config()
            check_file(Path(d))
            check_notes(Path(d))
            check_gui(Path(d))
        with tempfile.TemporaryDirectory() as home:
            check_cli(Path(home))
    print("OK")
