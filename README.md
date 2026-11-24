# wallet-gen

Gera 3 wallets — **BTC, ETH, XMR**. Endereços ficam em aberto; chaves privadas ficam cifradas com sua senha.
Mesmo arquivo `.json` em todos os jeitos de usar: gera num, abre no outro.

## 3 jeitos de usar

| Jeito | Para quem | Como |
|---|---|---|
| **Página web** | qualquer um, qualquer SO | abra o link do GitHub Pages ([afa7789.github.io/wallet-gen](https://afa7789.github.io/wallet-gen/)). Mais seguro: baixe `wallet-gen-web.zip` dos Releases, descompacte e abra `index.html` **sem internet** |
| **Executável** | quem quer app no PC | baixe dos [Releases](https://github.com/afa7789/wallet-gen/releases/latest): `wallet-gen-macos-arm64`, `wallet-gen-linux-x64`, `wallet-gen-windows-x64.exe`. Clique duplo = janela. No terminal = CLI |
| **Código-fonte** | dev | `uv run wallet_gen.py` (precisa de [uv](https://docs.astral.sh/uv/); ele baixa Python 3.12 e as versões do `wallet_gen.py.lock`) |

Executáveis não são assinados:
- **macOS:** `xattr -d com.apple.quarantine wallet-gen-macos-arm64 && chmod +x wallet-gen-macos-arm64`, depois `./wallet-gen-macos-arm64`.
- **Windows:** SmartScreen → "Mais informações" → "Executar assim mesmo".
- **Linux:** `chmod +x wallet-gen-linux-x64 && ./wallet-gen-linux-x64`.
- Confira o `SHA256SUMS` do Release: `shasum -a 256 -c SHA256SUMS`.

Onde ficam as wallets e o `config.json`: executável → `~/wallet-gen/` (`wallets/` + `config.json`); código-fonte → pasta do projeto; web → onde o navegador baixar. Troque com `WALLET_GEN_HOME=/outra/pasta`.

## CLI

Mesmos comandos no executável (`./wallet-gen-macos-arm64 …`) e no código (`uv run wallet_gen.py …`):

```sh
wallet-gen gerar --dica "minha dica"          # pede a senha 2x, salva, mostra endereços
wallet-gen lista                              # lista arquivos em wallets/
wallet-gen publicas 2026-11-24_113356.json    # endereços (sem senha)
wallet-gen privadas 2026-11-24_113356.json    # mostra a dica, pede a senha, mostra chaves + notas
wallet-gen notas    2026-11-24_113356.json    # só as notas cifradas (pede a senha)
wallet-gen notas    2026-11-24_113356.json --gravar   # substitui as notas pelo que vier no stdin
wallet-gen saldo    2026-11-24_113356.json    # saldo via nós públicos (sem senha)
wallet-gen sobre                              # o que gera as chaves + versões em uso
wallet-gen                                    # sem comando: abre a janela
```

- Arquivo: nome dentro de `wallets/` ou caminho completo.
- Senha nunca vai como argumento (ficaria no histórico do shell). No terminal ela não aparece ao digitar; em script, vai pelo stdin: `printf 'senha\nsenha\n' | wallet-gen gerar`.
- Erro (senha errada, arquivo não achado) → exit ≠ 0.

### Para agentes e scripts (`--json`)

`--json` (antes ou depois do comando) → **um objeto JSON** no stdout, prompts no stderr, tudo em UTF-8 (inclusive no Windows). Erro → `{"erro": "..."}` e exit 1. Senha = 1ª linha do stdin; em `notas --gravar`, o resto do stdin são as notas.

```sh
printf 's3nha\ns3nha\n' | wallet-gen --json gerar --dica "dica" --guardar-view-key
# {"arquivo": ".../wallets/2026-11-24_130102.json", "enderecos": {"btc": "bc1q…", "eth": "0x…", "xmr": "4…"}, "view_key_guardada": true}
wallet-gen --json lista                       # {"pasta": "...", "arquivos": ["2026-11-24_130102.json"]}
wallet-gen --json publicas 2026-11-24_130102.json          # {"arquivo", "dica", "enderecos"}
printf 's3nha\n' | wallet-gen --json privadas 2026-11-24_130102.json   # {"arquivo", "enderecos", "privadas", "notas"}
printf 's3nha\nseed do cofre\n' | wallet-gen --json notas 2026-11-24_130102.json --gravar   # {"arquivo", "notas", "gravou": true}
wallet-gen --json saldo 2026-11-24_130102.json             # {"arquivo", "enderecos", "saldo": {"btc": "0 BTC  · via …", …}}
```

Saldo por moeda: `"<valor> <MOEDA>  · via <nó>"` ou `"falhou em todos: …"` (nunca 0 em falha).

## Botões (app e web)

| Botão | Senha? | Rede? | O que faz |
|---|---|---|---|
| Gerar novo | define | não | app: cria `wallets/<data_hora>.json` (0600 no Mac/Linux; no Windows, ACL da pasta do usuário; nunca sobrescreve). Web: baixa o arquivo; endereços só aparecem abrindo ele (garante que foi salvo) |
| Ver públicas | não | não | escolhe arquivo, mostra endereços |
| Ver privadas | sim (mostra a dica) | não | mostra chaves privadas e libera as notas |
| Salvar notas | (a mesma, já aberta) | não | cifra as notas com a mesma senha no mesmo arquivo. App: grava no lugar (atômico). Web: baixa o arquivo atualizado |
| Ver saldo | não | **sim** | consulta nós públicos |
| Sobre | não | não | mesmo texto do `--about` |

## Abrir uma wallet que já existe

1. Feche qualquer janela antiga do wallet-gen.
2. Na pasta do projeto: `uv run wallet_gen.py`
3. **Ver públicas** → escolha o arquivo em `wallets/` (ex.: `2026-11-24_113356.json`) → mostra os 3 endereços. Não pede senha.
4. **Ver privadas** → mesmo arquivo → aparece sua **dica** → digite a senha → mostra as chaves privadas (em vermelho). Senha errada = erro, nada é mostrado.
5. **Ver saldo** → mesmo arquivo → BTC e ETH em segundos. XMR só se o arquivo tiver view key (opt-in no `config.json` antes de gerar). Senão aparece "sem view key".

Copiar: selecione o texto na área escura e use Cmd+C (Ctrl+C no Linux/Windows).

## Como as chaves são geradas (disclosure)

Geradores com defeito já roubaram muito dinheiro:
[Milk Sad / CVE-2023-39910](https://nvd.nist.gov/vuln/detail/CVE-2023-39910) (`bx seed`, mt19937, 32 bits de entropia),
[Trust Wallet / CVE-2023-31290](https://nvd.nist.gov/vuln/detail/CVE-2023-31290) (mt19937 com seed de 32 bits, explorado 2022–2023),
[Profanity](https://www.theblock.co/post/171192/e) (vanity ETH, provável causa do hack de ~US$160M da Wintermute, 2022),
[Randstorm](https://thehackernews.com/2023/11/randstorm-exploit-bitcoin-wallets.html) (BitcoinJS/JSBN `SecureRandom` fraco, wallets 2011–2015),
[Coldcard](https://trezor.io/blog/insights/lessons-from-the-coldcard-incident) (firmware 2021+: checava se a opção de RNG de hardware *existia*, não se estava *ligada*; seed saía de PRNG de software — ~40 bits no Mk3. Auditorias viram o RNG no binário e nunca conferiram que era chamado).
Por isso aqui nada é feito à mão: só o CSPRNG do sistema e bibliotecas mantidas por terceiros — e o `check.py` prova em runtime que a chave sai dele (abaixo).

| Moeda | Entropia | Derivação | Curva (lib mantida) |
|---|---|---|---|
| BTC | 32 bytes `secrets.token_bytes` → `os.urandom` = entropia da seed BIP39 (24 palavras) | BIP39 → BIP84 `m/84'/0'/0'/0/0` → P2WPKH `bc1q…`; arquivo guarda a seed **e** a WIF da mesma chave | secp256k1: coincurve (libsecp256k1, do Bitcoin Core) |
| ETH | 32 bytes `secrets.token_hex` → `os.urandom` | keccak256(pubkey)[12:] + checksum EIP-55 | secp256k1: coincurve (libsecp256k1) |
| XMR | 256 bits bip_utils `MoneroEntropyGenerator` → `os.urandom` | seed legacy 25 palavras; spend = sc_reduce32(seed), view = sc_reduce32(keccak256(spend)) | ed25519: PyNaCl (libsodium) |

**Web** (mesma ideia, libs JS mantidas, versões travadas no `web/bun.lock`, nada de CDN):

| Moeda | Entropia | Derivação |
|---|---|---|
| BTC | 32 bytes `crypto.getRandomValues` = entropia da seed BIP39 | `@scure/bip39` + `@scure/bip32` (BIP84) + `@scure/btc-signer` (WIF, P2WPKH), curva `@noble/curves` |
| ETH | 32 bytes `crypto.getRandomValues` | `micro-eth-signer` (EIP-55) |
| XMR | 32 bytes `crypto.getRandomValues` mod l = spend key | `monero-ts` 0.11.22 (seed 25 palavras, endereço, view key) |

Arquivo web: scrypt `@noble/hashes` + AES-256-GCM do WebCrypto, mesmos parâmetros. A página tem CSP (`script-src 'self'`) e mostra no Sobre as libs e versões. `web/dist/SHA256SUMS` = hash de cada arquivo do build.

- Entropia máxima do formato: 256 bits por chave (XMR reduz à ordem da curva, ~2²⁵², como toda carteira Monero).
- Não usa `random`/`Math.random`, mt19937, relógio como seed, nem seed de 32 bits.
- Cada moeda tem chave independente (sem BIP32/BIP39): vazar uma não revela as outras.
- Libs: bip_utils 2.13.0, coincurve 21.0.0, PyNaCl 1.6.2, pycryptodome 4.6.0 (todas fixadas no lock; `--about` mostra as em uso).
- Verificação:
  - **Fonte da entropia (lição Coldcard):** intercepta `os.urandom`/`random._urandom` (Python) e `crypto.getRandomValues` (web) e exige que as 3 chaves sejam exatamente os 3 blocos de 32 bytes servidos. Qualquer fallback ou outra fonte → falha.
  - BTC/ETH contra vetores públicos (chave = 1 e vetor oficial do BIP84); seed e WIF provados levando ao mesmo `bc1q`; XMR contra lib independente (monero-python), endereço e view key.
  - Web: `@noble/curves` pede 16 bytes extras por multiplicação (blinding contra canal lateral). O teste prova que isso não muda a chave: mesma entropia + blinding diferente = chaves idênticas. Mutação com `Math.random` → teste falha.
  - Arquivo da web abre no Python e do Python abre na web (inclui o baixado pelo navegador no E2E).

```sh
uv run check.py                    # offline (rede bloqueada): fonte, vetores, arquivo, GUI, CLI
uv run check.py --online           # nós públicos reais, controles com saldo > 0, sem processo órfão
uv run check.py --exe dist/wallet-gen   # executável: CLI inteira + janela abre
uv run check.py --web              # web: testes JS, compat Python<->web, E2E no Chrome/Brave (http e file://)
uv run check.py --web --web-online # + saldo na página
./build.sh                         # gera dist/wallet-gen do SO atual
cd web && bun install && bun build.mjs   # gera web/dist
```

CI (`.github/workflows/ci.yml`): lint (ruff + eslint, complexidade ≤ 10) → checks e executáveis em macOS, Linux e Windows → web → GitHub Pages (main) e Release com `SHA256SUMS` (tag `v*`).

## Arquivo

- `scrypt` (N=2¹⁷, r=8, p=1, sal 16 bytes) → **AES-256-GCM** (nonce 16 bytes, `os.urandom`). Senha normalizada NFC. Senha errada falha alto (tag GCM).
- Em aberto: dica, endereços, data de criação, parâmetros. Opcional: view key privada XMR (ver abaixo).
- **Notas (vault):** campo `notes_gcm`, AES-256-GCM com a **mesma chave** derivada da senha e **nonce novo a cada gravação** (reusar nonce quebraria o GCM). O bloco das chaves (`aes_gcm`) nunca é regravado; senha errada não grava nada. Arquivo antigo sem notas → notas vazias.
- **Pós-quântico:** o arquivo só usa cripto simétrica. AES-256 contra Grover fica com ~128 bits, o que é considerado seguro. Não há etapa de chave pública para ML-KEM substituir. Limite real = força da senha. As moedas em si (secp256k1/ed25519) não são pós-quânticas — isso é das redes, não do arquivo.

## Saldo (único momento com rede)

| Moeda | Nós padrão (em ordem, com fallback) | Sai da máquina |
|---|---|---|
| BTC | mempool.space, blockstream.info, mempool.emzy.de (Esplora) | endereço |
| ETH | publicnode, drpc, merkle, flashbots (`eth_getBalance`) | endereço |
| XMR | cakewallet, sethforprivacy, monerodevs, hashvault, stormycloud, stackwallet | nada de chave: `monero-wallet-rpc` roda local, nó só serve blocos |

- XMR precisa da view key **privada** (a pública já está dentro do endereço). Opt-in: no app, `"guardar_view_key_xmr": true` no `config.json`; na web, a caixinha ao gerar. Novos arquivos guardam a view key em aberto. Ela deixa ver o que entrou, **não** deixa gastar. Padrão: desligado.
- Saldo XMR: app usa `monero-wallet-rpc` oficial (`brew install monero`, ~670 MB com dependências, **não** baixa blockchain); web usa `monero-ts` no próprio navegador (só nós com https + CORS: cakewallet, sethforprivacy).
- XMR view-only mostra **recebido**, não vê gastos. Escaneia a partir de ~3 dias antes da criação do arquivo, toda vez (nada fica em cache). Medido no app: wallet de ~10 dias ≈ 40 s; de ~90 dias ≈ 3,5 min. Na web (WASM no navegador) é mais lento: ~10 dias ≈ 3 min.
- Arquivos antigos (sem `created`/view key) abrem normal; só o saldo XMR fica indisponível.
- Seus nós no `config.json` vêm antes dos padrão. Falhou um, tenta o próximo; falhou todos, mostra "falhou" (nunca 0).
- Valor é palavra de terceiro. Consultar as 3 do mesmo IP liga elas entre si.

```json
{
  "guardar_view_key_xmr": false,
  "nos": { "btc": ["https://meu-esplora/api"], "eth": ["https://meu-rpc"], "xmr": ["meu.no:18089"] }
}
```

`config.json` ausente ou inválido → padrão (view key desligada). Nunca trava Gerar/Ver.

## Restaurar em outras carteiras

Pegue as chaves com **Ver privadas** (ou `wallet-gen privadas ARQ`). Nunca cole chave em chat, nuvem ou screenshot.

| Moeda | Carteira | Cole | Confira |
|---|---|---|---|
| BTC | Cake, Sparrow, BlueWallet | a **seed** de 24 palavras (BIP39; tipo Native SegWit / BIP84 se perguntar) | 1º endereço `bc1q…` igual |
| BTC | Electrum | a linha `p2wpkh:K…` inteira ("Import Bitcoin addresses or private keys") | idem |
| ETH | MetaMask, Cake (aba Keys) | o hex de 64 caracteres | `0x…` igual |
| XMR | Cake, Feather, Monero GUI | as 25 palavras (Legacy, não Polyseed) + data de criação do arquivo | endereço **principal #0** `4…` (Cake mostra subendereço `8…` em Receber) |

Arquivos gerados antes da v0.2.0 não têm seed BTC, só WIF: abrem no Electrum/Sparrow; o Cake não importa chave BTC solta ([doc do Cake](https://docs.cakewallet.com/get-started/setup/restore-existing-wallet)).

## Limites

- Não auditado. Antes de depositar: restaure cada chave numa carteira real e confira o endereço — BTC no Electrum (`p2wpkh:…`), ETH no MetaMask (hex), XMR no Feather/Monero GUI (25 palavras).
- Perdeu arquivo ou senha = perdeu fundos. Faça backup do `wallets/`.
- Dica fica em aberto: não escreva a senha nela.

## Doações

Curtiu? Endereços gerados com o próprio wallet-gen:

| Moeda | Endereço |
|---|---|
| BTC | [`bc1qqjykl9nym5qn9u2dpqt0vfz8cgl4pt3n8mkngq`](bitcoin:bc1qqjykl9nym5qn9u2dpqt0vfz8cgl4pt3n8mkngq) |
| ETH | [`0xa2FB6CA627659644EFeBe3A83361e22e8B34921C`](ethereum:0xa2FB6CA627659644EFeBe3A83361e22e8B34921C) |
| XMR | [`42Nv3KCbqexE78fZMeMrjRHMDME62s5Jya71Pz12e79HUP6Wwbr37uG9ukRWrtvTg2WkikNk1NCz4RcU3dDcafUhLtdTdfY`](monero:42Nv3KCbqexE78fZMeMrjRHMDME62s5Jya71Pz12e79HUP6Wwbr37uG9ukRWrtvTg2WkikNk1NCz4RcU3dDcafUhLtdTdfY) |
