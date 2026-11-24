# Lessons

- `Popen(["uv", "run", ...]).kill()` mata só o `uv`; o Python filho (GUI) fica vivo. Para smoke de GUI, instancie `App()` + `destroy()` no próprio processo, ou mate o grupo de processos.
- Subprocesso iniciado em thread daemon não passa pelo `finally` quando o programa sai. Todo processo externo (ex.: `monero-wallet-rpc`) fica registrado e é encerrado num `atexit`; `check.py --online` prova com `check_no_orphan`.
- Workflow do GitHub: rodar `actionlint` antes do push (contexto `runner` não existe no `env` do job). Agora está no job lint do CI.
- Primeiro uso: testar com a pasta de dados ainda inexistente (`~/wallet-gen`). Temp dir que já existe escondeu `mkdir` sem `parents=True` em 2 releases.
