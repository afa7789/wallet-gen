// monero-ts usa process.nextTick/env (vindos do Node). No navegador: polyfill npm "process".
import process from "process/browser.js";

globalThis.process ??= process;
