/* tslint:disable */
/* eslint-disable */
export function hello(): string;
export class WasmKeyPair {
  private constructor();
  free(): void;
  [Symbol.dispose](): void;
  static generate(): WasmKeyPair;
  static fromSecretBytes(bytes: Uint8Array): WasmKeyPair;
  toSecretBytes(): Uint8Array;
  getPublicBytes(): Uint8Array;
  toSecretBase58(): string;
  getPublicBase58(): string;
  static fromSecretBase58(s: string): WasmKeyPair;
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly __wbg_wasmkeypair_free: (a: number, b: number) => void;
  readonly wasmkeypair_generate: () => number;
  readonly wasmkeypair_fromSecretBytes: (a: number, b: number) => [number, number, number];
  readonly wasmkeypair_toSecretBytes: (a: number) => [number, number];
  readonly wasmkeypair_getPublicBytes: (a: number) => [number, number];
  readonly wasmkeypair_toSecretBase58: (a: number) => [number, number];
  readonly wasmkeypair_getPublicBase58: (a: number) => [number, number];
  readonly wasmkeypair_fromSecretBase58: (a: number, b: number) => [number, number, number];
  readonly hello: () => [number, number];
  readonly __wbindgen_exn_store: (a: number) => void;
  readonly __externref_table_alloc: () => number;
  readonly __wbindgen_export_2: WebAssembly.Table;
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __externref_table_dealloc: (a: number) => void;
  readonly __wbindgen_free: (a: number, b: number, c: number) => void;
  readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
  readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;
/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
*
* @returns {InitOutput}
*/
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
