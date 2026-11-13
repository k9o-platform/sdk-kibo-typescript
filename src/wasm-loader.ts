/**
 * Loads the nodejs-target glue that wasm-bindgen emits for the bound core.
 *
 * That glue is CommonJS (`exports.zk_encrypt = ...`, `require("fs")`, a synchronous read of the sibling `_bg.wasm`).
 * This package is ESM (`"type": "module"`), so Node parses any `.js` under it as ESM and the glue dies with
 * `exports is not defined`; `import()` and `require()` of that file both hit it. The default loader therefore reads the
 * glue source and evaluates it with a CommonJS wrapper itself, which does not depend on the file extension or on the
 * nearest `package.json`.
 *
 * Failures are reported as what they are: no glue file at all, or a glue file that is there and failed (with the
 * underlying error attached as `cause`).
 */

import { KError } from "@k9o/core/errors";
import type { ZkWasm } from "./crypto.ts";

/** What the loader needs from the host; injectable so the failure paths are testable without a wasm artefact. */
export interface WasmLoaderDeps {
  /** Absolute paths to try, in order. */
  candidates: string[];
  /** Load the glue at `path`. Must reject with an error whose `code` is `ENOENT`/`MODULE_NOT_FOUND`/`ERR_MODULE_NOT_FOUND`
   *  and whose `path` (or message) names `path` when that file is missing. */
  importGlue(path: string): Promise<unknown>;
}

const NOT_FOUND_CODES = new Set(["ENOENT", "MODULE_NOT_FOUND", "ERR_MODULE_NOT_FOUND"]);

function describe(e: unknown): string {
  return e instanceof Error ? `${e.name}: ${e.message}` : String(e);
}

/** True when `e` says the file `path` itself is missing (not a file the glue went on to read). */
function isMissing(e: unknown, path: string): boolean {
  if (typeof e !== "object" || e === null) return false;
  const err = e as { code?: unknown; path?: unknown; message?: unknown };
  if (typeof err.code !== "string" || !NOT_FOUND_CODES.has(err.code)) return false;
  if (typeof err.path === "string") return err.path === path;
  return typeof err.message === "string" && err.message.includes(path);
}

function withCause(err: KError, cause: unknown): KError {
  (err as { cause?: unknown }).cause = cause;
  return err;
}

export async function loadZkGlue(deps: WasmLoaderDeps): Promise<ZkWasm> {
  for (const path of deps.candidates) {
    let mod: unknown;
    try {
      mod = await deps.importGlue(path);
    } catch (e) {
      if (isMissing(e, path)) continue;
      throw withCause(
        new KError({
          code: "KIBO_WASM_ERROR",
          message: `the Kibo zero-knowledge core (wasm) is present at ${path} but failed to load: ${describe(e)}`,
          context: { path, cause: describe(e) },
          recommendation: "Reinstall @k9o/kibo; if it persists, load the core yourself and pass it to setZkWasm.",
        }),
        e,
      );
    }
    const m = mod as Partial<ZkWasm> | null | undefined;
    if (typeof m?.zk_encrypt !== "function" || typeof m?.zk_decrypt !== "function") {
      throw new KError({
        code: "KIBO_WASM_ERROR",
        message: `the Kibo zero-knowledge core (wasm) loaded from ${path} does not export zk_encrypt and zk_decrypt`,
        context: { path },
        recommendation: "Reinstall @k9o/kibo; the bundled core does not match this version.",
      });
    }
    return m as ZkWasm;
  }
  throw new KError({
    code: "KIBO_WASM_ERROR",
    message: `the Kibo zero-knowledge core (wasm) is not bundled in this build of @k9o/kibo: no file at ${deps.candidates.join(" or ")}; encrypt and decrypt are unavailable`,
    context: { candidates: deps.candidates },
    recommendation: "Install a release of @k9o/kibo that ships the core, or load it yourself and pass it to setZkWasm.",
  });
}

/** Evaluate CommonJS source as a module living at `path`, with a `require` resolving from `path`. */
export function evalCommonJs(source: string, path: string, req: (id: string) => unknown, dirname: string): unknown {
  const module = { exports: {} as Record<string, unknown> };
  // eslint-disable-next-line no-new-func
  const wrapper = new Function("exports", "require", "module", "__filename", "__dirname", source);
  wrapper(module.exports, req, module, path, dirname);
  return module.exports;
}

/** Node host: glue next to this package's `wasm/` directory, evaluated as CommonJS. */
export function nodeDeps(moduleUrl: string): WasmLoaderDeps {
  // The node builtins are named at run time so a browser/RN bundler never tries to resolve them: this path only runs on Node.
  const builtin = (n: string) => ["node", n].join(":");
  const here = (rel: string) => decodeURIComponent(new URL(rel, moduleUrl).pathname.replace(/^\/([A-Za-z]:)/, "$1"));
  return {
    candidates: [here("../wasm/kibo_kms_rest_ffi.cjs"), here("../wasm/kibo_kms_rest_ffi.js")],
    async importGlue(path: string) {
      const fs = (await import(builtin("fs"))) as typeof import("node:fs");
      const nodeModule = (await import(builtin("module"))) as typeof import("node:module");
      const nodePath = (await import(builtin("path"))) as typeof import("node:path");
      const source = fs.readFileSync(path, "utf8"); // throws ENOENT with err.path === path when the glue is missing
      return evalCommonJs(source, path, nodeModule.createRequire(path), nodePath.dirname(path));
    },
  };
}
