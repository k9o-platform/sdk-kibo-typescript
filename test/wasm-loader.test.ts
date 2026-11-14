/**
 * The loader tells a missing core from a core that is there and failed, and loads CommonJS glue from this ESM package.
 * Everything here uses injected or temporary glue; the real compiled wasm is a CI artefact and is not in the tree.
 */
import { describe, expect, it } from "bun:test";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { KError } from "@k9o/core/errors";
import { loadZkGlue, nodeDeps } from "../src/wasm-loader.ts";

const stub = { zk_encrypt: async () => ({}), zk_decrypt: async () => ({}) };
const enoent = (path: string) => Object.assign(new Error(`ENOENT: no such file or directory, open '${path}'`), { code: "ENOENT", path });

describe("loadZkGlue", () => {
  it("returns the module from the first candidate that loads", async () => {
    const seen: string[] = [];
    const mod = await loadZkGlue({
      candidates: ["/a.cjs", "/a.js"],
      importGlue: async (p) => {
        seen.push(p);
        if (p === "/a.cjs") throw enoent(p);
        return stub;
      },
    });
    expect(mod).toBe(stub as never);
    expect(seen).toEqual(["/a.cjs", "/a.js"]);
  });

  it("says 'not bundled' and lists the paths when every candidate is missing", async () => {
    const err = (await loadZkGlue({ candidates: ["/x/a.cjs", "/x/a.js"], importGlue: async (p) => { throw enoent(p); } }).catch((e) => e)) as KError;
    expect(err).toBeInstanceOf(KError);
    expect(err.code).toBe("KIBO_WASM_ERROR");
    expect(err.message).toContain("not bundled");
    expect(err.message).toContain("/x/a.cjs");
    expect(err.message).toContain("/x/a.js");
  });

  it("reports a failed import as failed, with the real cause attached, not as 'not bundled'", async () => {
    const cause = new ReferenceError("exports is not defined in ES module scope");
    const err = (await loadZkGlue({ candidates: ["/x/a.js"], importGlue: async () => { throw cause; } }).catch((e) => e)) as KError;
    expect(err.code).toBe("KIBO_WASM_ERROR");
    expect(err.message).not.toContain("not bundled");
    expect(err.message).toContain("failed to load");
    expect(err.message).toContain("exports is not defined");
    expect((err as { cause?: unknown }).cause).toBe(cause);
    expect(err.context["path"]).toBe("/x/a.js");
  });

  it("treats a missing sibling file (the _bg.wasm the glue reads) as a failure, not as a missing glue", async () => {
    const err = (await loadZkGlue({ candidates: ["/x/a.js"], importGlue: async () => { throw enoent("/x/a_bg.wasm"); } }).catch((e) => e)) as KError;
    expect(err.message).toContain("failed to load");
    expect(err.message).toContain("a_bg.wasm");
  });

  it("rejects a module that lacks zk_encrypt / zk_decrypt", async () => {
    const err = (await loadZkGlue({ candidates: ["/x/a.js"], importGlue: async () => ({ other: 1 }) }).catch((e) => e)) as KError;
    expect(err.message).toContain("does not export zk_encrypt and zk_decrypt");
  });
});

describe("nodeDeps (default loader) against CommonJS glue inside an ESM package", () => {
  const root = mkdtempSync(join(tmpdir(), "kibo-loader-"));
  writeFileSync(join(root, "package.json"), JSON.stringify({ type: "module" }));
  const wasmDir = join(root, "wasm");
  const srcDir = join(root, "src");
  mkdirSync(wasmDir);
  mkdirSync(srcDir);
  const moduleUrl = pathToFileURL(join(srcDir, "crypto.ts")).href;

  it("reports a missing core as not bundled", async () => {
    const err = (await loadZkGlue(nodeDeps(moduleUrl)).catch((e) => e)) as KError;
    expect(err.message).toContain("not bundled");
  });

  it("loads a .js CommonJS glue (exports/require/__dirname) that plain import cannot", async () => {
    writeFileSync(
      join(wasmDir, "kibo_kms_rest_ffi.js"),
      `const fs = require("fs");\nconst here = __dirname;\nexports.zk_encrypt = async () => ({ envelope: [1], dir: here, hasFs: typeof fs.readFileSync });\nexports.zk_decrypt = async () => ({ plaintext: [2] });\n`,
    );
    const mod = await loadZkGlue(nodeDeps(moduleUrl));
    const out = (await mod.zk_encrypt({})) as { dir: string; hasFs: string };
    expect(out.dir).toBe(wasmDir);
    expect(out.hasFs).toBe("function");
  });

  it("reports a glue that throws while loading as failed, with the cause", async () => {
    writeFileSync(join(wasmDir, "kibo_kms_rest_ffi.cjs"), `throw new Error("bad wasm header");`);
    const err = (await loadZkGlue(nodeDeps(moduleUrl)).catch((e) => e)) as KError;
    expect(err.message).toContain("failed to load");
    expect(err.message).toContain("bad wasm header");
    expect((err as { cause?: Error }).cause?.message).toBe("bad wasm header");
  });
});
