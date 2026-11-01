import { expect } from "chai";
import * as fs from "fs";
import * as path from "path";
import * as ts from "typescript";

// The shared TypeScript helper is an ES module, so compile its real source file on the fly and evaluate it here.
function loadSharedCanonical(): any {
  const file = path.join(__dirname, "../../shared/canonical.ts");
  const js = ts.transpileModule(fs.readFileSync(file, "utf-8"), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 },
  }).outputText;
  const mod: any = { exports: {} };
  new Function("module", "exports", "require", "crypto", js)(mod, mod.exports, require, (globalThis as any).crypto);
  return mod.exports;
}

describe("Cross-language canonical JSON", function () {
  const vectors = JSON.parse(fs.readFileSync(path.join(__dirname, "../../shared/canonical_vectors.json"), "utf-8"));
  const canon = loadSharedCanonical();

  it("BC-AUD-08 TypeScript canonical JSON equals the Python reference for every vector", function () {
    for (const v of vectors) {
      expect(canon.canonicalJson(v.value)).to.equal(v.canonical);
    }
  });

  it("BC-AUD-08 TypeScript sha256 of the canonical form equals the Python hash for every vector", async function () {
    for (const v of vectors) {
      expect(await canon.canonicalHash(v.value)).to.equal(v.sha256);
    }
  });
});
