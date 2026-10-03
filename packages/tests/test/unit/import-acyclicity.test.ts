import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// Audit S1: `src/index.ts` <-> `src/pdf/archive.ts` used to import each
// other at value level (index re-exports archiveTimestamp; archive called
// timestampPdf). The one-call API now lives in a focused internal module
// (`src/timestamp-pdf.ts`) that both import, so the entry is a DAG root.
// This test scans the real source import graph and fails on any value
// cycle through the entry. Type-only edges (`import type`, `export type`,
// inline `type X` specifiers) are erased at emit and ignored.
//
// Out of scope (pre-existing, ESM-tolerated, untouched): the value cycle
// `pki/pki-utils.ts` <-> `tsa/token-validation.ts`. Only entry cycles are
// pinned here; see the T19 report.

const HERE = dirname(fileURLToPath(import.meta.url));
const CORE_SRC = resolve(HERE, "../../../core/src");

function coreSources(): string[] {
    const files: string[] = [];
    const walk = (directory: string): void => {
        for (const entry of readdirSync(directory, { withFileTypes: true })) {
            const path = resolve(directory, entry.name);
            if (entry.isDirectory()) walk(path);
            else if (entry.isFile() && entry.name.endsWith(".ts")) files.push(path);
        }
    };
    walk(CORE_SRC);
    return files.sort();
}

// True when an import/export clause carries at least one runtime binding.
// `import type ...` / `export type ...` and all-inline-type braces are
// erased, so they contribute no runtime graph edge.
export function clauseHasValueBinding(clause: string): boolean {
    if (/^\s*type[\s{]/.exec(clause) !== null) return false;
    const braced = /\{([\s\S]{0,2000})\}/.exec(clause);
    if (braced?.[1] === undefined) return clause.trim().length > 0;
    // A default binding before the braces (e.g. `Foo` in
    // `Foo, { type Bar }`) is a runtime binding on its own.
    const beforeBraces = clause.slice(0, braced.index).replace(",", "").trim();
    if (beforeBraces.length > 0) return true;
    return braced[1]
        .split(",")
        .map((specifier) => specifier.trim())
        .some((specifier) => specifier.length > 0 && /^(type|typeof)\s/.exec(specifier) === null);
}

// Value-level relative targets of one source file, resolved to paths.
export function valueImportTargets(sourcePath: string, knownFiles: Set<string>): string[] {
    const text = readFileSync(sourcePath, "utf8");
    const targets: string[] = [];
    const statement = /^(?:import|export)\b([^;]{1,2000}?)\bfrom\s{1,10}(["'])(\.[^"']{1,200})\2/gm;
    for (const match of text.matchAll(statement)) {
        const clause = match[1] ?? "";
        const specifier = match[3] ?? "";
        if (!clauseHasValueBinding(clause)) continue;
        if (!specifier.endsWith(".js")) continue;
        const resolved = resolve(dirname(sourcePath), specifier.slice(0, -3) + ".ts");
        if (knownFiles.has(resolved)) targets.push(resolved);
    }
    return targets;
}

// A cycle path through `entry` (entry listed first and last), or undefined
// when no value path from the entry leads back to it.
export function findCycleThroughEntry(
    graph: ReadonlyMap<string, readonly string[]>,
    entry: string
): string[] | undefined {
    const entryTargets = graph.get(entry) ?? [];
    for (const start of entryTargets) {
        const stack: string[] = [entry, start];
        const onStack = new Set(stack);
        const visit = (node: string): string[] | undefined => {
            for (const next of graph.get(node) ?? []) {
                if (next === entry) return [...stack, entry];
                if (onStack.has(next)) continue;
                onStack.add(next);
                stack.push(next);
                const found = visit(next);
                if (found !== undefined) return found;
                stack.pop();
                onStack.delete(next);
            }
            return undefined;
        };
        const found = visit(start);
        if (found !== undefined) return found;
    }
    return undefined;
}

describe("core import acyclicity (S1)", () => {
    it("classifies value vs type-only clauses", () => {
        expect(clauseHasValueBinding("{ timestampPdf }")).toBe(true);
        expect(clauseHasValueBinding("{ type TimestampOptions }")).toBe(false);
        expect(clauseHasValueBinding("{ TimestampError, type TSAConfig }")).toBe(true);
        expect(clauseHasValueBinding("type { TrustStore }")).toBe(false);
        expect(clauseHasValueBinding("* as pkijs")).toBe(true);
        expect(clauseHasValueBinding("*")).toBe(true);
        expect(clauseHasValueBinding("PDFDocument")).toBe(true);
        // A default value binding keeps the edge even when every named
        // specifier is type-only (M1: `Foo, { type Bar }` used to read false).
        expect(clauseHasValueBinding("Foo, { type Bar }")).toBe(true);
        expect(clauseHasValueBinding("Foo, { Bar, type Baz }")).toBe(true);
        // `import type` with a default binding is still type-only.
        expect(clauseHasValueBinding("type Foo")).toBe(false);
    });

    it("finds entry cycles on synthetic graphs", () => {
        const cyclic = new Map<string, readonly string[]>([
            ["entry", ["a"]],
            ["a", ["b"]],
            ["b", ["entry"]],
        ]);
        expect(findCycleThroughEntry(cyclic, "entry")).toEqual(["entry", "a", "b", "entry"]);
        const acyclic = new Map<string, readonly string[]>([
            ["entry", ["a", "b"]],
            ["a", ["b"]],
            ["b", []],
        ]);
        expect(findCycleThroughEntry(acyclic, "entry")).toBeUndefined();
        // A cycle elsewhere in the graph is not an entry cycle.
        const elsewhere = new Map<string, readonly string[]>([
            ["entry", ["a"]],
            ["a", []],
            ["x", ["y"]],
            ["y", ["x"]],
        ]);
        expect(findCycleThroughEntry(elsewhere, "entry")).toBeUndefined();
    });

    it("has no value cycle through the main entry", () => {
        const files = coreSources();
        expect(files.length).toBeGreaterThan(50);
        const known = new Set(files);
        const graph = new Map<string, readonly string[]>();
        let edgeCount = 0;
        for (const file of files) {
            const targets = valueImportTargets(file, known);
            graph.set(file, targets);
            edgeCount += targets.length;
        }
        // Guards against a silently broken scanner: the real graph is dense.
        expect(edgeCount).toBeGreaterThan(100);
        const entry = resolve(CORE_SRC, "index.ts");
        expect(graph.get(entry)?.length).toBeGreaterThan(5);
        const cycle = findCycleThroughEntry(graph, entry);
        expect(
            cycle,
            cycle === undefined
                ? ""
                : "value cycle through src/index.ts: " +
                      cycle.map((node) => node.slice(CORE_SRC.length + 1)).join(" -> ")
        ).toBeUndefined();
    });

    it("keeps pdf/archive.ts off the entry import", () => {
        const files = coreSources();
        const known = new Set(files);
        const archive = resolve(CORE_SRC, "pdf/archive.ts");
        const entry = resolve(CORE_SRC, "index.ts");
        expect(valueImportTargets(archive, known)).not.toContain(entry);
    });
});
