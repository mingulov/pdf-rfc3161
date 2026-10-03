// T16 pilot: OPTIONAL bounded exploration. Fuzzes every target with the
// contract budgets (60 s each, 2 s input timeout, 1 GiB RSS, 64 KiB
// input) inside an outer process timeout. Explores a scratch copy of
// the seeds so the checked-in corpus stays pristine; findings and run
// metadata land under fuzz/work/explore/ for upload. Any crash, hang,
// or unexpected exception fails this script with artifact paths.
//
// Usage: node fuzz/explore.mjs [target-name...]  (from packages/tests)
import { spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
    EXPLORE_SECONDS,
    INPUT_TIMEOUT_MS,
    INPUT_TIMEOUT_S,
    MAX_LEN,
    OUTER_TIMEOUT_S,
    RSS_LIMIT_MB,
    TARGETS,
} from "./targets.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const buildDir = join(here, "build");
const workDir = join(here, "work", "explore");
const jazzerCli = resolve(here, "../node_modules/@jazzer.js/core/dist/cli.js");

function runExplore(target) {
    const targetPath = join(buildDir, "tests/fuzz/targets", `${target.module}.js`);
    const runDir = join(workDir, target.name);
    const scratchCorpus = join(runDir, "corpus");
    rmSync(runDir, { recursive: true, force: true });
    mkdirSync(scratchCorpus, { recursive: true });
    cpSync(join(here, "corpus", target.corpus), scratchCorpus, { recursive: true });
    const args = [
        String(OUTER_TIMEOUT_S),
        "node",
        jazzerCli,
        targetPath,
        scratchCorpus,
        "-i",
        join(buildDir, "core"),
        "--timeout",
        String(INPUT_TIMEOUT_MS),
        ...(target.sync ? ["--sync"] : []),
        "--",
        `-max_total_time=${String(EXPLORE_SECONDS)}`,
        `-timeout=${String(INPUT_TIMEOUT_S)}`,
        `-max_len=${String(MAX_LEN)}`,
        `-rss_limit_mb=${String(RSS_LIMIT_MB)}`,
    ];
    const started = Date.now();
    const run = spawnSync("timeout", args, {
        encoding: "utf8",
        maxBuffer: 16 * 1024 * 1024,
        cwd: runDir,
    });
    const elapsedMs = Date.now() - started;
    writeFileSync(
        join(runDir, "run.log"),
        `$ timeout ${args.join(" ")}\nexit=${String(run.status)} elapsedMs=${String(elapsedMs)}\n--- stdout ---\n${run.stdout ?? ""}\n--- stderr ---\n${run.stderr ?? ""}\n`
    );
    const doneLine = `${run.stdout ?? ""}\n${run.stderr ?? ""}`
        .split("\n")
        .find((line) => line.startsWith("Done "));
    const entries = existsSync(scratchCorpus) ? readdirSync(scratchCorpus).length : 0;
    const artifacts = readdirSync(runDir).filter(
        (file) =>
            file.startsWith("crash-") || file.startsWith("leak-") || file.startsWith("timeout-")
    );
    return {
        status: run.status,
        elapsedMs,
        doneLine: doneLine ?? "(no Done line)",
        entries,
        artifacts,
        runDir,
    };
}

const wanted = new Set(process.argv.slice(2));
const selected = wanted.size === 0 ? TARGETS : TARGETS.filter((t) => wanted.has(t.name));
if (wanted.size > 0 && selected.length !== wanted.size) {
    console.error(`EXPLORE_FAIL: unknown target in [${[...wanted].join(", ")}]`);
    process.exit(1);
}
if (!existsSync(jazzerCli)) {
    console.error("EXPLORE_FAIL: Jazzer CLI missing (run pnpm install, then fuzz:build)");
    process.exit(1);
}

let failed = 0;
for (const target of selected) {
    const { status, elapsedMs, doneLine, entries, artifacts, runDir } = runExplore(target);
    if (status !== 0 || artifacts.length > 0) {
        failed += 1;
        console.error(
            `EXPLORE_FINDING ${target.name}: exit=${String(status)} ${doneLine} ` +
                `corpusEntries=${String(entries)} artifacts=[${artifacts.join(", ")}] dir=${runDir}`
        );
        continue;
    }
    console.log(
        `EXPLORE_PASS ${target.name}: ${doneLine} elapsedMs=${String(elapsedMs)} ` +
            `corpusEntries=${String(entries)} sync=${String(target.sync)}`
    );
}
if (failed > 0) {
    console.error(
        `EXPLORE_FAIL: ${String(failed)} target(s) with findings (see fuzz/work/explore/)`
    );
    process.exit(1);
}
console.log(`EXPLORE_DONE: ${String(selected.length)} target(s), no findings`);
