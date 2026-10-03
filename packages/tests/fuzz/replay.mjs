// T16 pilot: REQUIRED corpus-replay gate. Replays the checked-in nonempty
// seeds for every target in Jazzer.js regression mode with coverage, then
// proves coverage reaches EACH intended core function (not just "ran").
// Any nonzero Jazzer exit (crash, hang, unexpected exception, network
// attempt) or any uncovered intended function fails this script.
//
// Usage: node fuzz/replay.mjs  (from packages/tests, after fuzz:build)
import { spawnSync } from "node:child_process";
import {
    existsSync,
    mkdirSync,
    readdirSync,
    readFileSync,
    unlinkSync,
    writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
    INPUT_TIMEOUT_MS,
    INPUT_TIMEOUT_S,
    MAX_LEN,
    OUTER_TIMEOUT_S,
    RSS_LIMIT_MB,
    TARGETS,
} from "./targets.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const buildDir = join(here, "build");
const workDir = join(here, "work", "replay");
const jazzerCli = resolve(here, "../node_modules/@jazzer.js/core/dist/cli.js");

function fail(message) {
    console.error(`REPLAY_FAIL: ${message}`);
    process.exitCode = 1;
}

function checkPrereqs() {
    if (!existsSync(jazzerCli)) {
        fail(`Jazzer CLI missing at ${jazzerCli} (run pnpm install)`);
        return false;
    }
    const timeout = spawnSync("timeout", ["--version"], { encoding: "utf8" });
    if (timeout.status !== 0 || timeout.error !== undefined) {
        fail("`timeout` (coreutils) is required for the outer process bound");
        return false;
    }
    let ok = true;
    for (const target of TARGETS) {
        const modulePath = join(buildDir, "tests/fuzz/targets", `${target.module}.js`);
        if (!existsSync(modulePath)) {
            fail(`missing built target ${modulePath} (run fuzz:build)`);
            ok = false;
        }
        const corpusDir = join(here, "corpus", target.corpus);
        if (!existsSync(corpusDir) || readdirSync(corpusDir).length === 0) {
            fail(`corpus ${corpusDir} is missing or empty; seeds must be checked in`);
            ok = false;
        }
    }
    return ok;
}

function runReplay(target) {
    const targetPath = join(buildDir, "tests/fuzz/targets", `${target.module}.js`);
    const corpusDir = join(here, "corpus", target.corpus);
    const covDir = join(workDir, `cov-${target.name}`);
    mkdirSync(covDir, { recursive: true });
    // Fresh coverage per target so the proof below cannot pass on stale data.
    const staleCov = join(covDir, "coverage-final.json");
    if (existsSync(staleCov)) unlinkSync(staleCov);
    const args = [
        String(OUTER_TIMEOUT_S),
        "node",
        jazzerCli,
        targetPath,
        corpusDir,
        "-i",
        join(buildDir, "core"),
        "--timeout",
        String(INPUT_TIMEOUT_MS),
        ...(target.sync ? ["--sync"] : []),
        "--coverage",
        "--coverage_reporters=json",
        `--coverage_directory=${covDir}`,
        "-m",
        "regression",
        "--",
        `-timeout=${String(INPUT_TIMEOUT_S)}`,
        `-max_len=${String(MAX_LEN)}`,
        `-rss_limit_mb=${String(RSS_LIMIT_MB)}`,
    ];
    const started = Date.now();
    const run = spawnSync("timeout", args, { encoding: "utf8", maxBuffer: 16 * 1024 * 1024 });
    const elapsedMs = Date.now() - started;
    const logPath = join(workDir, `${target.name}.log`);
    mkdirSync(workDir, { recursive: true });
    writeFileSync(
        logPath,
        `$ timeout ${args.join(" ")}\nexit=${String(run.status)} elapsedMs=${String(elapsedMs)}\n--- stdout ---\n${run.stdout ?? ""}\n--- stderr ---\n${run.stderr ?? ""}\n`
    );
    return { status: run.status, elapsedMs, logPath, covDir };
}

function proveCoverage(target, covDir) {
    const covPath = join(covDir, "coverage-final.json");
    if (!existsSync(covPath)) {
        return { ok: false, detail: `missing ${covPath}` };
    }
    const coverage = JSON.parse(readFileSync(covPath, "utf8"));
    const fileKey = Object.keys(coverage).find((key) => key.endsWith(target.coreFile));
    if (fileKey === undefined) {
        return { ok: false, detail: `no coverage entry ending in ${target.coreFile}` };
    }
    const entry = coverage[fileKey];
    const hits = [];
    for (const name of target.functions) {
        const ids = Object.keys(entry.fnMap).filter((id) => entry.fnMap[id].name === name);
        if (ids.length === 0) {
            return { ok: false, detail: `${target.coreFile} has no function named ${name}` };
        }
        const count = ids.reduce((sum, id) => sum + (entry.f[id] ?? 0), 0);
        if (count === 0) {
            return { ok: false, detail: `${name} covered 0 times` };
        }
        hits.push(`${name}x${String(count)}`);
    }
    return { ok: true, detail: `${target.coreFile} ${hits.join(" ")}` };
}

if (!checkPrereqs()) process.exit(1);

let failed = 0;
for (const target of TARGETS) {
    const seeds = readdirSync(join(here, "corpus", target.corpus)).length;
    const { status, elapsedMs, logPath, covDir } = runReplay(target);
    if (status !== 0) {
        failed += 1;
        fail(
            `${target.name}: jazzer exit=${String(status)} after ${String(elapsedMs)}ms (see ${logPath})`
        );
        continue;
    }
    const proof = proveCoverage(target, covDir);
    if (!proof.ok) {
        failed += 1;
        fail(`${target.name}: ${proof.detail}`);
        continue;
    }
    console.log(
        `REPLAY_PASS ${target.name}: ${String(seeds)} seeds, ${String(elapsedMs)}ms, ` +
            `sync=${String(target.sync)}, coverage: ${proof.detail}`
    );
}

if (failed > 0) {
    fail(`${String(failed)} target(s) failed`);
} else {
    console.log(`REPLAY_GREEN: all ${String(TARGETS.length)} targets replayed with coverage proof`);
}
