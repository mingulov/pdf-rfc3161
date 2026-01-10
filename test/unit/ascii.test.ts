import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, resolve, relative } from "node:path";
import { test } from "vitest";

/**
 * This test ensures that all source code and documentation files contain only ASCII characters.
 * It prevents emojis, smart quotes, long dashes, and other non-standard characters from being committed.
 */

const EXTENSIONS = [".ts", ".js", ".cjs", ".mjs", ".md", ".json"];
const EXCLUDE_DIRS = ["node_modules", ".git", "dist", "coverage", ".corpus"];
const EXCLUDE_FILES = ["dummy_token.der"]; // Specific binary fixtures or third-party files

function getFiles(dir: string, allFiles: string[] = []): string[] {
    const files = readdirSync(dir);
    for (const file of files) {
        const path = join(dir, file);
        if (EXCLUDE_DIRS.some((d) => path.includes(d))) continue;
        if (EXCLUDE_FILES.includes(file)) continue;

        if (statSync(path).isDirectory()) {
            getFiles(path, allFiles);
        } else {
            if (EXTENSIONS.some((ext) => file.endsWith(ext))) {
                allFiles.push(path);
            }
        }
    }
    return allFiles;
}

const rootDir = resolve(__dirname, "../..");
const filesToLink = getFiles(rootDir);

test("all files should contain only ASCII characters", () => {
    const violations: { file: string; line: number; char: string }[] = [];

    for (const file of filesToLink) {
        const content = readFileSync(file, "utf8");
        const lines = content.split("\n");

        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            if (line === undefined) continue;
            // Use range that avoids control characters if possible, or just printable ASCII
            const asciiRegex = /[^\x20-\x7E\t\r\n]/;
            const match = asciiRegex.exec(line);
            if (match) {
                violations.push({
                    file: relative(rootDir, file),
                    line: i + 1,
                    char: match[0],
                });
            }
        }
    }

    if (violations.length > 0) {
        const message = violations
            .map((v) => `${v.file}:${String(v.line)} - found non-ASCII character: "${v.char}"`)
            .join("\n");
        throw new Error(`Non-ASCII characters found in the following files:\n${message}`);
    }
});
