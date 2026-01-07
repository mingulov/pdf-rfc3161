import { fileURLToPath } from "node:url";
import { dirname, resolve, join } from "node:path";
import { execSync, execFileSync } from "node:child_process";
import { existsSync, mkdirSync } from "node:fs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const REPO_URL = "https://github.com/py-pdf/sample-files.git";
const CORPUS_DIR = resolve(__dirname, "../.corpus");
const REPO_DIR = join(CORPUS_DIR, "py-pdf-sample-files");

async function main() {
    console.log("📂 Preparing PDF corpus...");

    if (!existsSync(CORPUS_DIR)) {
        mkdirSync(CORPUS_DIR);
    }

    if (existsSync(REPO_DIR)) {
        console.log(`Changes detected in ${REPO_DIR}, updating...`);
        try {
            execFileSync("git", ["pull"], { stdio: "inherit", cwd: REPO_DIR });
        } catch (error) {
            console.error("Failed to update corpus:", error);
            process.exit(1);
        }
    } else {
        console.log(`Cloning ${REPO_URL} into ${REPO_DIR}...`);
        try {
            execFileSync("git", ["clone", REPO_URL, REPO_DIR], { stdio: "inherit" });
        } catch (error) {
            console.error("Failed to clone corpus:", error);
            process.exit(1);
        }
    }

    console.log("✅ Corpus ready!");
}

main().catch((err) => {
    console.error(err);
    process.exit(1);
});
