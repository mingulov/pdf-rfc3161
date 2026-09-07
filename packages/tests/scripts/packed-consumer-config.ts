import { writeFileSync } from "node:fs";
import { join } from "node:path";

export function writeConsumerWorkspace(consumerDirectory: string, coreTarballPath: string): void {
    // pnpm 12 reads overrides from pnpm-workspace.yaml. JSON is valid YAML.
    writeFileSync(
        join(consumerDirectory, "pnpm-workspace.yaml"),
        JSON.stringify({ overrides: { "pdf-rfc3161": "file:" + coreTarballPath } }, null, 4) + "\n",
        "utf8"
    );
}
