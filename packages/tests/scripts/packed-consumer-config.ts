import { writeFileSync } from "node:fs";
import { join } from "node:path";

export function writeConsumerWorkspace(consumerDirectory: string, coreTarballPath: string): void {
    // pnpm 12 reads overrides from pnpm-workspace.yaml. Block style (not
    // inline JSON) so pnpm can edit the file in place, and esbuild builds
    // pre-approved: the packed gate bundles with the same esbuild pin the
    // repo itself trusts, whose postinstall pnpm would otherwise refuse to
    // approve against an uneditable manifest.
    writeFileSync(
        join(consumerDirectory, "pnpm-workspace.yaml"),
        "overrides:\n" +
            "  pdf-rfc3161: " +
            JSON.stringify("file:" + coreTarballPath) +
            "\nallowBuilds:\n  esbuild: true\n",
        "utf8"
    );
}
