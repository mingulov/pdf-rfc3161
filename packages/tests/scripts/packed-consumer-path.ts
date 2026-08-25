import { isAbsolute, relative, sep } from "node:path";

export interface PathOperations {
    isAbsolute(path: string): boolean;
    relative(from: string, to: string): string;
    sep: string;
}

const nativePathOperations: PathOperations = { isAbsolute, relative, sep };

export function isPathWithinRoot(
    root: string,
    target: string,
    operations: PathOperations = nativePathOperations
): boolean {
    const relativePath = operations.relative(root, target);
    return (
        relativePath === "" ||
        (!operations.isAbsolute(relativePath) &&
            relativePath !== ".." &&
            !relativePath.startsWith(`..${operations.sep}`))
    );
}
