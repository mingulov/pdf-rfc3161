import eslint from "@eslint/js";
import tseslint from "typescript-eslint";
import security from "eslint-plugin-security";

export default tseslint.config(
    eslint.configs.recommended,
    ...tseslint.configs.strictTypeChecked,
    ...tseslint.configs.stylisticTypeChecked,
    {
        languageOptions: {
            parserOptions: {
                projectService: true,
                tsconfigRootDir: import.meta.dirname,
            },
        },
    },
    {
        plugins: {
            security,
        },
        rules: {
            // Security rules
            "security/detect-object-injection": "off",
            "security/detect-non-literal-regexp": "warn",
            "security/detect-unsafe-regex": "error",
            "security/detect-buffer-noassert": "error",
            "security/detect-eval-with-expression": "error",
            "security/detect-no-csrf-before-method-override": "error",
            "security/detect-possible-timing-attacks": "warn",

            // TypeScript specific
            "@typescript-eslint/no-unused-vars": [
                "error",
                { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
            ],
            "@typescript-eslint/explicit-function-return-type": "off",
            "@typescript-eslint/no-explicit-any": "warn",
            "@typescript-eslint/prefer-nullish-coalescing": "error",
            "@typescript-eslint/prefer-optional-chain": "error",
            "@typescript-eslint/strict-boolean-expressions": "off",

            // General
            "no-console": ["warn", { allow: ["warn", "error"] }],
            eqeqeq: ["error", "always"],
            "prefer-const": "error",
        },
    },
    {
        files: [
            "**/*.test.ts",
            "**/test/utils/**/*",
            "packages/cli/src/**/*.ts",
            "**/test/integration/**/*.ts",
        ],
        rules: {
            // Relax some rules for tests and CLI
            "@typescript-eslint/no-explicit-any": "off",
            "@typescript-eslint/no-unsafe-assignment": "off",
            "@typescript-eslint/no-unsafe-member-access": "off",
            "@typescript-eslint/no-unsafe-call": "off",
            "@typescript-eslint/no-unsafe-argument": "off",
            "@typescript-eslint/require-await": "off",
            "@typescript-eslint/no-require-imports": "off",
            "@typescript-eslint/no-unnecessary-type-assertion": "off",
            "@typescript-eslint/no-non-null-assertion": "off",
            "@typescript-eslint/no-confusing-void-expression": "off",
            "@typescript-eslint/unbound-method": "off",
            "@typescript-eslint/restrict-template-expressions": "off",
            "@typescript-eslint/no-empty-function": "off",
            "@typescript-eslint/dot-notation": "off",
            "security/detect-object-injection": "off",
            "security/detect-unsafe-regex": "off",
            "no-console": "off",
        },
    },
    {
        ignores: ["dist/", "node_modules/", "coverage/", "*.config.ts", "*.config.js"],
    }
);
