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
        files: ["**/*.test.ts"],
        rules: {
            // Relax some rules for tests
            "@typescript-eslint/no-explicit-any": "off",
            "@typescript-eslint/no-unsafe-assignment": "off",
            "@typescript-eslint/no-unsafe-member-access": "off",
            "@typescript-eslint/no-unsafe-call": "off",
            "security/detect-object-injection": "off",
            "security/detect-unsafe-regex": "off",
            "no-console": "off",
        },
    },
    {
        ignores: ["dist/", "node_modules/", "coverage/", "*.config.ts", "*.config.js"],
    }
);
