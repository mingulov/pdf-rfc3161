# Contributing to pdf-rfc3161

Thank you for your interest in contributing! This document provides guidelines and information for contributors.

## Development Setup

The project is a monorepo managed by `pnpm`.

1. Clone and install dependencies:

    ```bash
    git clone https://github.com/mingulov/pdf-rfc3161.git
    cd pdf-rfc3161
    pnpm install
    ```

2. Build all packages:

    ```bash
    pnpm -r build
    ```

3. Run tests:
    ```bash
    pnpm -r test
    ```

## Project Structure

```
pdf-rfc3161/
|-- packages/
|   |-- core/             # Core library (signing, timestamping, utilities)
|   |-- cli/              # Command-line interface
|   |-- tests/            # Test suite (unit & integration)
|   `-- demo/             # Demo application (Vite/React)
|-- pnpm-workspace.yaml   # Workspace configuration
`-- package.json          # Root scripts
```

## Running Tests

```bash
# All tests
pnpm -r test

# Specific package
pnpm --filter pdf-rfc3161 test

# Watch mode (in package directory)
pnpm test:watch
```

## Code Style

- Use TypeScript strict mode
- Follow existing code patterns
- Add JSDoc comments for public APIs
- Keep functions small and focused

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass (`npm test`)
6. Ensure type checking passes (`npm run typecheck`)
7. Commit your changes (`git commit -m 'Add amazing feature'`)
8. Push to your fork (`git push origin feature/amazing-feature`)
9. Open a Pull Request

## Reporting Bugs

Please use the GitHub issue tracker and include:

- Node.js version
- Operating system
- Steps to reproduce
- Expected vs actual behavior
- Any error messages

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
