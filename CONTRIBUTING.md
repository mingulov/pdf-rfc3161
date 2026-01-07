# Contributing to pdf-rfc3161

Thank you for your interest in contributing! This document provides guidelines and information for contributors.

## Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/mingulov/pdf-rfc3161.git
   cd pdf-rfc3161
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Run tests:
   ```bash
   npm test
   ```

4. Build the project:
   ```bash
   npm run build
   ```

## Project Structure

```
pdf-rfc3161/
├── src/
│   ├── index.ts          # Public API exports
│   ├── types.ts          # TypeScript interfaces
│   ├── constants.ts      # OIDs and constants
│   ├── tsa/              # TSA client layer
│   │   ├── request.ts    # TimeStampReq creation
│   │   ├── response.ts   # TimeStampResp parsing
│   │   └── client.ts     # HTTP communication
│   └── pdf/              # PDF manipulation layer
│       ├── prepare.ts    # PDF preparation
│       └── embed.ts      # Token embedding
├── test/
│   ├── unit/             # Unit tests (mocked)
│   └── integration/      # Integration tests (real TSAs)
└── examples/             # Usage examples
```

## Running Tests

```bash
# All tests
npm test

# Watch mode
npm run test:watch

# With coverage
npm run test:coverage

# Only unit tests
npm test -- --filter unit

# Only integration tests (requires network)
npm test -- --filter integration
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
