# Contributing to Clampd

Thanks for your interest in contributing to Clampd.

## Reporting Issues

Open a [GitHub Issue](https://github.com/clampd/clampd/issues) with:

- What you expected to happen
- What actually happened
- Steps to reproduce
- Version (`clampd --version` or Docker image tag)

## Feature Requests

Open an issue with the `enhancement` label. Describe the use case, not just the solution.

## Pull Requests

1. Fork the repo and create a branch from `main`
2. Write tests for any new functionality
3. Run the test suite: `cargo test --workspace` (services) or `npm test` / `pytest` (SDKs)
4. Keep PRs focused — one feature or fix per PR
5. Update documentation if you changed behavior

### What we accept

- Bug fixes with test coverage
- SDK improvements (Python, TypeScript)
- Documentation improvements
- New detection rules (submit as TOML in a PR with test cases)
- Docker/deployment improvements

### What requires discussion first

- New services or architectural changes
- Changes to the detection pipeline
- Changes to the licensing or auth flow

Open an issue to discuss before investing time in a large PR.

## Development Setup

```bash
# Clone
git clone https://github.com/clampd/clampd.git
cd clampd

# Rust services
cd services && cargo test --workspace

# Python SDK
cd sdk/python && pip install -e ".[all,dev]" && pytest

# TypeScript SDK
cd sdk/typescript && npm install && npm test
```

## Code Style

- **Rust**: `cargo fmt` + `cargo clippy`
- **TypeScript**: Prettier + ESLint
- **Python**: Ruff

## License

By contributing, you agree that your contributions will be licensed under the same license as the component you're contributing to (Apache 2.0 for SDKs, BSL 1.1 for services).
