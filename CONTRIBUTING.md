# Contributing to ProofLayer Rules

Thanks for your interest. ProofLayer's rules layer is open source under [LICENSE](LICENSE) (Apache-2.0). Contributions welcome.

## How to contribute

1. **Filing an issue:** Use GitHub issues for bug reports and feature requests. Search existing issues first.

2. **Submitting a PR:**
   - Fork the repo
   - Create a feature branch (`git checkout -b feature/your-feature`)
   - Make changes; ensure tests pass (`pytest tests/`)
   - Commit with a clear message
   - Open a PR against `main`

3. **New detection rules:** PRs adding new rules must include:
   - A clear description of the attack pattern
   - A test case in `tests/` that triggers the rule
   - A sample positive and negative case

4. **Style:** Follow existing code conventions. Python 3.10+ assumed.

## Development setup

See [QUICKSTART.md](QUICKSTART.md) for the basic install. To run tests locally:

```bash
pip install -e ".[dev]"
pytest tests/
```

## Code of Conduct

By participating in this project, you agree to abide by the [Code of Conduct](CODE_OF_CONDUCT.md).

## Reporting security issues

Please do **not** open a public issue for security vulnerabilities. See [SECURITY.md](SECURITY.md) for the responsible disclosure process.

## License

By contributing, you agree your contributions will be licensed under the project's license (Apache-2.0).
