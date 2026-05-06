# Contributing to ProofLayer Runtime

Thanks for your interest in contributing. `prooflayer-runtime` is the open core of the ProofLayer security platform — the runtime engine, rule loader, action engine, and core MCP-attack rule pack. Community contributions to any of these are welcome.

## What's in scope

- **New detection rules** — additional YAML rules under `prooflayer/rules/` (prompt injection, command injection, jailbreaks, data exfiltration, role manipulation, tool poisoning, SQL injection, SSRF/XXE, or new categories).
- **Transport / interceptor improvements** — better stdio, SSE, or HTTP wrapping; additional MCP gateway integrations.
- **Action engine** — richer ALLOW/WARN/BLOCK/KILL semantics, structured event output, OpenTelemetry traces.
- **Tests, fuzzing, and benchmarks** — increased coverage, new attack-pack fixtures, latency regressions.
- **Documentation** — clearer examples, deployment guides, integration tutorials.

## What's NOT in scope here

The closed-source detector model (LoRA + GRPO training) and any hosted control plane / dashboard work live in separate, proprietary repositories. PRs that try to depend on or reimplement those components in this repo will be redirected.

## Developer Certificate of Origin (DCO)

We use the **Developer Certificate of Origin** ([DCO](https://developercertificate.org/)) instead of a CLA. By adding a `Signed-off-by` line to your commits, you assert that you wrote the contribution or otherwise have the right to submit it under the project's open-source license (Apache 2.0).

Sign your commits with `-s`:

```bash
git commit -s -m "feat: add detection rule for X"
```

Each commit message will get a trailing line like:

```
Signed-off-by: Your Name <your.email@example.com>
```

PRs without DCO sign-off on every commit will be asked to amend before merge.

## Workflow

1. **Open an issue** for non-trivial changes before writing code, especially for new categories of rules or interceptor changes. This keeps the design conversation lightweight.
2. **Fork the repo**, branch from `main`, name your branch descriptively (e.g. `feat/rule-cmd-inject-zsh-globs`, `fix/transport-stdio-buffering`).
3. **Write tests** for new rules and any interceptor logic. Use the existing fixtures under `tests/` as a guide.
4. **Run the test suite** locally:
   ```bash
   pip install -e .[dev]
   pytest
   ```
5. **Open a PR** against `main`. Reference any related issue. Describe what changed and why.
6. **Iterate on review.** A maintainer will leave feedback; expect at least one round.

## Style

- **Python**: match the surrounding code; the repo uses standard type hints and `mypy`.
- **YAML rules**: follow the existing rule schema (`id`, `severity`, `category`, `message`, `pattern`, `score`, `owasp`). Use stable rule IDs that won't be reused.
- **Commit messages**: conventional-commits style (`feat:`, `fix:`, `chore:`, `docs:`, `test:`).

## Reporting security issues

Do **not** file public issues for vulnerabilities. Email security@sinewave.ai with details. We'll coordinate disclosure.

## License of contributions

By submitting a contribution, you agree it is licensed under [Apache 2.0](LICENSE) (the project's license). The DCO sign-off is your assertion that you have the right to do so.

---

If anything here is unclear or you want to discuss a contribution before opening a PR, open a discussion or reach out via the email above.
