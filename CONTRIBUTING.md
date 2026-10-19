# Contributing to openbao-agent-guard

Thank you for contributing to `openbao-agent-guard`! This repository implements defense-in-depth secret management and execution guardrails for autonomous AI coding agents.

---

## Security Philosophy & Guardrails

`openbao-agent-guard` enforces strict runtime barriers to ensure AI agents never exfiltrate or compromise credentials:

1. **DISPLAY Sink Refusal**: Direct `stdout`/`stderr` secret display is refused with error code 3.
2. **Tier-Based Path Segregation**: Tier 1 (`restricted/`) and Tier 2 (`services/`) paths enforce strict isolation.
3. **Working-Tree Protection**: Universal Git tracking protection prevents writing secrets into git-tracked or unignored files.
4. **Zero-Knowledge Hash Verification**: Agents receive SHA-256 integrity digests without reading raw secret strings into agent context.
5. **Strict File Permissions**: When secrets must be materialized for child processes, they are written with `0600` permissions into temporary paths outside source control.

---

## Local Development & Testing

### Prerequisites

- **Bash**: `v4.0+`
- **Docker Compose**: For integration tests with live OpenBao server
- **ShellCheck**: For script static analysis

### Running Tests

The test suite runs deterministically without requiring a live OpenBao container by using a hermetic CLI mock:

```bash
# Run the 7-suite security regression tests
./test/run-tests.sh
```

---

## Commit Conventions

We follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat(guard)`: New policy or verification capability
- `fix(guard)`: Bug fix or leak prevention enhancement
- `test(security)`: Test suite expansion
- `ci(github)`: Workflow improvements
- `docs(policy)`: Policy documentation updates

---

## Pull Requests

- Every change must pass `./test/run-tests.sh` with 0 failures.
- Never weaken existing security sinks or Git working-tree protections.
- Provide clear justification for any new sink or exemption.
