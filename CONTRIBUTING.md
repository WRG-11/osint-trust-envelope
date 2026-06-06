# Contributing

`osint-trust-envelope` is a single-author, low-traffic project. Contributions are welcome,
but review time is limited and scope control matters.

## Before You Start

- Search existing issues and pull requests first.
- Open an issue before starting larger work or behavior changes.
- Small docs fixes and test-only fixes can go straight to PR.

## Triage Expectations

There is no guaranteed SLA. For small PRs, expect a best-effort review when the
maintainer is active. For larger proposals, an issue may sit until there is a
clear use case, reproduction, or maintainer need.

## Local Dev Setup

```bash
git clone https://github.com/WRG-11/osint-trust-envelope.git
cd osint-trust-envelope
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
python -m pip install -e .[dev]
pytest
```

## Bar for Accepting a PR

- Tests pass locally and in CI.
- No scope creep: one problem per PR.
- Keep the diff at or below 200 LOC unless prearranged in an issue.
- Add or update tests when behavior changes.
- Update README or CHANGELOG only when the user-facing surface changes.
- Do not add dependencies — the core library is intentionally zero-dependency (stdlib only).

## Commit Messages

Use clear, concise commit messages. Conventional commit style is preferred:

- `feat: add rule export filter`
- `fix: handle empty verdict results`
- `docs: update installation notes`

## Security Issues

Do not open public issues for security vulnerabilities. Use GitHub Security Advisories:

- https://github.com/WRG-11/osint-trust-envelope/security/advisories
