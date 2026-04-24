# Contributing to FingerTrap Detector

Thanks for your interest in making AI agents more secure. Contributions are welcome and appreciated.

---

## Ways to Contribute

- **New detection signatures** — found a novel prompt injection or exfiltration pattern? Open an issue or PR.
- **Bug reports** — false positives, missed detections, edge cases.
- **Documentation** — clearer examples, better OWASP mapping explanations.
- **Tests** — more adversarial payloads, edge case coverage.

---

## Getting Started

```bash
git clone https://github.com/mradamu31/detector.git
cd detector
npm install
```

The core detection logic lives in `detector.js`. Signatures and pattern lists are inline — easy to read and extend.

---

## Submitting Changes

1. Fork the repo and create a branch (`fix/my-fix` or `feat/my-feature`)
2. Keep changes focused — one logical change per PR
3. Test against the existing examples in `README.md`
4. Open a pull request with a clear description of what changed and why

---

## Reporting Vulnerabilities

**Do not open a public issue for security vulnerabilities.**

Email: [security@fingertrap.io](mailto:security@fingertrap.io)

We'll respond within 48 hours and coordinate a fix before any public disclosure.

---

## Code Style

- ESM modules (`import`/`export`), no CJS
- No build step — what ships to npm is what you write
- Keep dependencies minimal — this is a drop-in library

---

## Questions?

Open a GitHub issue or reach out at [fingertrap.io](https://fingertrap.io).
