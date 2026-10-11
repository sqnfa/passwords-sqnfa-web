# Release notes

## 1.0.2

- Fixed npm publication with npm 12's package-keyed `npm pack --json` output while retaining support for earlier CLI versions.
- Pinned the publishing CLI to npm 12.2.0.

## 1.0.1

- Fixed GitHub CI on Node 22 by removing an unsupported test-runner flag.

## 1.0.0

- Configurable password validation with a 15-code-point minimum and 1,024-byte default limit.
- Unicode NFC normalization, full-value blocklists, and support for spaces and passphrases without composition rules or truncation.
- Word, email-context, regex, and Pwned Passwords checks; native Web Crypto lookup identifiers and padded response handling.
- Synchronous and asynchronous extension contracts registered through `use()`, fluent subclass support, and stop-on-failure defaults.
- Independent results and timing statistics for overlapping asynchronous calls.
- Public TypeScript declarations, ESM, CommonJS, and browser builds with no runtime npm dependencies.
- Vanilla JavaScript and Angular 21 LTS samples with password-manager support, visibility controls, and rejection guidance.
- TypeScript 7.0.2 tooling, standards regression tests, browser verification, dependency audits, and CI.
- Documented NIST SP 800-63B-4 and OWASP policy mapping and optional OPAQUE integration boundaries.
