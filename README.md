# Passwords are sqnfa for web

A configurable client-side password validation pipeline with synchronous and asynchronous extension support. Built-in checks cover length, complete-password blocklists, account context, and Pwned Passwords. The package has no runtime npm dependencies.

## Install and use

```sh
npm install passwords-sqnfa-web
```

```javascript
import {PasswordsSqnfaWeb} from 'passwords-sqnfa-web';

const pipeline = new PasswordsSqnfaWeb()
  .useLengthHandler()
  .useBlackListHandler({caseInsensitiveWords: ['passwordpassword']});

const result = await pipeline.handle(password);
if (result.isSuccess) {
  // Use this NFC-normalized password in your application's authentication flow.
  const validatedPassword = result.getPassword();
} else {
  // Explain the failed policy and help the user choose a different passphrase.
  const failures = result.getFailures();
}
```

Handlers are registered explicitly and run in order. `stopOnFailure` defaults to `true`; a failed check stops further work. Pass `false` to collect failures across validation stages. Complete validation successfully before invoking authentication or other network work.

The pipeline and built-in handlers normalize passwords to Unicode NFC. Password case and leading/trailing whitespace are kept. Passwords are never truncated. Use the same normalization at registration and authentication, including your server or OPAQUE adapter.

ESM imports, CommonJS `require()`, TypeScript declarations, and an ES2022 browser script are provided. Load `build/passwords-sqnfa-web.min.js` to use `new PasswordsSqnfaWeb.PasswordsSqnfaWeb()` in a plain HTML page. For CommonJS, use `const {PasswordsSqnfaWeb} = require('passwords-sqnfa-web')`.

## Password guidance

The [NIST and OWASP guidance review](docs/password-guidance.md) maps current requirements to the code, samples, and server responsibilities. The length handler defaults to 15 Unicode code points and a 1,024-byte UTF-8 limit. This supports passphrases of at least 64 Unicode characters, including spaces and emoji. Configure a minimum of 8 only for passwords used exclusively with enforced MFA.

Blocklists compare complete passwords. A word or email token inside a longer passphrase does not cause a rejection. Regex patterns describe complete blocked values; do not use them to impose character-class composition rules.

Apply password selection policies when setting or changing passwords. At login, verify the enrolled credential using the same normalization. Client-side checks provide feedback; production servers must independently enforce policy, screen common/compromised passwords, limit authentication attempts, use authenticated TLS, and protect credentials and sessions.

## API

All classes and contracts below are exported from `passwords-sqnfa-web`. Every `use*` method returns `this` and accepts `stopOnFailure = true` as its final argument.

| Method                             | Configuration and behavior                                                                                                                                                                                                              |
| ---------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `useLengthHandler(config?)`        | `LengthConfiguration`: `minLength = 15` Unicode code points; `maxByteSize = 1024` UTF-8 bytes. Rejects values outside the configured limits.                                                                                            |
| `useBlackListHandler(config)`      | `BlackListConfiguration`: `caseInsensitiveWords: string[]` of complete common or expected password values. NFC-normalized, case-insensitive equality.                                                                                   |
| `useEmailBlackListHandler(config)` | `EmailBlackListConfiguration(email, minTokenLength = 1)`: derives complete blocked values from the email address, local part, account tokens, and domain labels excluding the final label. `minTokenLength` counts Unicode code points. |
| `useRegexHandler(config)`          | `RegexConfiguration`: `regExps: RegExp[]` of complete-password blocklist patterns. Global/sticky patterns are checked independently for each password.                                                                                  |
| `useHaveibeenpwnedHandler(config)` | `HaveibeenpwnedConfiguration(httpClient)`: checks the Pwned Passwords range API. `pwnedPasswordsUrl` defaults to `https://api.pwnedpasswords.com/range/`.                                                                               |
| `use(handler)`                     | Registers a `Handler` (`handle(password): Promise<Result>`) or `HandlerSync` (`handleSync(password): Result`). Both contracts require a `name`.                                                                                         |

Configuration classes can be instantiated or supplied as structurally matching objects. `LengthHandler`, `BlackListHandler`, `EmailBlackListHandler`, `RegexHandler`, and `HaveibeenpwnedHandler` can also be used directly.

`Result.ok(password)` and `Result.fail(failure | failures)` construct results. `isSuccess` selects `getPassword()` or `getFailures()`; requesting the other value throws. A `Failure` contains `handler`, `rule`, and numeric `expected`/`actual` values. Handler exceptions reject `handle()` and must be treated as an incomplete check.

`statistics` maps handler names to elapsed milliseconds for the last completed invocation, including the pipeline's total time. Overlapping invocations have independent failures, handler snapshots, and timings. If a handler throws, previously completed statistics remain available.

### Breach checking

`HaveibeenpwnedHttpClient.get(url): Promise<string[]>` returns response rows in `35-character hexadecimal suffix:count` format. Blank lines and zero-count padding rows are ignored; malformed or empty responses reject the check. SHA-1 is used only for the lookup identifier required by Pwned Passwords, through native Web Crypto. HTTPS or localhost is required. Configure a timeout and propagate service errors from your HTTP adapter.

Request padded responses with `Add-Padding: true`. Perform breach checking on submission, not on every keystroke, and never send the complete password or complete hash to the range endpoint. The samples supply Fetch and Angular `HttpClient` adapters. The endpoint needs no API key or subscription. OWASP recommends this service for breached-password screening; see the [API and privacy review](docs/password-guidance.md#pwned-passwords-integration).

## Optional authentication extensions

Public handler contracts, result types, and fluent `this` return types support separately implemented authentication adapters:

```typescript
import {PasswordsSqnfaWeb} from 'passwords-sqnfa-web';
import type {Handler} from 'passwords-sqnfa-web';

class AuthenticationPipeline extends PasswordsSqnfaWeb {
  useAuthentication(handler: Handler): this {
    return this.use(handler);
  }
}
```

An optional OPAQUE package can provide its protocol adapter and a `useOpaque()` convenience method. It must define registration/login exchanges, server endpoints, per-attempt state, protocol parameters, and a separate typed session API. Supply the NFC-normalized password consistently to the selected implementation. Session keys and protocol messages must not be placed in `getPassword()`, policy failures, or timing statistics. Protocol implementation and deployment need their own security review; installing an adapter does not establish NIST compliance or phishing resistance.

## Samples

From the project root, with Node.js 22.12+ or 24:

```sh
npm ci
npm run example:vanilla
```

Open <http://localhost:8080> for the [vanilla JavaScript sample](examples/vanilla.html).

```sh
npm ci --prefix examples/angular
npm run example:angular
```

Open <http://localhost:4200> for the [Angular 21 LTS sample](examples/angular/README.md). `npm run build:angular` produces its production build.

Both samples use the length and complete-password blocklists, explain rejections, support password-manager autofill and paste, offer a show/hide control, and clear passwords after submission. Optional breach checking uses padded responses and a 15-second timeout. The local list is illustrative; a production verifier needs a suitable common/compromised password corpus even if the demo's remote check is disabled.

The library uses TypeScript 7.0.2. Angular 21 is the newest [LTS release](https://angular.dev/reference/releases); its builder requires TypeScript `>=5.9 <6.0`, so the sample uses 5.9.3 with a separate lockfile.

## Development

```sh
npm ci
npm run check
npm ci --prefix examples/angular
npm run build:angular
npx playwright install chromium
npm run test:examples
npm pack
```

`check` type-checks source and tests, checks lint/formatting, runs unit tests, builds declarations and ESM/CommonJS/browser outputs, and verifies their public entry points. `test:coverage` reports coverage; `fix` formats source files. `test:examples` runs browser checks against the built library and Angular production build, with mocked breach responses.

CI verifies the library, Angular build, browser flows, and dependency audits on Node 22 and 24. Dependabot checks npm packages and CI actions weekly.

## Releases

Push an annotated `vX.Y.Z` tag to Azure DevOps to publish one snapshot commit and matching annotated tag to GitHub. GitHub Actions publishes the package to npm through trusted publishing and creates a GitHub Release from the tag's notes. Azure development history stays in Azure. See [release setup and credential locations](docs/releasing.md).

## License

Apache-2.0.
