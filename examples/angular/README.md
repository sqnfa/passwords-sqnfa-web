# Angular 21 LTS sample

A standalone, zoneless Angular app using signals, template-driven forms, and Angular `HttpClient`. It consumes the actual library package through a local `file:../..` dependency, including its generated declarations. No TypeScript path aliases point at source files.

From the repository root:

```sh
npm ci
npm ci --prefix examples/angular
npm run example:angular
```

Open <http://localhost:4200>. For production output, run `npm run build:angular`; files are emitted to `examples/angular/dist/password-demo/browser`.

Angular 21 is the latest LTS release. See the [official support table](https://angular.dev/reference/releases). Angular core packages are 21.2.25 and CLI/build packages are 21.2.26. This sample intentionally uses TypeScript 5.9.3 because the Angular 21 builder requires `>=5.9 <6.0`; the independent library uses TypeScript 7.0.2. Each project has its own lockfile. Install with Node 22.12+.

The sample checks NFC-normalized Unicode length and complete-password email-context and common-value blocklists. Breach checking is opt-in and uses a typed adapter for `HaveibeenpwnedHttpClient`, requesting padded responses and timing out after 15 seconds. Failures and elapsed timings appear in the UI; passwords are cleared after submission and never placed in result output or logs. The show/hide control reveals the local input only when the user requests it. HTTP errors report an incomplete check. See the [NIST/OWASP guidance mapping](../../docs/password-guidance.md) for production verifier requirements.
