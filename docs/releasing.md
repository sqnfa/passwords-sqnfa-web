# Publish releases from GitHub

The [Release workflow](../.github/workflows/release.yml) validates annotated `vX.Y.Z` tags, publishes the package to npm with provenance, and creates a GitHub Release using the tag annotation as its release notes.

## Trusted publishing setup

1. Enable GitHub Actions in `sqnfa/passwords-sqnfa-web`.
2. Create a GitHub environment named `npm` under **Settings → Environments**. The publish job uses this environment. You may restrict deployment to `v*` tags.
3. As an owner of `passwords-sqnfa-web`, open **Settings → Trusted publishing** on [npmjs.com](https://www.npmjs.com/package/passwords-sqnfa-web) and add a GitHub Actions publisher:

   | Field                | Value                      |
   | -------------------- | -------------------------- |
   | Organization or user | `sqnfa`                    |
   | Repository           | `passwords-sqnfa-web`      |
   | Workflow filename    | `release.yml`              |
   | Environment name     | `npm`                      |
   | Allowed actions      | Allow direct `npm publish` |

Enter the workflow filename alone, including its extension. New trusted publishers allow staged publishing by default; this workflow requires direct `npm publish` permission. An `OIDC permission denied for this action` error means this action must be enabled in the publisher settings.

GitHub supplies the short-lived OIDC identity and automatic `GITHUB_TOKEN`. The publish job grants `id-token: write` and `contents: write`; no npm token is needed. It pins npm 12.2.0 and runs on Node 24. npm 12.2.0 requires Node 22.22.2+, 24.15.0+, or 26+.

## Release behavior

Tags must be annotated, contain nonempty release notes, and match `package.json` exactly. SemVer prereleases such as `v1.1.0-rc.1` are supported; build metadata is rejected. The workflow checks out the tag, verifies the library and browser samples, rebuilds the package, and publishes its verified tarball with provenance.

Stable versions publish to `latest`; prereleases publish to `next`. An older version uses `maintenance` when its normal channel already points to a newer version. The GitHub Release is created only after npm publication succeeds.

## Retry a release

For permission or configuration failures, fix the reported setting and select **Re-run failed jobs** in the existing Release run. A new version is unnecessary when publication has not succeeded.

You may also retry manually from the existing tag:

```sh
gh workflow run release.yml --repo sqnfa/passwords-sqnfa-web --ref v1.0.3 -f tag=v1.0.3
```

Use the same tag for the workflow ref and input so provenance identifies the released code. Dispatching from `main` is rejected. Code changes require a new version and tag.

An already-published version is accepted only if its SHA-512 tarball integrity matches the rebuilt artifact. The workflow then creates or verifies the GitHub Release without republishing npm. Different artifacts or release notes are rejected. Release workflows queue without cancelling active runs.

## References

- [npm trusted publishing](https://docs.npmjs.com/trusted-publishers/)
- [GitHub workflow concurrency](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency)
