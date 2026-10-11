import {appendFileSync, writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {assertGithubTag, assertRepository, readRelease} from './metadata.mjs';

try {
  const tag =
    process.env.RELEASE_TAG ||
    process.env.BUILD_SOURCEBRANCH?.replace(/^refs\/tags\//, '');
  const release = readRelease(process.cwd(), tag);
  assertRepository(release, process.env.GITHUB_REPOSITORY);
  if (process.env.GITHUB_ACTIONS === 'true') {
    assertGithubTag(release.tag, process.env.GITHUB_REF);
  }
  if (process.env.RUNNER_TEMP) {
    writeFileSync(
      join(process.env.RUNNER_TEMP, 'release-notes.md'),
      release.notes + '\n'
    );
  }
  if (process.env.GITHUB_OUTPUT) {
    appendFileSync(
      process.env.GITHUB_OUTPUT,
      `tag=${release.tag}\nprerelease=${release.prerelease}\n`
    );
  }
  console.log(`Validated ${release.tag} (${release.commit}).`);
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
