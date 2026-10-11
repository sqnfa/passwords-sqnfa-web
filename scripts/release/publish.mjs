import {
  assertGithubTag,
  assertRepository,
  githubRepository,
  readRelease,
} from './metadata.mjs';
import {createGithubRelease, publishPackage} from './publisher.mjs';

try {
  if (process.env.GITHUB_ACTIONS !== 'true') {
    throw new Error('Publish through the GitHub Release workflow.');
  }
  const repository = githubRepository(process.env.GITHUB_REPOSITORY);
  const release = readRelease(process.cwd(), process.env.RELEASE_TAG);
  assertRepository(release, repository);
  assertGithubTag(release.tag, process.env.GITHUB_REF);
  if (!process.env.GITHUB_TOKEN)
    throw new Error('GitHub Actions must supply its automatic GITHUB_TOKEN.');
  const artifact = await publishPackage({directory: process.cwd(), release});
  console.log(
    `${release.packageName}@${release.version}: ${artifact.created ? `published to npm (${artifact.distTag})` : 'existing npm artifact verified'}.`
  );
  const github = await createGithubRelease({
    repository,
    token: process.env.GITHUB_TOKEN,
    release,
  });
  console.log(
    `${github.created ? 'Created' : 'Verified'} GitHub Release: ${github.url}`
  );
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
