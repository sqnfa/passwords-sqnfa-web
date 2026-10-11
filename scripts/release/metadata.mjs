import {execFileSync} from 'node:child_process';

export function git(directory, args, environment = {}) {
  return execFileSync('git', args, {
    cwd: directory,
    env: {...process.env, ...environment},
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  }).trimEnd();
}

export function readRelease(directory, tag, {checkHead = true} = {}) {
  const versionPattern =
    /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?$/;
  if (typeof tag !== 'string' || !tag.startsWith('v')) {
    throw new Error('Supply a release tag such as v1.0.0.');
  }
  const version = tag.slice(1);
  if (!versionPattern.test(version)) {
    throw new Error(
      'Release tags must use v followed by a SemVer version without build metadata.'
    );
  }
  const ref = `refs/tags/${tag}`;
  if (git(directory, ['cat-file', '-t', ref]) !== 'tag') {
    throw new Error(
      'Release tags must be annotated and contain release notes.'
    );
  }
  const object = git(directory, ['cat-file', '-p', ref]);
  const separator = object.indexOf('\n\n');
  const notes =
    separator < 0
      ? ''
      : object
          .slice(separator + 2)
          .split(/\n-----BEGIN (?:PGP|SSH) SIGNATURE-----/)[0]
          .trim();
  if (!notes) throw new Error('The annotated tag must contain release notes.');
  const commit = git(directory, ['rev-parse', `${ref}^{commit}`]);
  if (checkHead && git(directory, ['rev-parse', 'HEAD']) !== commit) {
    throw new Error('The checkout must match the release tag.');
  }
  const pkg = JSON.parse(git(directory, ['show', `${commit}:package.json`]));
  if (pkg.version !== version) {
    throw new Error('The release tag must match package.json version.');
  }
  return {
    tag,
    version,
    commit,
    notes,
    packageName: pkg.name,
    repository: pkg.repository?.url,
    prerelease: version.includes('-'),
    tree: git(directory, ['rev-parse', `${commit}^{tree}`]),
  };
}

export function githubRepository(value) {
  if (!/^[a-zA-Z0-9-]+\/[a-zA-Z0-9_.-]+$/.test(value || '')) {
    throw new Error('GITHUB_REPOSITORY must be owner/repository.');
  }
  return value;
}

export function assertRepository(release, repository) {
  const expected = `git+https://github.com/${githubRepository(repository)}.git`;
  if (release.repository !== expected) {
    throw new Error(
      'package.json repository.url must match the GitHub publication repository.'
    );
  }
}

export function assertGithubTag(tag, reference) {
  if (reference !== `refs/tags/${tag}`) {
    throw new Error(
      `Run the release workflow from ${tag} so provenance identifies the release. For a manual retry: gh workflow run release.yml --ref ${tag} -f tag=${tag}`
    );
  }
}
