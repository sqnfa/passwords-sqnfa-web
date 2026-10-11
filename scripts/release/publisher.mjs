import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {join} from 'node:path';
import {githubRequest} from './github-api.mjs';

function compareVersions(left, right) {
  const parts = (value) => {
    const [core, ...suffix] = value.split('-');
    return {
      core: core.split('.').map(BigInt),
      suffix: suffix.join('-').split('.').filter(Boolean),
    };
  };
  const a = parts(left);
  const b = parts(right);
  for (let index = 0; index < 3; index++) {
    if (a.core[index] !== b.core[index])
      return a.core[index] > b.core[index] ? 1 : -1;
  }
  if (!a.suffix.length || !b.suffix.length)
    return Number(!a.suffix.length) - Number(!b.suffix.length);
  for (
    let index = 0;
    index < Math.max(a.suffix.length, b.suffix.length);
    index++
  ) {
    const x = a.suffix[index];
    const y = b.suffix[index];
    if (x === y) continue;
    if (x === undefined || y === undefined) return x === undefined ? -1 : 1;
    const xn = /^\d+$/.test(x);
    const yn = /^\d+$/.test(y);
    if (xn && yn) return BigInt(x) > BigInt(y) ? 1 : -1;
    if (xn !== yn) return xn ? -1 : 1;
    return x > y ? 1 : -1;
  }
  return 0;
}

async function registryVersion(name, version) {
  const response = await fetch(
    `https://registry.npmjs.org/${encodeURIComponent(name)}/${encodeURIComponent(version)}`,
    {
      signal: AbortSignal.timeout(30000),
    }
  );
  if (response.status === 404) return null;
  if (!response.ok)
    throw new Error(
      `npm registry returned HTTP ${response.status}; publication stopped.`
    );
  return response.json();
}

export async function publishPackage({
  directory,
  release,
  npm = (args) =>
    execFileSync('npm', args, {
      cwd: directory,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    }),
}) {
  const output = JSON.parse(npm(['pack', '--json', '--ignore-scripts']));
  // npm 12 keys artifacts by package name; earlier versions return an array.
  const artifacts = Array.isArray(output)
    ? output
    : Object.values(output ?? {});
  const [packed] = artifacts;
  if (
    artifacts.length !== 1 ||
    packed?.name !== release.packageName ||
    packed.version !== release.version ||
    !/^[a-zA-Z0-9_.-]+\.tgz$/.test(packed.filename)
  ) {
    throw new Error('The packed artifact does not match the release.');
  }
  const integrity = `sha512-${createHash('sha512')
    .update(readFileSync(join(directory, packed.filename)))
    .digest('base64')}`;
  const verify = (existing) => {
    if (
      existing.name !== release.packageName ||
      existing.version !== release.version ||
      existing.dist?.integrity !== integrity
    ) {
      throw new Error(
        'This npm version already exists with a different artifact; versions are immutable.'
      );
    }
  };
  const existing = await registryVersion(release.packageName, release.version);
  if (existing) {
    verify(existing);
    return {created: false, filename: packed.filename};
  }
  const channel = release.prerelease ? 'next' : 'latest';
  const current = await registryVersion(release.packageName, channel);
  const distTag =
    current && compareVersions(current.version, release.version) > 0
      ? 'maintenance'
      : channel;
  try {
    npm([
      'publish',
      packed.filename,
      '--provenance',
      '--access',
      'public',
      '--tag',
      distTag,
      '--registry',
      'https://registry.npmjs.org',
    ]);
  } catch (error) {
    // A publish can succeed even if the client loses its response.
    const published = await registryVersion(
      release.packageName,
      release.version
    );
    if (!published) throw error;
    verify(published);
  }
  return {created: true, filename: packed.filename, distTag};
}

export async function createGithubRelease({repository, token, release}) {
  const path = `/repos/${repository}/releases`;
  const existing = await githubRequest(`${path}/tags/${release.tag}`, token, {
    allowMissing: true,
  });
  if (existing) {
    if (
      existing.draft ||
      existing.prerelease !== release.prerelease ||
      existing.body?.trim() !== release.notes
    ) {
      throw new Error(
        'The GitHub Release already exists with different notes or publication settings.'
      );
    }
    return {created: false, url: existing.html_url};
  }
  const created = await githubRequest(path, token, {
    method: 'POST',
    body: JSON.stringify({
      tag_name: release.tag,
      target_commitish: release.commit,
      name: release.tag,
      body: release.notes,
      draft: false,
      prerelease: release.prerelease,
      make_latest: 'legacy',
    }),
  });
  return {created: true, url: created.html_url};
}
