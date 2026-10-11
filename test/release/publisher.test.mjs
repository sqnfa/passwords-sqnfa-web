import assert from 'node:assert/strict';
import {afterEach, test} from 'node:test';
import {createHash} from 'node:crypto';
import {mkdtempSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {
  assertGithubTag,
  assertRepository,
} from '../../scripts/release/metadata.mjs';
import {
  createGithubRelease,
  publishPackage,
} from '../../scripts/release/publisher.mjs';

const originalFetch = globalThis.fetch;
const directories = [];
const release = {
  tag: 'v1.0.0',
  version: '1.0.0',
  packageName: 'release-fixture',
  prerelease: false,
  commit: 'a'.repeat(40),
  notes: 'Release notes\n\nWith a second paragraph.',
};
const response = (body, status = 200) =>
  new Response(body === null ? null : JSON.stringify(body), {status});

afterEach(() => {
  globalThis.fetch = originalFetch;
  for (const directory of directories.splice(0))
    rmSync(directory, {recursive: true, force: true});
});

function artifact(version = '1.0.0') {
  const directory = mkdtempSync(join(tmpdir(), 'passwords-publish-test-'));
  directories.push(directory);
  const filename = `release-fixture-${version}.tgz`;
  const bytes = Buffer.from('A reproducible packed artifact');
  writeFileSync(join(directory, filename), bytes);
  const integrity = `sha512-${createHash('sha512').update(bytes).digest('base64')}`;
  const calls = [];
  return {
    directory,
    filename,
    integrity,
    calls,
    npm: (args) => {
      calls.push(args);
      return args[0] === 'pack'
        ? JSON.stringify([{name: release.packageName, version, filename}])
        : '';
    },
  };
}

test('publishes a stable tarball with provenance and no stored npm token', async () => {
  const fixture = artifact();
  globalThis.fetch = async (url) =>
    url.endsWith('/latest')
      ? response({version: '0.6.0'})
      : response(null, 404);
  const result = await publishPackage({...fixture, release});
  assert.equal(result.distTag, 'latest');
  assert.deepEqual(fixture.calls[1], [
    'publish',
    fixture.filename,
    '--provenance',
    '--access',
    'public',
    '--tag',
    'latest',
    '--registry',
    'https://registry.npmjs.org',
  ]);
});

test('publishes an artifact from npm 12 package-keyed pack output', async () => {
  const fixture = artifact();
  globalThis.fetch = async () => response(null, 404);
  const npm = (args) => {
    const output = fixture.npm(args);
    return args[0] === 'pack'
      ? JSON.stringify({[release.packageName]: JSON.parse(output)[0]})
      : output;
  };
  const result = await publishPackage({...fixture, npm, release});
  assert.equal(result.created, true);
  assert.equal(result.filename, fixture.filename);
  assert.equal(fixture.calls[1][0], 'publish');
  assert.equal(fixture.calls[1][1], fixture.filename);
});

test('refuses empty or multiple packed artifacts before accessing the registry', async () => {
  const fixture = artifact();
  const [packed] = JSON.parse(fixture.npm(['pack']));
  globalThis.fetch = async () =>
    assert.fail('The registry must not be accessed');
  for (const output of [
    [],
    {},
    null,
    [packed, packed],
    {[release.packageName]: packed, another: packed},
  ]) {
    const npm = (args) => {
      assert.equal(args[0], 'pack');
      return JSON.stringify(output);
    };
    await assert.rejects(
      publishPackage({...fixture, npm, release}),
      /packed artifact does not match/
    );
  }
});

test('publishes prereleases to next', async () => {
  const version = '1.1.0-rc.1';
  const fixture = artifact(version);
  globalThis.fetch = async () => response(null, 404);
  assert.equal(
    (
      await publishPackage({
        ...fixture,
        release: {...release, version, prerelease: true},
      })
    ).distTag,
    'next'
  );
});

test('an older release cannot downgrade latest', async () => {
  const fixture = artifact();
  globalThis.fetch = async (url) =>
    url.endsWith('/latest')
      ? response({version: '2.0.0'})
      : response(null, 404);
  assert.equal(
    (await publishPackage({...fixture, release})).distTag,
    'maintenance'
  );
});

test('compares numeric prerelease identifiers numerically when preserving next', async () => {
  const version = '1.1.0-beta.9';
  const fixture = artifact(version);
  globalThis.fetch = async (url) =>
    url.endsWith('/next')
      ? response({version: '1.1.0-beta.10'})
      : response(null, 404);
  assert.equal(
    (
      await publishPackage({
        ...fixture,
        release: {...release, version, prerelease: true},
      })
    ).distTag,
    'maintenance'
  );
});

test('an identical existing npm version is verified and not republished', async () => {
  const fixture = artifact();
  globalThis.fetch = async () =>
    response({
      name: release.packageName,
      version: release.version,
      dist: {integrity: fixture.integrity},
    });
  assert.equal((await publishPackage({...fixture, release})).created, false);
  assert.equal(fixture.calls.length, 1);
});

test('refuses an npm version with different contents', async () => {
  const fixture = artifact();
  globalThis.fetch = async () =>
    response({
      name: release.packageName,
      version: release.version,
      dist: {integrity: 'sha512-different'},
    });
  await assert.rejects(
    publishPackage({...fixture, release}),
    /different artifact/
  );
  assert.equal(fixture.calls.length, 1);
});

test('registry errors stop publication rather than being interpreted as a missing version', async () => {
  const fixture = artifact();
  globalThis.fetch = async () => response(null, 503);
  await assert.rejects(publishPackage({...fixture, release}), /HTTP 503/);
  assert.equal(fixture.calls.length, 1);
});

test('recovers when npm accepted the artifact but the client lost its response', async () => {
  const fixture = artifact();
  let published = false;
  globalThis.fetch = async () =>
    published
      ? response({
          name: release.packageName,
          version: release.version,
          dist: {integrity: fixture.integrity},
        })
      : response(null, 404);
  const npm = (args) => {
    if (args[0] === 'publish') {
      published = true;
      throw new Error('Connection lost');
    }
    return fixture.npm(args);
  };
  assert.equal(
    (await publishPackage({...fixture, npm, release})).created,
    true
  );
});

test('creates a GitHub Release with the tag annotation as its exact notes', async () => {
  let body;
  globalThis.fetch = async (_url, options) => {
    if (options.method === 'POST') {
      body = JSON.parse(options.body);
      return response({
        html_url:
          'https://github.com/sqnfa/passwords-sqnfa-web/releases/tag/v1.0.0',
      });
    }
    return response(null, 404);
  };
  const result = await createGithubRelease({
    repository: 'sqnfa/passwords-sqnfa-web',
    token: 'test-token',
    release,
  });
  assert.equal(result.created, true);
  assert.equal(body.body, release.notes);
  assert.equal(body.tag_name, release.tag);
  assert.equal(body.target_commitish, release.commit);
  assert.equal(body.prerelease, false);
  assert.equal(body.make_latest, 'legacy');
});

test('retries verify an existing GitHub Release without overwriting its notes', async () => {
  const existing = {
    body: release.notes,
    draft: false,
    prerelease: false,
    html_url: 'https://github.com/example/release',
  };
  globalThis.fetch = async () => response(existing);
  assert.equal(
    (
      await createGithubRelease({
        repository: 'sqnfa/passwords-sqnfa-web',
        token: 'test-token',
        release,
      })
    ).created,
    false
  );
  globalThis.fetch = async () => response({...existing, body: 'Changed notes'});
  await assert.rejects(
    createGithubRelease({
      repository: 'sqnfa/passwords-sqnfa-web',
      token: 'test-token',
      release,
    }),
    /different notes/
  );
});

test('rejects a repository mismatch before publishing', () => {
  assert.throws(
    () =>
      assertRepository(
        {
          ...release,
          repository: 'git+https://github.com/another/repository.git',
        },
        'sqnfa/passwords-sqnfa-web'
      ),
    /must match/
  );
});

test('manual publishing retries must use the tag ref to keep provenance tied to the released code', () => {
  assert.doesNotThrow(() => assertGithubTag('v1.0.0', 'refs/tags/v1.0.0'));
  assert.throws(
    () => assertGithubTag('v1.0.0', 'refs/heads/main'),
    /provenance identifies/
  );
  assert.throws(
    () => assertGithubTag('v1.0.0', 'refs/tags/v2.0.0'),
    /--ref v1.0.0/
  );
});
