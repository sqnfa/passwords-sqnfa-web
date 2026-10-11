import assert from 'node:assert/strict';
import {afterEach, test} from 'node:test';
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {git, readRelease} from '../../scripts/release/metadata.mjs';
import {mirrorSnapshot} from '../../scripts/release/snapshot.mjs';

const temporaryDirectories = [];
const identity = {
  GIT_AUTHOR_NAME: 'Test Author',
  GIT_AUTHOR_EMAIL: 'test@example.com',
  GIT_COMMITTER_NAME: 'Test Author',
  GIT_COMMITTER_EMAIL: 'test@example.com',
};
const run = (directory, args) =>
  git(
    directory,
    ['-c', 'commit.gpgSign=false', '-c', 'tag.gpgSign=false', ...args],
    identity
  );
const notes =
  'A complete release\n\n- Unicode: café\n- Literal text: `code`, $(commands), and <markup>.';

function fixture() {
  const directory = mkdtempSync(join(tmpdir(), 'passwords-release-test-'));
  temporaryDirectories.push(directory);
  const source = join(directory, 'azure');
  const remote = join(directory, 'github.git');
  mkdirSync(source);
  mkdirSync(remote);
  run(source, ['init', '--initial-branch', 'main']);
  run(remote, ['init', '--bare', '--initial-branch', 'main']);
  writeFileSync(
    join(source, 'package.json'),
    JSON.stringify({
      name: 'release-fixture',
      version: '1.0.0',
      repository: {url: 'git+https://github.com/sqnfa/passwords-sqnfa-web.git'},
    })
  );
  writeFileSync(join(source, 'README.md'), 'Initial source');
  run(source, ['add', '.']);
  run(source, ['commit', '-m', 'A development commit']);
  const initial = run(source, ['rev-parse', 'HEAD']);
  writeFileSync(join(source, 'README.md'), 'Released code');
  writeFileSync(join(source, 'executable.sh'), '#!/bin/sh\nexit 0\n');
  chmodSync(join(source, 'executable.sh'), 0o755);
  symlinkSync('README.md', join(source, 'readme-link'));
  run(source, ['add', '.']);
  run(source, ['commit', '-m', 'Another development commit']);
  run(source, ['tag', '-a', 'v1.0.0', '-m', notes]);
  return {
    source,
    remote,
    initial,
    mirror: (tag = 'v1.0.0') =>
      mirrorSnapshot({sourceDirectory: source, remote, tag}),
  };
}

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0))
    rmSync(directory, {recursive: true, force: true});
});

test('exports the exact tagged tree as one commit, preserving modes, links, and notes without source history', () => {
  const {source, remote, mirror} = fixture();
  const result = mirror();
  const release = readRelease(source, 'v1.0.0');
  assert.equal(result.created, true);
  assert.equal(run(remote, ['rev-list', '--all', '--count']), '1');
  assert.equal(run(remote, ['rev-parse', 'main^{tree}']), release.tree);
  assert.equal(
    run(remote, ['log', '-1', '--format=%s']),
    'chore(release): v1.0.0'
  );
  assert.equal(readRelease(remote, 'v1.0.0', {checkHead: false}).notes, notes);
  assert.throws(() =>
    run(remote, ['cat-file', '-e', `${release.commit}^{commit}`])
  );
});

test('later releases have one GitHub parent, apply deletions, and keep earlier release tags', () => {
  const {source, remote, mirror} = fixture();
  const first = mirror();
  writeFileSync(
    join(source, 'package.json'),
    JSON.stringify({name: 'release-fixture', version: '1.1.0'})
  );
  rmSync(join(source, 'executable.sh'));
  writeFileSync(join(source, 'README.md'), 'Second release');
  run(source, ['add', '--all']);
  run(source, ['commit', '-m', 'More source development']);
  run(source, ['tag', '-a', 'v1.1.0', '-m', 'Second release notes']);
  const second = mirror('v1.1.0');
  assert.equal(run(remote, ['rev-parse', `${second.commit}^`]), first.commit);
  assert.equal(run(remote, ['rev-list', '--all', '--count']), '2');
  assert.equal(run(remote, ['show', 'main:README.md']), 'Second release');
  assert.throws(() => run(remote, ['show', 'main:executable.sh']));
  assert.equal(run(remote, ['rev-parse', 'v1.0.0^{commit}']), first.commit);
  assert.deepEqual(mirror('v1.0.0'), {...first, created: false});
  assert.equal(run(remote, ['rev-parse', 'main']), second.commit);
});

test('repeating an identical release does not make another commit', () => {
  const {remote, mirror} = fixture();
  const first = mirror();
  assert.deepEqual(mirror(), {...first, created: false});
  assert.equal(run(remote, ['rev-list', '--all', '--count']), '1');
});

test('refuses a reused tag with changed notes', () => {
  const {source, remote, mirror} = fixture();
  const first = mirror();
  run(source, ['tag', '-f', '-a', 'v1.0.0', '-m', 'Changed notes']);
  assert.throws(mirror, /already exists with different content or notes/);
  assert.equal(run(remote, ['rev-parse', 'main']), first.commit);
});

test('rejects lightweight, empty, mismatched, and invalid release tags', () => {
  const {source} = fixture();
  run(source, ['tag', 'v1.0.1']);
  assert.throws(() => readRelease(source, 'v1.0.1'), /must be annotated/);
  run(source, ['tag', '-a', 'v1.0.2', '-m', '']);
  assert.throws(() => readRelease(source, 'v1.0.2'), /contain release notes/);
  run(source, ['tag', '-a', 'v2.0.0', '-m', notes]);
  assert.throws(() => readRelease(source, 'v2.0.0'), /match package.json/);
  for (const tag of [
    'main',
    'v01.0.0',
    'v1.0.0-01',
    'v1.0.0+build',
    'v1.0.0;echo unsafe',
  ]) {
    assert.throws(() => readRelease(source, tag), /release tag|Release tags/);
  }
});

test('refuses a source checkout different from the tag', () => {
  const {source, initial} = fixture();
  run(source, ['checkout', '--detach', initial]);
  assert.throws(() => readRelease(source, 'v1.0.0'), /checkout must match/);
});

test('does not move GitHub main backwards to a divergent source release', () => {
  const {source, remote, initial, mirror} = fixture();
  const first = mirror();
  run(source, ['checkout', '--detach', initial]);
  writeFileSync(
    join(source, 'package.json'),
    JSON.stringify({name: 'release-fixture', version: '2.0.0'})
  );
  run(source, ['add', '.']);
  run(source, ['commit', '-m', 'Divergent source']);
  run(source, ['tag', '-a', 'v2.0.0', '-m', notes]);
  assert.throws(() => mirror('v2.0.0'), /must descend/);
  assert.equal(run(remote, ['rev-parse', 'main']), first.commit);
});

test('an atomic push leaves both branch and tag untouched if the remote rejects the tag', () => {
  const {remote, mirror} = fixture();
  const hook = join(remote, 'hooks', 'pre-receive');
  writeFileSync(
    hook,
    '#!/bin/sh\nwhile read old new ref; do\n  case "$ref" in refs/tags/*) exit 1 ;; esac\ndone\n'
  );
  chmodSync(hook, 0o755);
  assert.throws(mirror);
  assert.equal(run(remote, ['for-each-ref', '--format=%(refname)']), '');
});

test('fails before pushing if Git attributes would change the exported snapshot', () => {
  const {source, remote, mirror} = fixture();
  writeFileSync(join(source, '.gitattributes'), 'README.md export-ignore\n');
  run(source, ['add', '.']);
  run(source, ['commit', '-m', 'Exclude a tracked release file']);
  run(source, ['tag', '-f', '-a', 'v1.0.0', '-m', notes]);
  assert.throws(mirror, /Exported files differ/);
  assert.equal(run(remote, ['for-each-ref', '--format=%(refname)']), '');
});

test('exports tracked files even when current ignore rules exclude them', () => {
  const {source, remote, mirror} = fixture();
  writeFileSync(join(source, '.gitignore'), 'ignored.txt\n');
  writeFileSync(join(source, 'ignored.txt'), 'An intentionally tracked file');
  run(source, ['add', '--force', '.']);
  run(source, ['commit', '-m', 'Track a file despite its ignore rule']);
  run(source, ['tag', '-f', '-a', 'v1.0.0', '-m', notes]);
  mirror();
  assert.equal(
    run(remote, ['show', 'main:ignored.txt']),
    'An intentionally tracked file'
  );
});

test('preserves an existing GitHub history without connecting it to Azure history', () => {
  const {source, remote, mirror} = fixture();
  const seed = join(source, '..', 'github-seed');
  mkdirSync(seed);
  run(seed, ['init', '--initial-branch', 'main']);
  writeFileSync(join(seed, 'old-github-file'), 'An existing GitHub commit');
  run(seed, ['add', '.']);
  run(seed, ['commit', '-m', 'Existing GitHub history']);
  const parent = run(seed, ['rev-parse', 'HEAD']);
  run(seed, ['push', remote, 'main']);
  const result = mirror();
  assert.equal(run(remote, ['rev-parse', `${result.commit}^`]), parent);
  assert.throws(() => run(remote, ['show', 'main:old-github-file']));
  assert.equal(
    readFileSync(join(source, 'README.md'), 'utf8'),
    'Released code'
  );
});
