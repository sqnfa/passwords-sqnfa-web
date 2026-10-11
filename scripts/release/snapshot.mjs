import {execFileSync} from 'node:child_process';
import {mkdtempSync, readdirSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {git, readRelease} from './metadata.mjs';

export function mirrorSnapshot({
  sourceDirectory,
  tag,
  remote,
  branch = 'main',
  authentication = {},
}) {
  const release = readRelease(sourceDirectory, tag, {checkHead: false});
  const temporary = mkdtempSync(join(tmpdir(), 'passwords-release-'));
  const environment = {
    ...authentication,
    GIT_AUTHOR_NAME: 'Martin Storgaard Dieu',
    GIT_AUTHOR_EMAIL: 'info@sqnfa.com',
    GIT_COMMITTER_NAME: 'Martin Storgaard Dieu',
    GIT_COMMITTER_EMAIL: 'info@sqnfa.com',
  };
  const run = (args) => git(temporary, args, environment);
  try {
    run(['check-ref-format', '--branch', branch]);
    run(['init', '--initial-branch', branch]);
    run(['remote', 'add', 'origin', remote]);
    const refs = new Map(
      run(['ls-remote', 'origin', `refs/heads/${branch}`, `refs/tags/${tag}`])
        .split('\n')
        .filter(Boolean)
        .map((line) => line.split(/\s+/).reverse())
    );
    if (refs.has(`refs/tags/${tag}`)) {
      run([
        'fetch',
        '--no-tags',
        'origin',
        `refs/tags/${tag}:refs/tags/${tag}`,
      ]);
      const published = readRelease(temporary, tag, {checkHead: false});
      const message = run(['log', '-1', '--format=%B', published.commit]);
      if (
        published.tree !== release.tree ||
        published.notes !== release.notes ||
        !message.endsWith(`Azure-Source-Commit: ${release.commit}`)
      ) {
        throw new Error(
          'The GitHub release tag already exists with different content or notes.'
        );
      }
      return {commit: published.commit, created: false};
    }
    if (refs.has(`refs/heads/${branch}`)) {
      run([
        'fetch',
        '--no-tags',
        'origin',
        `refs/heads/${branch}:refs/remotes/origin/${branch}`,
      ]);
      run(['checkout', '-B', branch, `refs/remotes/origin/${branch}`]);
      const previous = run(['log', '-1', '--format=%B']).match(
        /^Azure-Source-Commit: ([a-f0-9]{40,64})$/m
      )?.[1];
      if (previous) {
        try {
          git(sourceDirectory, [
            'merge-base',
            '--is-ancestor',
            previous,
            release.commit,
          ]);
        } catch {
          throw new Error(
            'The tagged source must descend from the previous mirrored release.'
          );
        }
      }
    }
    for (const entry of readdirSync(temporary)) {
      if (entry !== '.git')
        rmSync(join(temporary, entry), {recursive: true, force: true});
    }
    const archive = join(temporary, '.git', 'snapshot.tar');
    execFileSync(
      'git',
      ['archive', '--format=tar', '--output', archive, release.commit],
      {cwd: sourceDirectory, stdio: ['ignore', 'pipe', 'pipe']}
    );
    execFileSync('tar', ['-xf', archive, '-C', temporary], {
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    // The archive contains only tracked source files, including any ignored ones.
    run(['add', '--all', '--force']);
    if (run(['write-tree']) !== release.tree) {
      throw new Error(
        'Exported files differ from the tagged tree. Do not use export-ignore or export-subst attributes for release files.'
      );
    }
    run([
      '-c',
      'commit.gpgSign=false',
      'commit',
      '--allow-empty',
      '-m',
      `chore(release): ${tag}\n\nRelease-Tag: ${tag}\nAzure-Source-Commit: ${release.commit}`,
    ]);
    const notes = join(temporary, '.git', 'release-notes.md');
    writeFileSync(notes, release.notes + '\n');
    run([
      '-c',
      'tag.gpgSign=false',
      'tag',
      '--annotate',
      '--cleanup=verbatim',
      tag,
      '--file',
      notes,
    ]);
    const commit = run(['rev-parse', 'HEAD']);
    run([
      'push',
      '--atomic',
      'origin',
      `HEAD:refs/heads/${branch}`,
      `refs/tags/${tag}:refs/tags/${tag}`,
    ]);
    return {commit, created: true};
  } finally {
    rmSync(temporary, {recursive: true, force: true});
  }
}
