import {readFileSync} from 'node:fs';
import {assertRepository, githubRepository, readRelease} from './metadata.mjs';
import {
  githubRequest,
  gitAuthentication,
  installationToken,
} from './github-app.mjs';
import {mirrorSnapshot} from './snapshot.mjs';

let token;
try {
  const repository = githubRepository(process.env.GITHUB_REPOSITORY);
  const tag = process.env.BUILD_SOURCEBRANCH?.replace(/^refs\/tags\//, '');
  assertRepository(readRelease(process.cwd(), tag), repository);
  token = await installationToken({
    appId: process.env.GITHUB_APP_ID,
    installationId: process.env.GITHUB_INSTALLATION_ID,
    privateKey: readFileSync(process.env.GITHUB_APP_PRIVATE_KEY_PATH, 'utf8'),
    repository,
  });
  const result = mirrorSnapshot({
    sourceDirectory: process.cwd(),
    tag,
    remote: `https://github.com/${repository}.git`,
    branch: process.env.GITHUB_MIRROR_BRANCH || 'main',
    authentication: gitAuthentication(token, repository),
  });
  console.log(
    `${tag}: GitHub snapshot ${result.commit}${result.created ? ' pushed.' : ' already exists; rerun the GitHub Release workflow if publishing needs a retry.'}`
  );
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
} finally {
  if (token) {
    try {
      await githubRequest('/installation/token', token, {method: 'DELETE'});
    } catch {
      console.error(
        'Could not revoke the short-lived GitHub installation token; it will expire automatically.'
      );
    }
  }
}
