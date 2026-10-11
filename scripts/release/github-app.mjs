import {createSign} from 'node:crypto';

export async function githubRequest(path, token, options = {}) {
  const response = await fetch(`https://api.github.com${path}`, {
    ...options,
    headers: {
      Accept: 'application/vnd.github+json',
      Authorization: `Bearer ${token}`,
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': 'passwords-sqnfa-web-release',
      ...(options.body ? {'Content-Type': 'application/json'} : {}),
    },
    signal: AbortSignal.timeout(30000),
  });
  if (response.status === 404 && options.allowMissing) return null;
  if (!response.ok)
    throw new Error(`GitHub API ${path} returned HTTP ${response.status}.`);
  return response.status === 204 ? null : response.json();
}

export async function installationToken({
  appId,
  installationId,
  privateKey,
  repository,
}) {
  if (!/^\d+$/.test(appId || '') || !/^\d+$/.test(installationId || '')) {
    throw new Error('Configure githubAppId and githubInstallationId in Azure.');
  }
  const now = Math.floor(Date.now() / 1000);
  const encode = (value) =>
    Buffer.from(JSON.stringify(value)).toString('base64url');
  const unsigned = `${encode({alg: 'RS256', typ: 'JWT'})}.${encode({iat: now - 60, exp: now + 540, iss: appId})}`;
  const signature = createSign('RSA-SHA256')
    .update(unsigned)
    .sign(privateKey, 'base64url');
  const result = await githubRequest(
    `/app/installations/${installationId}/access_tokens`,
    `${unsigned}.${signature}`,
    {
      method: 'POST',
      body: JSON.stringify({
        repositories: [repository.split('/')[1]],
        permissions: {contents: 'write', workflows: 'write'},
      }),
    }
  );
  if (!result?.token)
    throw new Error('GitHub did not return an installation token.');
  return result.token;
}

export function gitAuthentication(token, repository) {
  const count = Number(process.env.GIT_CONFIG_COUNT || 0);
  return {
    GIT_TERMINAL_PROMPT: '0',
    GIT_CONFIG_COUNT: String(count + 2),
    [`GIT_CONFIG_KEY_${count}`]: `http.https://github.com/${repository}.git.extraHeader`,
    [`GIT_CONFIG_VALUE_${count}`]: `Authorization: Basic ${Buffer.from(`x-access-token:${token}`).toString('base64')}`,
    [`GIT_CONFIG_KEY_${count + 1}`]: 'credential.helper',
    [`GIT_CONFIG_VALUE_${count + 1}`]: '',
  };
}
