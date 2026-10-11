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
