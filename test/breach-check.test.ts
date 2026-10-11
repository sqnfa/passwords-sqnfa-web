import {createHash} from 'node:crypto';
import {HaveibeenpwnedHandler, HaveibeenpwnedConfiguration} from '../src/index';

it('does not report HIBP padding entries with zero occurrences as a breach', async () => {
  const password = 'padding test';
  const digest = createHash('sha1')
    .update(password)
    .digest('hex')
    .toUpperCase();
  const get = vi.fn(async () => [digest.slice(5) + ':0']);
  const handler = new HaveibeenpwnedHandler(
    new HaveibeenpwnedConfiguration({get})
  );
  expect((await handler.handle(password)).isSuccess).toBe(true);
  expect(get).toHaveBeenCalledWith(
    'https://api.pwnedpasswords.com/range/' + digest.slice(0, 5)
  );
});

it('matches complete HIBP suffixes case-insensitively with positive counts', async () => {
  const password = 'pwned test';
  const digest = createHash('sha1').update(password).digest('hex');
  const handler = new HaveibeenpwnedHandler(
    new HaveibeenpwnedConfiguration({get: async () => [digest.slice(5) + ':4']})
  );
  expect((await handler.handle(password)).isSuccess).toBe(false);
});

it('rejects a response row without an occurrence count', async () => {
  const password = 'bare suffix test';
  const digest = createHash('sha1')
    .update(password)
    .digest('hex')
    .toUpperCase();
  const handler = new HaveibeenpwnedHandler(
    new HaveibeenpwnedConfiguration({get: async () => [digest.slice(5)]})
  );
  await expect(handler.handle(password)).rejects.toThrow(
    'Invalid Pwned Passwords response row.'
  );
});

it('rejects an unavailable Web Crypto operation', async () => {
  const digest = vi
    .spyOn(globalThis.crypto.subtle, 'digest')
    .mockRejectedValueOnce(new Error('crypto unavailable'));
  const get = vi.fn(async () => []);
  try {
    const handler = new HaveibeenpwnedHandler(
      new HaveibeenpwnedConfiguration({get})
    );
    await expect(handler.handle('passphrase')).rejects.toThrow(
      'crypto unavailable'
    );
    expect(get).not.toHaveBeenCalled();
  } finally {
    digest.mockRestore();
  }
});

it('rejects an empty breach response instead of reporting success', async () => {
  const handler = new HaveibeenpwnedHandler(
    new HaveibeenpwnedConfiguration({get: async () => ['']})
  );
  await expect(handler.handle('passphrase')).rejects.toThrow(
    'Empty Pwned Passwords response.'
  );
});
