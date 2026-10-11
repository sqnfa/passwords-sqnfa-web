import {
  PasswordsSqnfaWeb,
  LengthHandler,
  Result,
  HaveibeenpwnedHandler,
  HaveibeenpwnedConfiguration,
} from '../src/index';
import {createHash} from 'node:crypto';

it.each(['a'.repeat(64), '🚀'.repeat(64), ' '.repeat(64), 'a\0'.repeat(32)])(
  'accepts 64 characters without composition rules or truncation',
  (password) => {
    expect(new LengthHandler().handleSync(password).getPassword()).toBe(
      password
    );
  }
);

it('uses the same NFC password for validation and an authentication extension', async () => {
  const input = 'cafe\u0301 and a passphrase';
  const authenticate = vi.fn(async (password: string) => Result.ok(password));
  const result = await new PasswordsSqnfaWeb()
    .useLengthHandler()
    .use({name: 'Authentication', handle: authenticate})
    .handle(input);
  expect(authenticate).toHaveBeenCalledWith(input.normalize('NFC'));
  expect(result.getPassword()).toBe(input.normalize('NFC'));
});

it('counts the normalized password rather than decomposed representations', () => {
  const handler = new LengthHandler();
  expect(handler.handleSync('e\u0301'.repeat(14)).isSuccess).toBe(false);
  expect(handler.handleSync('e\u0301'.repeat(15)).getPassword()).toBe(
    'é'.repeat(15)
  );
});

it('preserves case and leading/trailing whitespace during normalization', async () => {
  const password = '  A Long Passphrase  ';
  expect(
    (
      await new PasswordsSqnfaWeb().useLengthHandler().handle(password)
    ).getPassword()
  ).toBe(password);
});

it('checks the NFC password against the breach service', async () => {
  const password = 'cafe\u0301 passphrase';
  const digest = createHash('sha1')
    .update(password.normalize('NFC'))
    .digest('hex')
    .toUpperCase();
  const get = vi.fn(async () => [digest.slice(5) + ':7']);
  const handler = new HaveibeenpwnedHandler(
    new HaveibeenpwnedConfiguration({get})
  );
  expect((await handler.handle(password)).isSuccess).toBe(false);
  expect(get).toHaveBeenCalledWith(
    'https://api.pwnedpasswords.com/range/' + digest.slice(0, 5)
  );
});
