import {BlackListHandler, BlackListConfiguration} from '../../src/index';

const handler = new BlackListHandler(
  new BlackListConfiguration(['password', 'troubadour', 'café'])
);

it.each(['password', 'PASSWORD', 'Troubadour', 'cafe\u0301'])(
  'rejects a complete blocked value: %s',
  (password) => {
    expect(handler.handleSync(password).getFailures()[0].rule).toBe(
      'caseInsensitiveWords'
    );
  }
);

it.each([
  'password in a long passphrase',
  '1troubadour2',
  'my café passphrase',
  'unrelated passphrase',
])(
  'permits a password containing an unblocked complete value: %s',
  (password) => {
    expect(handler.handleSync(password).isSuccess).toBe(true);
  }
);

it('accepts a password when the configured blocklist is empty', () => {
  expect(
    new BlackListHandler({caseInsensitiveWords: []}).handleSync('a passphrase')
      .isSuccess
  ).toBe(true);
});
