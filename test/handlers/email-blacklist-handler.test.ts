import {
  EmailBlackListHandler,
  EmailBlackListConfiguration,
} from '../../src/index';

const handler = new EmailBlackListHandler(
  new EmailBlackListConfiguration('john-doe@company.example.com')
);

it.each([
  'john',
  'doe',
  'company',
  'example',
  'john-doe',
  'john-doe@company.example.com',
  'JOHN-DOE',
])('rejects complete contextual values: %s', (password) => {
  expect(handler.handleSync(password).getFailures()[0].rule).toBe(
    'emailTokens'
  );
});

it.each([
  'a company passphrase',
  'john likes long passphrases',
  '1john-doe2',
  'com',
  'compa',
])('permits passwords containing contextual substrings: %s', (password) => {
  expect(handler.handleSync(password).isSuccess).toBe(true);
});

it('filters derived tokens using a Unicode character minimum', () => {
  const filtered = new EmailBlackListHandler({
    email: 'john-doe@company.example.com',
    minTokenLength: 4,
  });
  expect(filtered.handleSync('doe').isSuccess).toBe(true);
  expect(filtered.handleSync('john').isSuccess).toBe(false);
});

it('can add contextual values for another email address', () => {
  const updated = new EmailBlackListHandler({
    email: 'first@example.com',
    minTokenLength: 4,
  });
  updated.addEmailInformation('second@service.example', 4);
  expect(updated.handleSync('second').isSuccess).toBe(false);
  expect(updated.handleSync('long second passphrase').isSuccess).toBe(true);
});

it('rejects malformed context configuration', () => {
  expect(
    () => new EmailBlackListHandler({email: 'invalid', minTokenLength: 1})
  ).toThrow();
  expect(
    () =>
      new EmailBlackListHandler({email: 'user@example.com', minTokenLength: 0})
  ).toThrow();
});
