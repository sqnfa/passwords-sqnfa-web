import {
  BlackListHandler,
  BlackListConfiguration,
} from '../../src/handlers/blacklist-handler';
// https://xkcd.com/936/
const config = new BlackListConfiguration(
  ['troubaD'],
  [new RegExp(/tr[o0]ub[a4]dor[u&][r3]/i)]
);
const handler = new BlackListHandler(config);

describe('a valid password', () => {
  const password = 'MyPassword';
  it('should return the original password in the result.', () => {
    const result = handler.handleSync(password);
    expect(result.isSuccess).toBeTruthy();
    expect(result.getPassword()).toBe(password);
  });

  it('should be valid when no case insensitive words are provided.', () => {
    const emptyHandler = new BlackListHandler({
      caseInsensitiveWords: [],
      regExps: [],
    });

    const result = emptyHandler.handleSync(password);

    expect(result.isSuccess).toBeTruthy();
    expect(result.getPassword()).toBe(password);
  });
});

describe('an invalid password', () => {
  it('should reject banned words.', () => {
    const result = handler.handleSync("I'm a TrouBad m4ker");
    const failures = result.getFailures();

    expect(failures).toHaveLength(1);
    expect(failures[0].rule).toBe('caseInsensitiveWords');
    expect(failures[0].expected).toBe(0);
    expect(failures[0].actual).toBe(1);
  });

  it('should reject banned words when the password starts with it.', () => {
    const result = handler.handleSync('trouBADour');
    const failures = result.getFailures();

    expect(failures).toHaveLength(1);
    expect(failures[0].rule).toBe('caseInsensitiveWords');
    expect(failures[0].expected).toBe(0);
    expect(failures[0].actual).toBe(1);
  });

  it('should reject banned regular expressions.', () => {
    const result = handler.handleSync('tr0ub4dor&3');
    const failures = result.getFailures();

    expect(failures).toHaveLength(1);
    expect(failures[0].rule).toBe('regExps');
    expect(failures[0].expected).toBe(0);
    expect(failures[0].actual).toBe(1);
  });

  it('should include both failures if both rules are broken.', () => {
    const result = handler.handleSync('troubador&3');
    const failures = result.getFailures();

    expect(failures).toHaveLength(2);
    expect(failures).toContainEqual({
      handler: handler.name,
      rule: 'regExps',
      expected: 0,
      actual: 1,
    });
    expect(failures).toContainEqual({
      handler: handler.name,
      rule: 'caseInsensitiveWords',
      expected: 0,
      actual: 1,
    });
  });
});
