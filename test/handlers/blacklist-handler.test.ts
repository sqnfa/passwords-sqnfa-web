import {
  BlacklistHandler,
  BlacklistConfiguration,
} from '../../src/handlers/blacklist-handler';
// https://xkcd.com/936/
const config = new BlacklistConfiguration(
  ['troubad'],
  [new RegExp(/tr[o0]ub[a4]dor[u&][r3]/i)]
);
const handler = new BlacklistHandler(config);

describe('a valid password', () => {
  it('should return the original password in the result.', () => {
    const password = 'MyPassword';

    const result = handler.handle(password);
    expect(result.isSuccess).toBeTruthy();
    expect(result.getPassword()).toBe(password);
  });
});

describe('an invalid password', () => {
  it('should reject banned words.', () => {
    const result = handler.handle("I'm a TrouBad m4ker");
    const failures = result.getFailures();

    expect(failures).toHaveLength(1);
    expect(failures[0].rule).toBe('caseInsensitiveWords');
    expect(failures[0].expected).toBe(0);
    expect(failures[0].actual).toBe(1);
  });

  it('should reject banned regular expressions.', () => {
    const result = handler.handle('tr0ub4dor&3');
    const failures = result.getFailures();

    expect(failures).toHaveLength(1);
    expect(failures[0].rule).toBe('regExps');
    expect(failures[0].expected).toBe(0);
    expect(failures[0].actual).toBe(1);
  });
});
