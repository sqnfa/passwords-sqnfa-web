import {
  RegexHandler,
  RegexConfiguration,
} from '../../src/handlers/regex-handler';
// https://xkcd.com/936/
const config = new RegexConfiguration([new RegExp(/tr[o0]ub[a4]dor[u&][r3]/i)]);
const handler = new RegexHandler(config);

describe('a valid password', () => {
  const password = 'MyPassword';
  it('should return the original password in the result.', () => {
    const result = handler.handleSync(password);
    expect(result.isSuccess).toBeTruthy();
    expect(result.getPassword()).toBe(password);
  });

  it('should be valid when no case insensitive words are provided.', () => {
    const emptyHandler = new RegexHandler({
      regExps: [],
    });

    const result = emptyHandler.handleSync(password);

    expect(result.isSuccess).toBeTruthy();
    expect(result.getPassword()).toBe(password);
  });
});

describe('an invalid password', () => {
  it('should reject banned regular expressions.', () => {
    const result = handler.handleSync('tr0ub4dor&3');
    const failures = result.getFailures();

    expect(failures).toHaveLength(1);
    expect(failures[0].rule).toBe('regExps');
    expect(failures[0].expected).toBe(0);
    expect(failures[0].actual).toBe(1);
  });
});
