import {
  BlackListHandler,
  BlackListConfiguration,
} from '../../src/handlers/blacklist-handler';
// https://xkcd.com/936/
const config = new BlackListConfiguration(['troubaD'], 0.75);
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
      ratioThreshold: 1,
    });

    const result = emptyHandler.handleSync(password);

    expect(result.isSuccess).toBeTruthy();
    expect(result.getPassword()).toBe(password);
  });

  it('should work when containing the word, but is long enough.', () => {
    // Contains the word, but 7/10 = 0.70, which is smaller than threshold of 0.75
    const result = handler.handleSync('troubaDour');
    expect(result.isSuccess).toBeTruthy();
  });
});

describe('an invalid password', () => {
  it('should reject banned words.', () => {
    // Contains troubad and ratio is 7/9 = 0.78
    const result = handler.handleSync('1troubadr');
    const failures = result.getFailures();

    expect(failures).toHaveLength(1);
    expect(failures[0].rule).toBe('caseInsensitiveWords');
    expect(failures[0].expected).toBe(0);
    expect(failures[0].actual).toBe(1);
  });

  it('should reject banned words when the password starts with it.', () => {
    const result = handler.handleSync('trouBADor');
    const failures = result.getFailures();

    expect(failures).toHaveLength(1);
    expect(failures[0].rule).toBe('caseInsensitiveWords');
    expect(failures[0].expected).toBe(0);
    expect(failures[0].actual).toBe(1);
  });
});
