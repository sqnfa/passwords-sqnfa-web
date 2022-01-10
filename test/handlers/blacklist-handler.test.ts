import {
  BlacklistHandler,
  BlacklistConfiguration,
} from '../../src/handlers/blacklist-handler';
// https://xkcd.com/936/
const config = new BlacklistConfiguration(
  ['troubaD'],
  [new RegExp(/tr[o0]ub[a4]dor[u&][r3]/i)]
);
const handler = new BlacklistHandler(config);

describe('a valid password', () => {
  const password = 'MyPassword';
  it('should return the original password in the result.', () => {
    const result = handler.handle(password);
    expect(result.isSuccess).toBeTruthy();
    expect(result.getPassword()).toBe(password);
  });

  it('should be valid when no case insensitive words are provided.', () => {
    const emptyHandler = new BlacklistHandler({
      caseInsensitiveWords: [],
      regExps: [],
    });

    const result = emptyHandler.handle(password);

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

  it('should reject banned words when the password starts with it.', () => {
    const result = handler.handle('trouBADour');
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

describe('when adding an e-mail to the blacklist', () => {
  it('should add all tokens to the blacklist.', () => {
    const emptyHandler = new BlacklistHandler({
      caseInsensitiveWords: [],
      regExps: [],
    });

    emptyHandler.addEmailInformation('john-doe@company.example.com');
    ['john', 'doe', 'company', 'example'].forEach(password => {
      const result = emptyHandler.handle(password);

      const failures = result.getFailures();
      expect(failures).toHaveLength(1);
      expect(failures[0].rule).toBe('caseInsensitiveWords');
      expect(failures[0].expected).toBe(0);
      expect(failures[0].actual).toBe(1);
    });
  });

  it('should allow the tld to be used.', () => {
    const emptyHandler = new BlacklistHandler({
      caseInsensitiveWords: [],
      regExps: [],
    });
    emptyHandler.addEmailInformation('john-doe@company.example.com');

    const result = emptyHandler.handle('com');

    expect(result.isSuccess).toBeTruthy();
  });

  it('should block partial words based on a sliding window.', () => {
    const emptyHandler = new BlacklistHandler({
      caseInsensitiveWords: [],
      regExps: [],
    });
    emptyHandler.addEmailInformation('john-doe@company.example.com', 5);

    [
      'john',
      'doe',
      'company',
      'example',
      'compa',
      'ompan',
      'mpany',
      'examp',
      'xampl',
      'ample',
    ].forEach(password => {
      const result = emptyHandler.handle(password);

      const failures = result.getFailures();
      expect(failures).toHaveLength(1);
      expect(failures[0].rule).toBe('caseInsensitiveWords');
      expect(failures[0].expected).toBe(0);
      expect(failures[0].actual).toBe(1);
    });
  });

  it('should allow short words in the e-mail.', () => {
    const emptyHandler = new BlacklistHandler({
      caseInsensitiveWords: [],
      regExps: [],
    });
    emptyHandler.addEmailInformation('john-doe@eu.example.com', undefined, 2);

    const result = emptyHandler.handle('eu');

    expect(result.isSuccess).toBeTruthy();
  });
});
