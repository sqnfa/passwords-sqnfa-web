import {
  BlackListHandler,
  BlacklistConfiguration,
} from '../../src/handlers/blacklist-handler';
// https://xkcd.com/936/
const config = new BlacklistConfiguration(
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
});

describe('when adding an e-mail to the blacklist', () => {
  it('should add all tokens to the blacklist.', () => {
    const emptyHandler = new BlackListHandler({
      caseInsensitiveWords: [],
      regExps: [],
    });

    emptyHandler.addEmailInformation(
      'john-doe@company.example.com',
      undefined,
      3
    );
    ['john', 'doe', 'company', 'example'].forEach(password => {
      const result = emptyHandler.handleSync(password);

      const failures = result.getFailures();
      expect(failures).toHaveLength(1);
      expect(failures[0].rule).toBe('emailTokens');
      expect(failures[0].expected).toBe(0);
      expect(failures[0].actual).toBe(1);
    });
  });

  it('should allow the tld to be used.', () => {
    const emptyHandler = new BlackListHandler({
      caseInsensitiveWords: [],
      regExps: [],
    });
    emptyHandler.addEmailInformation('john-doe@company.example.com');

    const result = emptyHandler.handleSync('com');

    expect(result.isSuccess).toBeTruthy();
  });

  it('should block partial words based on a sliding window.', () => {
    const emptyHandler = new BlackListHandler({
      caseInsensitiveWords: [],
      regExps: [],
    });
    emptyHandler.addEmailInformation('john-doe@company.example.com', 5);

    [
      'john',
      'company',
      'example',
      'compa',
      'ompan',
      'mpany',
      'examp',
      'xampl',
      'ample',
      'johnd',
      'ohndo',
      'hndoe',
      'panye',
      'anyex',
      'nyexa',
      'yexam',
      'john-',
      'ohn-d',
      'hn-do',
      'n-doe',
      'pany.',
      'any.e',
      'ny.ex',
      'y.exa',
      '.exam',
    ].forEach(password => {
      const result = emptyHandler.handleSync(password);

      const failures = result.getFailures();
      expect(failures).toHaveLength(1);
      expect(failures[0].rule).toBe('emailTokens');
      expect(failures[0].expected).toBe(0);
      expect(failures[0].actual).toBe(1);
    });
  });

  it('should allow short words in the e-mail.', () => {
    const emptyHandler = new BlackListHandler({
      caseInsensitiveWords: [],
      regExps: [],
    });
    emptyHandler.addEmailInformation('john-doe@eu.example.com');

    ['eu', 'doe'].forEach(password => {
      const result = emptyHandler.handleSync(password);

      expect(result.isSuccess).toBeTruthy();
    });
  });
});
