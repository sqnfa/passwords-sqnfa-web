import {
  EmailBlackListHandler,
  EmailBlackListConfiguration,
} from '../../src/handlers/email-blacklist-handler';

const email = 'john-doe@company.example.com';

describe('when adding an e-mail to the blacklist without using the sliding window', () => {
  const emailTokenHandler = new EmailBlackListHandler({
    email: email,
    slidingWindow: 0,
    minTokenLength: 0,
  });
  it('should only add all tokens to the blacklist.', () => {
    ['john', 'doe', 'company', 'example'].forEach(password => {
      const result = emailTokenHandler.handleSync(password);

      const failures = result.getFailures();
      expect(failures).toHaveLength(1);
      expect(failures[0].rule).toBe('emailTokens');
      expect(failures[0].expected).toBe(0);
      expect(failures[0].actual).toBe(1);
    });
  });

  it('should allow the tld to be used.', () => {
    const result = emailTokenHandler.handleSync('com');

    expect(result.isSuccess).toBeTruthy();
  });
});
describe('when adding an e-mail to the blacklist using the sliding window', () => {
  const config = new EmailBlackListConfiguration(email, 5, 4);
  const handler = new EmailBlackListHandler(config);

  it('should block partial words based on a sliding window.', () => {
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
      const result = handler.handleSync(password);

      const failures = result.getFailures();
      expect(failures).toHaveLength(1);
      expect(failures[0].rule).toBe('emailTokens');
      expect(failures[0].expected).toBe(0);
      expect(failures[0].actual).toBe(1);
    });
  });

  it('should allow short words in the e-mail.', () => {
    const result = handler.handleSync('doe');

    expect(result.isSuccess).toBeTruthy();
  });
});
