import {
  HaveibeenpwnedConfiguration,
  HaveibeenpwnedHandler,
} from '../src/haveibeenpwned-handler';
import {HaveibeenpwnedHttpClient} from '../src/types/sqnfa';

class MockHttpClient implements HaveibeenpwnedHttpClient {
  /**
   * Mocking a call to the Pwned Passwords API.
   *
   * @see https://haveibeenpwned.com/API/v3#PwnedPasswords
   * @see https://api.pwnedpasswords.com/range/28139
   *
   * @param url The URL to search by a partial hash for 28139.
   * @returns A snippet of the real response.
   */
  public get(url: string): string[] {
    if (!url.endsWith('28139')) {
      throw new Error(
        'This is a mock, please use the proper range identifier.'
      );
    }
    return [
      '7A30ADC83D7691025DE549A05759E6D822A:6',
      '7AA7421C63EA988F9012997E9E752B5E0FA:1',
      '7ADF36C33CB03CDDA4E73ACB31E93054D69:166',
      '7B1F7880ADE0F53530A55D9AF0210B9AD7B:4',
      '7BDFC2F85B77D669B10776D61E337A0D9BF:5',
      '7CD7ED367A78942FCC9F171ABBCA2D325BD:3',
      '7DDFD32D1D0ADDEDB81B7EB79FB1D1C1D20:1',
      '7DED1D74A49C0A514AD1E3C2080F19ACDD6:1',
      '7DFEF6FF7BA11232570F04386ABA88D04C4:2',
      '7E0C10B6614F9F767203B49144C771D27AD:1',
      '7E19FD46468919C2DA6A9D83AFEC5D294F7:4',
      '7E21179FE769B2C458140AA1B876247848E:1',
      '7F1224E046CEEA62A9EC2EE2698A79E3281:6',
      '7F5D93088F9CEE5180568EEDA5C249AE2AF:1',
      '7FB4885BC540D70911FF945A2C1D9481D1C:1',
      '7FC66358E06E8BEA35F4F0F6C9605939E9A:2',
    ];
  }
}

// https://xkcd.com/936/
const pwnedPassword = 'tr0ub4dor&3';
// Please note that this password should no longer be consider OK, since it is publically available now
const okPassword = '@ecgS=C63fz>}f`b3_G3';

const handler = new HaveibeenpwnedHandler(
  new HaveibeenpwnedConfiguration(new MockHttpClient())
);

describe('a leaked password', () => {
  it('should fail the check.', () => {
    const result = handler.handle(pwnedPassword);
    const failures = result.getFailures();

    expect(failures).toHaveLength(1);
    expect(failures[0].handler).toEqual(handler.name);
    expect(failures[0].rule).toEqual('pwned');
    expect(failures[0].expected).toEqual(0);
    expect(failures[0].actual).toEqual(1);
  });
});

describe('a valid password', () => {
  it('should yield the same password.', () => {
    const result = handler.handle(okPassword);

    expect(result.getPassword()).toEqual(okPassword);
  });
});
