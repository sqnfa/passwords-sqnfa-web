import {Result} from '../result';
import {Handler, HaveibeenpwnedHttpClient} from '../types/sqnfa';
import * as jshashes from 'jshashes';

export class HaveibeenpwnedConfiguration {
  public pwnedPasswordsUrl = 'https://api.pwnedpasswords.com/range/';
  constructor(readonly httpClient: HaveibeenpwnedHttpClient) {}
}

export class HaveibeenpwnedHandler implements Handler {
  public readonly name = 'HaveibeenpwnedHandler';

  /**
   * NIST 800-63B:
   * Password complexity: Users’ password choices are very predictable,
   * so attackers are likely to guess passwords that have been successful
   * in the past. For this reason, it is recommended that passwords chosen
   * by users be compared against a “black list” of unacceptable passwords.
   * This list should include passwords from previous breach corpuses.
   *
   * The web service haveibeenpwned.com is a free resource for anyone to
   * quickly assess if they may have been put at risk due to an online
   * account of theirs having been compromised or "pwned" in a data breach.
   */
  constructor(private config: HaveibeenpwnedConfiguration) {}

  /**
   * Uses the pwned passwords range search that ensures k-anonymity while looking for breaches.
   *
   * @param password The password to check.
   * @returns Successful result if the password is not found or a failure otherwise.
   */
  async handle(password: string): Promise<Result> {
    const hashedPassword = new jshashes.SHA1().setUpperCase(true).hex(password);
    const url = this.constructUrl(hashedPassword);
    const pwnedPasswordHashes = await this.config.httpClient.get(url);

    const predicate = hashedPassword.substring(5);
    const pwnedValue = pwnedPasswordHashes.find(value =>
      value.startsWith(predicate)
    );

    if (pwnedValue) {
      return Result.fail({
        handler: this.name,
        rule: 'pwned',
        actual: 1,
        expected: 0,
      });
    }

    return Result.ok(password);
  }

  private constructUrl(hashedPassword: string): string {
    let url = this.config.pwnedPasswordsUrl;
    if (!url.endsWith('/')) {
      url += '/';
    }
    return url + hashedPassword.substring(0, 5);
  }
}
