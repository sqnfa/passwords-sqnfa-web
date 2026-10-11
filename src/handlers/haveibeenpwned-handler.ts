import {Result} from '../result.js';
import type {Handler, HaveibeenpwnedHttpClient} from '../types/sqnfa.js';

export class HaveibeenpwnedConfiguration {
  /**
   * The Pwned Passwords range API endpoint.
   */
  public pwnedPasswordsUrl = 'https://api.pwnedpasswords.com/range/';
  constructor(
    /**
     * Bring your own http client that does the actual call to the API.
     */
    readonly httpClient: HaveibeenpwnedHttpClient
  ) {}
}

export class HaveibeenpwnedHandler implements Handler {
  public readonly name = 'HaveibeenpwnedHandler';

  /** Check passwords against the Pwned Passwords range API using a SHA-1 prefix. */
  constructor(private config: HaveibeenpwnedConfiguration) {}

  /**
   * Sends only a five-character hash prefix and compares returned suffixes locally.
   *
   * @param password The password to check.
   * @returns Successful result if the password is not found or a failure otherwise.
   */
  async handle(password: string): Promise<Result> {
    password = password.normalize('NFC');
    // SHA-1 is only the lookup identifier required by the Pwned Passwords API.
    const digest = await globalThis.crypto.subtle.digest(
      'SHA-1',
      new TextEncoder().encode(password)
    );
    const hashedPassword = Array.from(new Uint8Array(digest), (byte) =>
      byte.toString(16).padStart(2, '0')
    )
      .join('')
      .toUpperCase();
    const url = this.constructUrl(hashedPassword);
    const pwnedPasswordHashes = await this.config.httpClient.get(url);

    const predicate = hashedPassword.substring(5);
    let pwnedValue = false;
    let validRows = 0;
    for (const value of pwnedPasswordHashes) {
      const row = value.trim();
      if (!row) continue;
      const match = /^([a-f\d]{35}):(\d+)$/i.exec(row);
      if (!match) throw new Error('Invalid Pwned Passwords response row.');
      validRows++;
      if (match[1].toUpperCase() === predicate && Number(match[2]) > 0) {
        pwnedValue = true;
      }
    }

    if (validRows === 0) throw new Error('Empty Pwned Passwords response.');
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
