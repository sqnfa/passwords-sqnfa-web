import {Result} from './result';
import {Handler, HaveibeenpwnedHttpClient} from './types/sqnfa';
import * as jshashes from 'jshashes';

export class HaveibeenpwnedConfiguration {
  public pwnedPasswordsUrl = 'https://api.pwnedpasswords.com/range/';
  constructor(readonly httpClient: HaveibeenpwnedHttpClient) {}
}

export class HaveibeenpwnedHandler implements Handler {
  public readonly name = 'HaveibeenpwnedHandler';

  /**
   *
   */
  constructor(private config: HaveibeenpwnedConfiguration) {}

  handle(password: string): Result {
    const hashedPassword = new jshashes.SHA1().hex(password);
    const url = this.constructUrl(hashedPassword);
    const pwnedPasswordHashes = this.config.httpClient.get(url);

    const predicate = hashedPassword.substring(5).toUpperCase();
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
