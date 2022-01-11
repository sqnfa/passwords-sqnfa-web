import {Result} from '../result';
import {HandlerSync} from '../types/sqnfa';

export class LengthConfiguration {
  /**
   * The minimum number of characters in the password.
   */
  public minLength = 8;
  /**
   * The maximum number of bytes the password is represented in UTF8 code units.
   */
  public maxByteSize = 72;
}

export class LengthHandler implements HandlerSync {
  private config: LengthConfiguration;

  public readonly name: string = 'LengthHandler';

  /**
   * NIST 800-63B:
   * Password length has been found to be a primary factor in characterizing
   * password strength. [...] Extremely long passwords (perhaps megabytes in
   * length) could conceivably require excessive processing time to hash, so
   * it is reasonable to have some limit. [...] Accordingly, at LOA2,
   * SP 800-63-2 permitted the use of randomly generated PINs with 6 or more
   * digits while requiring user-chosen memorized secrets to be a minimum of
   * 8 characters long.
   */
  constructor(config?: LengthConfiguration) {
    if (!config) {
      config = new LengthConfiguration();
    }
    this.config = config;
  }

  /**
   * Checks that the password is minimum minLength and takes up at most
   * maxBytesSize encoded in UTF-8.
   *
   * @param password The password to check.
   * @returns Successful result is within the limits or a failure otherwise.
   */
  public handleSync(password: string): Result {
    if (password.length < this.config.minLength) {
      return Result.fail({
        rule: 'minLength',
        expected: this.config.minLength,
        actual: password.length,
        handler: this.name,
      });
    }

    // TODO: Omit calling utf8Length if the password cannot be longer.
    const size = this.utf8Length(password);
    if (size > this.config.maxByteSize) {
      return Result.fail({
        rule: 'maxByteSize',
        expected: this.config.maxByteSize,
        actual: size,
        handler: this.name,
      });
    }

    return Result.ok(password);
  }

  /**
   * Calculates the byte length of a string encoded as UTF8.
   *
   * See: https://github.com/dcodeIO/bcrypt.js/blob/7e2e93af99df2952253f9cf32db29aefa8f272f7/dist/bcrypt.js#L341
   * @param string The string to measure.
   * @returns The byte length of the string encoded as UTF8.
   */
  private utf8Length(string: string) {
    let len = 0,
      c = 0;
    for (let i = 0; i < string.length; ++i) {
      c = string.charCodeAt(i);
      if (c < 128) len += 1;
      else if (c < 2048) len += 2;
      else if (
        (c & 0xfc00) === 0xd800 &&
        (string.charCodeAt(i + 1) & 0xfc00) === 0xdc00
      ) {
        ++i;
        len += 4;
      } else len += 3;
    }
    return len;
  }
}
