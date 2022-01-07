import {Result} from '../result';
import {Handler} from '../types/sqnfa';

export class LengthConfiguration {
  /**
   * The minimum number of characters in the password.
   */
  public minLength = 10;
  /**
   * The maximum number of bytes the password is represented in UTF8 code units.
   * Note that bcrypt has a password limit of 72 bytes.
   */
  public maxByteSize = 72;
}

export class LengthHandler implements Handler {
  private config: LengthConfiguration;

  public readonly name: string = 'LengthHandler';

  /**
   * Initializes the instance with the given config.
   */
  constructor(config?: LengthConfiguration) {
    if (!config) {
      config = new LengthConfiguration();
    }
    this.config = config;
  }

  public handle(password: string): Result {
    if (password.length < this.config.minLength) {
      return Result.fail({
        rule: 'minLength',
        expected: this.config.minLength,
        actual: password.length,
        handler: this.name,
      });
    }

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
