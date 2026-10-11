import {Result} from '../result.js';
import type {HandlerSync} from '../types/sqnfa.js';

export class LengthConfiguration {
  /**
   * The minimum number of Unicode code points in the password.
   */
  public minLength = 15;
  /**
   * The maximum UTF-8 encoded password size in bytes.
   */
  public maxByteSize = 1024;
}

export class LengthHandler implements HandlerSync {
  private config: LengthConfiguration;

  public readonly name: string = 'LengthHandler';

  /** Validate Unicode character length and UTF-8 byte size. */
  constructor(config?: LengthConfiguration) {
    if (!config) {
      config = new LengthConfiguration();
    }
    this.config = config;
  }

  /**
   * Checks that the password is minimum minLength and takes up at most
   * maxByteSize encoded in UTF-8.
   *
   * @param password The password to check.
   * @returns Successful result is within the limits or a failure otherwise.
   */
  public handleSync(password: string): Result {
    password = password.normalize('NFC');
    const characterCount = Array.from(password).length;
    if (characterCount < this.config.minLength) {
      return Result.fail({
        rule: 'minLength',
        expected: this.config.minLength,
        actual: characterCount,
        handler: this.name,
      });
    }

    const size = new TextEncoder().encode(password).byteLength;
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
}
