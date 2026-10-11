import {Result} from '../result.js';
import type {HandlerSync} from '../types/sqnfa.js';

export class BlackListConfiguration {
  constructor(
    /** Complete password values to reject, compared without case distinctions. */
    readonly caseInsensitiveWords: string[]
  ) {}
}

/** Compare the complete password against configured common or expected values. */
export class BlackListHandler implements HandlerSync {
  public readonly name = 'BlackListHandler';
  private readonly blockedValues: Set<string>;

  constructor(config: BlackListConfiguration) {
    this.blockedValues = new Set(
      config.caseInsensitiveWords.map((value) =>
        value.normalize('NFC').toUpperCase()
      )
    );
  }

  public handleSync(password: string): Result {
    password = password.normalize('NFC');
    if (this.blockedValues.has(password.toUpperCase())) {
      return Result.fail({
        handler: this.name,
        rule: 'caseInsensitiveWords',
        expected: 0,
        actual: 1,
      });
    }
    return Result.ok(password);
  }
}
