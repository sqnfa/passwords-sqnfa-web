import {Result} from '../result.js';
import type {HandlerSync} from '../types/sqnfa.js';

export class RegexConfiguration {
  /**
   *
   */
  constructor(
    /**
     * Patterns describing complete blocked password values after NFC normalization.
     */
    readonly regExps: RegExp[]
  ) {}
}

export class RegexHandler implements HandlerSync {
  public readonly name: string = 'RegexHandler';

  /** Reject complete password values matching a configured blocklist pattern. */
  constructor(private readonly config: RegexConfiguration) {}

  public handleSync(password: string): Result {
    password = password.normalize('NFC');
    // Global and sticky patterns carry lastIndex between test() calls.
    // Each password must be checked from the start without mutating caller state.
    const matchesRegExp = this.config.regExps.some((regExp) => {
      const match = new RegExp(
        `^(?:${regExp.source})(?![\\s\\S])`,
        regExp.flags
      ).exec(password);
      return match !== null && match.index === 0;
    });
    if (matchesRegExp) {
      return Result.fail({
        handler: this.name,
        rule: 'regExps',
        expected: 0,
        actual: 1,
      });
    }

    return Result.ok(password);
  }
}
