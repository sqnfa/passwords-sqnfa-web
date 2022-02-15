import {Result} from '../result';
import {HandlerSync} from '../types/sqnfa';

export class RegexConfiguration {
  /**
   *
   */
  constructor(
    /**
     * A list of black listed regular expressions. Each expression is compared with the original password.
     */
    readonly regExps: RegExp[]
  ) {}
}

export class RegexHandler implements HandlerSync {
  public readonly name: string = 'RegexHandler';

  /**
   * NIST 800-63B:
   * Password complexity: Users’ password choices are very predictable,
   * so attackers are likely to guess passwords that have been successful
   * in the past. For this reason, it is recommended that passwords chosen
   * by users be compared against a “black list” of unacceptable passwords.
   * This list should include dictionary words, and specific words (such as
   * the name of the service itself) that users are likely to choose.
   *
   * This handler black lists passwords that matches defined regular
   * expressions, such as specific words related to the service itself.
   */
  constructor(private readonly config: RegexConfiguration) {}

  public handleSync(password: string): Result {
    const matchesRegExp = this.config.regExps.some(regExp =>
      regExp.test(password)
    );
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
