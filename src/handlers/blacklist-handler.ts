import {Failure, Result} from '../result';
import {HandlerSync} from '../types/sqnfa';

export class BlackListConfiguration {
  /**
   *
   */
  constructor(
    /**
     * A list of black listed words. Both the password and every words are compared with toLocaleUpperCase.
     */
    readonly caseInsensitiveWords: string[],
    /**
     * A list of black listed regular expressions. Each expression is compared with the original password.
     */
    readonly regExps: RegExp[]
  ) {}
}

export class BlackListHandler implements HandlerSync {
  public readonly name: string = 'BlackListHandler';

  /**
   * NIST 800-63B:
   * Password complexity: Users’ password choices are very predictable,
   * so attackers are likely to guess passwords that have been successful
   * in the past. For this reason, it is recommended that passwords chosen
   * by users be compared against a “black list” of unacceptable passwords.
   * This list should include dictionary words, and specific words (such as
   * the name of the service itself) that users are likely to choose.
   *
   * This handler black lists passwords containing parts of black listed words
   * or passwords that matches defined regular expressions.
   */
  constructor(private readonly config: BlackListConfiguration) {}

  public handleSync(password: string): Result {
    const failures: Failure[] = [];

    const upperCasePassword = password.toLocaleUpperCase();
    const containsCaseInsensitveWord = this.config.caseInsensitiveWords.some(
      word => upperCasePassword.indexOf(word.toLocaleUpperCase()) >= 0
    );
    if (containsCaseInsensitveWord) {
      failures.push({
        handler: this.name,
        rule: 'caseInsensitiveWords',
        expected: 0,
        actual: 1,
      });
    }

    const matchesRegExp = this.config.regExps.some(regExp =>
      regExp.test(password)
    );
    if (matchesRegExp) {
      failures.push({
        handler: this.name,
        rule: 'regExps',
        expected: 0,
        actual: 1,
      });
    }

    if (failures.length > 0) {
      return Result.fail(failures);
    }

    return Result.ok(password);
  }
}
