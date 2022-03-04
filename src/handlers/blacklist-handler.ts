import {Result} from '../result';
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
     * The ratio between the length of the password over the length of the black listed word.
     * 0.75 would imply that 6 out of 8 consecutive characters cannot be on the black list.
     */
    readonly ratioThreshold: number
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
   * This handler black lists passwords containing parts of black listed words.
   */
  constructor(private readonly config: BlackListConfiguration) {}

  public handleSync(password: string): Result {
    const upperCasePassword = password.toLocaleUpperCase();
    const passwordLength = upperCasePassword.length;
    const containsCaseInsensitveWord = this.config.caseInsensitiveWords.some(
      word =>
        upperCasePassword.indexOf(word.toLocaleUpperCase()) >= 0 &&
        word.length / passwordLength >= this.config.ratioThreshold
    );
    if (containsCaseInsensitveWord) {
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
