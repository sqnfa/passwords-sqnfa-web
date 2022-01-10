import {Result} from '../result';
import {Handler} from '../types/sqnfa';

export class BlacklistConfiguration {
  /**
   *
   */
  constructor(
    /**
     * A list of blacklisted words. Both the password and every words are compared with toLocaleUpperCase.
     */
    readonly caseInsensitiveWords: string[],
    /**
     * A list of blacklisted regular expressions. Each expression is compared with the original password.
     */
    readonly regExps: RegExp[]
  ) {}
}

export class BlacklistHandler implements Handler {
  public readonly name: string = 'BlacklistHandler';

  constructor(private readonly config: BlacklistConfiguration) {}

  public handle(password: string): Result {
    const upperCasePassword = password.toLocaleUpperCase();
    const containsCaseInsensitveWord = this.config.caseInsensitiveWords.some(
      word => upperCasePassword.indexOf(word.toLocaleUpperCase()) >= 0
    );
    if (containsCaseInsensitveWord) {
      return Result.fail({
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
      return Result.fail({
        handler: this.name,
        rule: 'regExps',
        expected: 0,
        actual: 1,
      });
    }

    return Result.ok(password);
  }

  /**
   * addEmailInformation
   */
  public addEmailInformation(
    email: string,
    slidingWindowSize = 0,
    minTokenLength = 2
  ): void {
    const tokens = email.split(/[@!#$%&'*+-/=?^_`{|]+/);
    tokens.pop();

    tokens.forEach(token => this.addToken(token, minTokenLength));

    if (slidingWindowSize > 0) {
      tokens.forEach(token => {
        const maxIndex = token.length - slidingWindowSize + 1;
        for (let index = 0; index < maxIndex; index++) {
          this.addToken(
            token.substring(index, index + slidingWindowSize),
            minTokenLength
          );
        }
      });
    }
  }

  private addToken(token: string, minLength: number) {
    if (token.length > minLength) {
      this.config.caseInsensitiveWords.push(token);
    }
  }
}
