import {Result} from '../result';
import {HandlerSync} from '../types/sqnfa';

export class EmailBlackListConfiguration {
  constructor(
    /**
     * The information contained within the e-mail will be added to the black list.
     */
    readonly email: string,
    /**
     * The size of the sliding window used when tokenizing the email.
     */
    readonly slidingWindow: number,
    /**
     * A safe-gaurd to ensure that shorter tokens are not added, i.e. ensure that
     * the handler is not too restrictive.
     */
    readonly minTokenLength: number
  ) {}
}

export class EmailBlackListHandler implements HandlerSync {
  public readonly name: string = 'EmailBlackListHandler';

  private emailTokens: string[] = [];

  /**
   * NIST 800-63B:
   * Password complexity: Users’ password choices are very predictable,
   * so attackers are likely to guess passwords that have been successful
   * in the past. For this reason, it is recommended that passwords chosen
   * by users be compared against a “black list” of unacceptable passwords.
   * This list should include pecific words (such as the name of the service
   * itself) that users are likely to choose.
   *
   * This handler black lists passwords containing parts of the user's e-mail
   * address. The e-mail is tokenized and each token is added to the black list.
   */
  constructor(config: EmailBlackListConfiguration) {
    this.addEmailInformation(
      config.email,
      config.slidingWindow,
      config.minTokenLength
    );
  }

  public handleSync(password: string): Result {
    const upperCasePassword = password.toLocaleUpperCase();

    const containsEmailTokens = this.emailTokens.some(
      token => upperCasePassword.indexOf(token.toLocaleUpperCase()) >= 0
    );
    if (containsEmailTokens) {
      return Result.fail({
        handler: this.name,
        rule: 'emailTokens',
        expected: 0,
        actual: 1,
      });
    }

    return Result.ok(password);
  }

  /**
   * Adds information about the e-mail. The e-mail is tokenized and each token
   * is added to the black list.
   *
   * Example: john.doe@example.com
   *
   *   Tokens: john, example
   *   (Note that doe is below minTokenLength)
   *
   * Sliding windows 4:
   *
   *   Tokens: john, example, ohn., hn.d, n.do, .doe, exam, xamp, ampl, mple
   *
   * @param email The e-mail that should be black listed.
   * @param slidingWindowSize If positive non-zero: Adds words of the size provided sliding accross the e-mail.
   * @param minTokenLength A safe-gaurd to not let the black list be too restricted.
   */
  public addEmailInformation(
    email: string,
    slidingWindowSize: number,
    minTokenLength: number
  ): void {
    const words = new Set<string>();
    const parts = email.split('@'),
      localTokens = parts[0].split(/[!#$%&'*+-/=?^_`{|]+/),
      domainTokens = parts[1].split(/[!#$%&'*+-/=?^_`{|]+/);
    const lastTld = domainTokens.pop();

    localTokens.forEach(token => words.add(token));
    domainTokens.forEach(token => words.add(token));

    if (slidingWindowSize > 0) {
      // Process each token
      localTokens.forEach(token => {
        this.addSlidingWindowWords(token, slidingWindowSize, words);
      });
      domainTokens.forEach(token => {
        this.addSlidingWindowWords(token, slidingWindowSize, words);
      });

      // Proccess the token joined together
      this.addSlidingWindowWords(
        localTokens.join(''),
        slidingWindowSize,
        words
      );
      this.addSlidingWindowWords(
        domainTokens.join(''),
        slidingWindowSize,
        words
      );

      // Process the original local part of the e-mail
      this.addSlidingWindowWords(parts[0], slidingWindowSize, words);
      // Process the original domain part of the e-mail
      let domainPart = parts[1];
      if (lastTld) {
        domainPart = domainPart.substring(
          0,
          domainPart.length - lastTld.length - 1
        );
      }
      this.addSlidingWindowWords(domainPart, slidingWindowSize, words);
    }
    // Add all words to the caseInsensitiveWords configuration that are longer than minTokenLength
    words.forEach(word => this.addToken(word, minTokenLength));
  }

  private addSlidingWindowWords(
    token: string,
    slidingWindowSize: number,
    words: Set<string>
  ) {
    const maxIndex = token.length - slidingWindowSize + 1;
    for (let index = 0; index < maxIndex; index++) {
      words.add(token.substring(index, index + slidingWindowSize));
    }
  }

  private addToken(token: string, minLength: number) {
    if (token.length >= minLength) {
      this.emailTokens.push(token);
    }
  }
}
