import {Result} from '../result';
import {Handler} from '../types/sqnfa';

export class BlacklistConfiguration {
  /**
   *
   */
  constructor(
    readonly caseInsensitiveWords?: string[],
    readonly regExps?: RegExp[]
  ) {}
}

export class BlacklistHandler implements Handler {
  public readonly name: string = 'BlacklistHandler';

  constructor(private readonly config: BlacklistConfiguration) {}

  public handle(password: string): Result {
    const lowerPassword = password.toLowerCase();
    if (this.config.caseInsensitiveWords) {
      for (const entry in this.config.caseInsensitiveWords) {
        if (
          Object.prototype.hasOwnProperty.call(
            this.config.caseInsensitiveWords,
            entry
          )
        ) {
          const word = this.config.caseInsensitiveWords[entry];
          if (lowerPassword.indexOf(word) > 0) {
            return Result.fail({
              handler: this.name,
              rule: 'caseInsensitiveWords',
              expected: 0,
              actual: 1,
            });
          }
        }
      }
    }

    if (this.config.regExps) {
      for (const entry in this.config.regExps) {
        if (Object.prototype.hasOwnProperty.call(this.config.regExps, entry)) {
          const regExp = this.config.regExps[entry];
          if (regExp.test(password)) {
            return Result.fail({
              handler: this.name,
              rule: 'regExps',
              expected: 0,
              actual: 1,
            });
          }
        }
      }
    }
    return Result.ok(password);
  }
}
