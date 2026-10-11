import {Result} from '../result.js';
import type {HandlerSync} from '../types/sqnfa.js';

export class EmailBlackListConfiguration {
  constructor(
    /** Email address used to derive complete context-specific password values. */
    readonly email: string,
    /** Minimum size of a derived token, in Unicode code points. */
    readonly minTokenLength: number = 1
  ) {}
}

/** Reject complete passwords equal to an email address or its account/service tokens. */
export class EmailBlackListHandler implements HandlerSync {
  public readonly name = 'EmailBlackListHandler';
  private readonly emailTokens = new Set<string>();

  constructor(config: EmailBlackListConfiguration) {
    this.addEmailInformation(config.email, config.minTokenLength);
  }

  public handleSync(password: string): Result {
    password = password.normalize('NFC');
    if (this.emailTokens.has(password.toUpperCase())) {
      return Result.fail({
        handler: this.name,
        rule: 'emailTokens',
        expected: 0,
        actual: 1,
      });
    }
    return Result.ok(password);
  }

  /** Add complete contextual values; no substring or sliding-window comparisons. */
  public addEmailInformation(email: string, minTokenLength = 1): void {
    email = email.normalize('NFC');
    const separator = email.lastIndexOf('@');
    if (separator <= 0 || separator === email.length - 1) {
      throw new Error(
        'An email address with a local part and domain is required.'
      );
    }
    if (!Number.isInteger(minTokenLength) || minTokenLength < 1) {
      throw new Error('minTokenLength must be a positive integer.');
    }
    const localPart = email.slice(0, separator);
    const domain = email.slice(separator + 1);
    const domainParts = domain.split('.');
    domainParts.pop();
    const tokens = [
      email,
      localPart,
      ...localPart.split(/[^\p{L}\p{M}\p{N}]+/u),
      ...domainParts,
    ];
    for (const token of tokens) {
      if (Array.from(token).length >= minTokenLength)
        this.emailTokens.add(token.toUpperCase());
    }
  }
}
