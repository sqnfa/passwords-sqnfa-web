import {Result} from '../result';
import {Handler} from '../types/sqnfa';
import {hashSync} from 'bcryptjs';

export class BcryptConfiguration {
  constructor(readonly salt: string) {}
}

export class BcryptHandler implements Handler {
  public readonly name: string = 'BcryptHandler';

  /**
   * Initializes the instance with the given config.
   */
  constructor(private readonly config: BcryptConfiguration) {}

  public handle(password: string): Result {
    const hash = hashSync(password, this.config.salt);
    return Result.ok(hash);
  }
}
