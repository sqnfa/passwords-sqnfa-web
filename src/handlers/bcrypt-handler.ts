import {Result} from '../result';
import {HandlerSync} from '../types/sqnfa';
import {hashSync} from 'bcryptjs';

export class BcryptConfiguration {
  constructor(readonly salt: string) {}
}

export class BcryptHandler implements HandlerSync {
  public readonly name: string = 'BcryptHandler';

  /**
   * Can be used
   */
  constructor(private readonly config: BcryptConfiguration) {}

  public handleSync(password: string): Result {
    const hash = hashSync(password, this.config.salt);
    return Result.ok(hash);
  }
}
