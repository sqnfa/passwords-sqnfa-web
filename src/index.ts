import {BcryptConfiguration, BcryptHandler} from './handlers/bcrypt-handler';
import {
  BlacklistConfiguration,
  BlacklistHandler,
} from './handlers/blacklist-handler';
import {
  HaveibeenpwnedConfiguration,
  HaveibeenpwnedHandler,
} from './handlers/haveibeenpwned-handler';
import {LengthConfiguration, LengthHandler} from './handlers/length-handler';
import {Sha512Handler} from './handlers/sha512-handler';
import {Failure, Result} from './result';
import {Handler, HandlerSync} from './types/sqnfa';

export class PasswordsSqnfaWeb implements Handler {
  public readonly name = 'PasswordsSqnfaWeb';
  private handlers: [Handler | HandlerSync, boolean][] = [];
  private failures: Failure[] = [];

  async handle(password: string): Promise<Result> {
    this.failures = [];
    for (const entity in this.handlers) {
      if (Object.prototype.hasOwnProperty.call(this.handlers, entity)) {
        const element = this.handlers[entity],
          handler = element[0],
          stopOnFailure = element[1];
        let result: Result;
        if ('handleSync' in handler) {
          result = handler.handleSync(password);
        } else {
          result = await handler.handle(password);
        }

        if (result.isSuccess) {
          password = result.getPassword();
        } else {
          result.getFailures().forEach(failure => this.failures.push(failure));

          if (stopOnFailure) {
            return Result.fail(this.failures);
          }
        }
      }
    }

    if (this.failures.length > 0) {
      return Result.fail(this.failures);
    }
    return Result.ok(password);
  }

  public useSync(
    handler: HandlerSync,
    stopOnFailure = false
  ): PasswordsSqnfaWeb {
    this.handlers.push([handler, stopOnFailure]);
    return this;
  }

  public use(handler: Handler, stopOnFailure = false): PasswordsSqnfaWeb {
    this.handlers.push([handler, stopOnFailure]);
    return this;
  }

  public useLengthHandler(
    config?: LengthConfiguration,
    stopOnFailure = false
  ): PasswordsSqnfaWeb {
    return this.useSync(new LengthHandler(config), stopOnFailure);
  }

  public useBlackListHandler(
    config: BlacklistConfiguration,
    stopOnFailure = false
  ): PasswordsSqnfaWeb {
    return this.useSync(new BlacklistHandler(config), stopOnFailure);
  }

  public useHaveibeenpwnedHandler(
    config: HaveibeenpwnedConfiguration,
    stopOnFailure = false
  ): PasswordsSqnfaWeb {
    return this.use(new HaveibeenpwnedHandler(config), stopOnFailure);
  }

  public useSha512Handler(stopOnFailure = false): PasswordsSqnfaWeb {
    return this.useSync(new Sha512Handler(), stopOnFailure);
  }

  public useBcryptHandler(
    config: BcryptConfiguration,
    stopOnFailure = false
  ): PasswordsSqnfaWeb {
    return this.useSync(new BcryptHandler(config), stopOnFailure);
  }
}
