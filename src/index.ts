import {BcryptConfiguration, BcryptHandler} from './handlers/bcrypt-handler';
import {
  BlacklistConfiguration,
  BlackListHandler,
} from './handlers/blacklist-handler';
import {
  HaveibeenpwnedConfiguration,
  HaveibeenpwnedHandler,
} from './handlers/haveibeenpwned-handler';
import {LengthConfiguration, LengthHandler} from './handlers/length-handler';
import {Sha512Handler} from './handlers/sha512-handler';
import {Failure, Result} from './result';
import {Handler, HandlerSync} from './types/sqnfa';

/**
 * 
 * 
 * @license passwords-sqnfa-web (c) 2022 Martin Storgaard Dieu <martin@storgaarddieu.com>
 * Released under the Apache License, Version 2.0
 * see: https://github.com/sqnfa/passwords-sqnfa-web/ for details
 */
export class PasswordsSqnfaWeb implements Handler {
  public readonly name = 'PasswordsSqnfaWeb';
  private handlers: [Handler | HandlerSync, boolean][] = [];
  private failures: Failure[] = [];
  private statistics: {[key: string]: number} = {};

  async handle(password: string): Promise<Result> {
    this.failures = [];
    this.statistics = {};
    const thisStartTime = performance.now();
    for (const entity of this.handlers) {
      let result: Result;
      const handler = entity[0];
      const stopOnFailure = entity[1];

      const handlerStartTime = performance.now();
      if ('handleSync' in handler) {
        result = handler.handleSync(password);
      } else {
        result = await handler.handle(password);
      }
      this.statistics[handler.name] = ~~(performance.now() - handlerStartTime);

      if (result.isSuccess) {
        password = result.getPassword();
      } else {
        result.getFailures().forEach(failure => this.failures.push(failure));
      }

      if (stopOnFailure && this.failures.length > 0) {
        break;
      }
    }

    const thisEndTime = performance.now();
    this.statistics[this.name] = ~~(thisEndTime - thisStartTime);
    if (this.failures.length > 0) {
      return Result.fail(this.failures);
    }
    return Result.ok(password);
  }

  /**
   * Bring your own handler. Any instance that implements the HandlerSync interface can be added.
   * Please bear in mind that high password complexity requriements does not always yield
   * highly secure passwords chosen by the user.
   *
   * @param handler A syncronous implementaion of a handler.
   * @param stopOnFailure If true, the execution will stop, if any failures has happened to this point.
   * @returns The current instance of PasswordsSqnfaWeb which allows chaining of the use* methods.
   */
  public useSync(
    handler: HandlerSync,
    stopOnFailure = false
  ): PasswordsSqnfaWeb {
    this.handlers.push([handler, stopOnFailure]);
    return this;
  }

  /**
   * Bring your own handler. Any instance that implements the Handler interface can be added.
   * Please bear in mind that high password complexity requriements does not always yield
   * highly secure passwords chosen by the user.
   *
   * @param handler An asyncronous implementaion of a handler.
   * @param stopOnFailure If true, the execution will stop, if any failures has happened to this point.
   * @returns The current instance of PasswordsSqnfaWeb which allows chaining of the use* methods.
   */
  public use(handler: Handler, stopOnFailure = false): PasswordsSqnfaWeb {
    this.handlers.push([handler, stopOnFailure]);
    return this;
  }

  /**
   * @see LengthHandler for details.
   *
   * @param config @see LengthConfiguration for details.
   * @param stopOnFailure If true, the execution will stop, if any failures has happened to this point.
   * @returns The current instance of PasswordsSqnfaWeb which allows chaining of the use* methods.
   */
  public useLengthHandler(
    config?: LengthConfiguration,
    stopOnFailure = false
  ): PasswordsSqnfaWeb {
    return this.useSync(new LengthHandler(config), stopOnFailure);
  }

  /**
   * @see BlackListHandler for details.
   *
   * @param config @see BlacklistConfiguration for details.
   * @param stopOnFailure If true, the execution will stop, if any failures has happened to this point.
   * @param email If provided, the information contained within the e-mail will be added.
   * @param emailSlidingWindow The size of the sliding window used when tokenizing the email.
   * @param emailMinTokenLength A safe-gaurd to ensure that shorter tokens are not added.
   * @returns The current instance of PasswordsSqnfaWeb which allows chaining of the use* methods.
   */
  public useBlackListHandler(
    config: BlacklistConfiguration,
    stopOnFailure = false,
    email?: string,
    emailSlidingWindow?: number,
    emailMinTokenLength?: number
  ): PasswordsSqnfaWeb {
    const handler = new BlackListHandler(config);
    if (email) {
      handler.addEmailInformation(
        email,
        emailSlidingWindow,
        emailMinTokenLength
      );
    }
    return this.useSync(handler, stopOnFailure);
  }

  /**
   * @see HaveibeenpwnedHandler for details.
   *
   * @param config @see HaveibeenpwnedConfiguration for details.
   * @param stopOnFailure If true, the execution will stop, if any failures has happened to this point.
   * @returns The current instance of PasswordsSqnfaWeb which allows chaining of the use* methods.
   */
  public useHaveibeenpwnedHandler(
    config: HaveibeenpwnedConfiguration,
    stopOnFailure = false
  ): PasswordsSqnfaWeb {
    return this.use(new HaveibeenpwnedHandler(config), stopOnFailure);
  }

  /**
   * @see Sha512Handler for details.
   *
   * @param stopOnFailure If true, the execution will stop, if any failures has happened to this point.
   * @returns The current instance of PasswordsSqnfaWeb which allows chaining of the use* methods.
   */
  public useSha512Handler(stopOnFailure = false): PasswordsSqnfaWeb {
    return this.useSync(new Sha512Handler(), stopOnFailure);
  }

  /**
   * @see BcryptHandler for details.
   *
   * @param config @see BcryptConfiguration for details.
   * @param stopOnFailure If true, the execution will stop, if any failures has happened to this point.
   * @returns The current instance of PasswordsSqnfaWeb which allows chaining of the use* methods.
   */
  public useBcryptHandler(
    config: BcryptConfiguration,
    stopOnFailure = false
  ): PasswordsSqnfaWeb {
    return this.use(new BcryptHandler(config), stopOnFailure);
  }
}
