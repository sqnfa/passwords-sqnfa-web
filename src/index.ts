import {BcryptConfiguration, BcryptHandler} from './handlers/bcrypt-handler';
import {
  BlackListConfiguration,
  BlackListHandler,
} from './handlers/blacklist-handler';
import {
  EmailBlackListConfiguration,
  EmailBlackListHandler,
} from './handlers/email-blacklist-handler';
import {
  HaveibeenpwnedConfiguration,
  HaveibeenpwnedHandler,
} from './handlers/haveibeenpwned-handler';
import {LengthConfiguration, LengthHandler} from './handlers/length-handler';
import {RegexConfiguration, RegexHandler} from './handlers/regex-handler';
import {Sha512Handler} from './handlers/sha512-handler';
import {Failure, Result} from './result';
import {Handler, HandlerSync} from './types/sqnfa';

/**
 * Passwords are still essential for most applications. This also includes web applications.
 * This library implements the recommendations that apply to client-side password handling
 * from the National Institute of Standards and Technology (NIST) and the Open Web Application
 * Security Project (OWASP). The purpose of this library is to provide an easy pluggable
 * client-side password preprocessor. It is not a substitute for the proper handling of passwords
 * in the backend and should only be considered an extra layer.
 *
 * @license passwords-sqnfa-web Copyright 2022 Martin Storgaard Dieu <martin@storgaarddieu.com>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://github.com/sqnfa/passwords-sqnfa-web/blob/main/LICENSE
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
export class PasswordsSqnfaWeb implements Handler {
  public readonly name = 'PasswordsSqnfaWeb';
  /**
   * A key-value property that contains the name of handlers that has been
   * run as key and their total running time statistics in milliseconds as
   * value.
   */
  public statistics: {[key: string]: number} = {};

  private handlers: [Handler | HandlerSync, boolean][] = [];
  private failures: Failure[] = [];

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
   * @param handler A syncronous implementaion of the handler interface.
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
   * @param handler An asyncronous implementaion of the handler interface.
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
   * @returns The current instance of PasswordsSqnfaWeb which allows chaining of the use* methods.
   */
  public useBlackListHandler(
    config: BlackListConfiguration,
    stopOnFailure = false
  ): PasswordsSqnfaWeb {
    return this.useSync(new BlackListHandler(config), stopOnFailure);
  }

  /**
   * @see RegexHandler for details.
   *
   * @param config @see RegexConfiguration for details.
   * @param stopOnFailure If true, the execution will stop, if any failures has happened to this point.
   * @returns The current instance of PasswordsSqnfaWeb which allows chaining of the use* methods.
   */
  public useRegexHandler(
    config: RegexConfiguration,
    stopOnFailure = false
  ): PasswordsSqnfaWeb {
    return this.useSync(new RegexHandler(config), stopOnFailure);
  }

  /**
   * @see EmailBlackListHandler for details.
   *
   * @param config @see EmailBlackListConfiguration for details
   * @param stopOnFailure If true, the execution will stop, if any failures has happened to this point.
   * @returns The current instance of PasswordsSqnfaWeb which allows chaining of the use* methods.
   */
  public useEmailBlackListHandler(
    config: EmailBlackListConfiguration,
    stopOnFailure = false
  ): PasswordsSqnfaWeb {
    return this.useSync(new EmailBlackListHandler(config), stopOnFailure);
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
