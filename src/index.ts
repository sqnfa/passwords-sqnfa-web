import {
  BlackListConfiguration,
  BlackListHandler,
} from './handlers/blacklist-handler.js';
import {
  EmailBlackListConfiguration,
  EmailBlackListHandler,
} from './handlers/email-blacklist-handler.js';
import {
  HaveibeenpwnedConfiguration,
  HaveibeenpwnedHandler,
} from './handlers/haveibeenpwned-handler.js';
import {LengthConfiguration, LengthHandler} from './handlers/length-handler.js';
import {RegexConfiguration, RegexHandler} from './handlers/regex-handler.js';
import {Result} from './result.js';
import type {Failure} from './result.js';
import type {Handler, HandlerSync} from './types/sqnfa.js';

/**
 * Configurable client-side password checks and asynchronous extension support.
 * See docs/password-guidance.md for the NIST/OWASP policy mapping and server responsibilities.
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

  async handle(password: string): Promise<Result> {
    password = password.normalize('NFC');
    const failures: Failure[] = [];
    const statistics: Record<string, number> = {};
    // Snapshot configuration so additions only affect subsequent calls.
    const handlers = [...this.handlers];
    const thisStartTime = performance.now();
    for (const entity of handlers) {
      let result: Result;
      const handler = entity[0];
      const stopOnFailure = entity[1];

      const handlerStartTime = performance.now();
      if ('handleSync' in handler) {
        result = handler.handleSync(password);
      } else {
        result = await handler.handle(password);
      }
      statistics[handler.name] = ~~(performance.now() - handlerStartTime);

      if (result.isSuccess) {
        password = result.getPassword().normalize('NFC');
      } else {
        result.getFailures().forEach((failure) => failures.push(failure));
      }

      if (stopOnFailure && failures.length > 0) {
        break;
      }
    }

    const thisEndTime = performance.now();
    statistics[this.name] = ~~(thisEndTime - thisStartTime);
    this.statistics = statistics;
    if (failures.length > 0) {
      return Result.fail(failures);
    }
    return Result.ok(password);
  }

  /**
   * Bring your own handler. Any instance that implements Handler or HandlerSync can be added.
   * Please bear in mind that high password complexity requirements does not always yield
   * highly secure passwords chosen by the user.
   *
   * @param handler A synchronous or asynchronous implementation of a handler contract.
   * @param stopOnFailure If true, the execution will stop, if any failures has happened to this point.
   * @returns The current instance of PasswordsSqnfaWeb which allows chaining of the use* methods.
   */
  public use(handler: Handler | HandlerSync, stopOnFailure = true): this {
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
    stopOnFailure = true
  ): this {
    return this.use(new LengthHandler(config), stopOnFailure);
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
    stopOnFailure = true
  ): this {
    return this.use(new BlackListHandler(config), stopOnFailure);
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
    stopOnFailure = true
  ): this {
    return this.use(new RegexHandler(config), stopOnFailure);
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
    stopOnFailure = true
  ): this {
    return this.use(new EmailBlackListHandler(config), stopOnFailure);
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
    stopOnFailure = true
  ): this {
    return this.use(new HaveibeenpwnedHandler(config), stopOnFailure);
  }
}

// The package root is the supported API for consumers and optional extensions.
export {Result} from './result.js';
export type {Failure} from './result.js';
export type {
  Handler,
  HandlerSync,
  HaveibeenpwnedHttpClient,
} from './types/sqnfa.js';
export {
  BlackListConfiguration,
  BlackListHandler,
} from './handlers/blacklist-handler.js';
export {
  EmailBlackListConfiguration,
  EmailBlackListHandler,
} from './handlers/email-blacklist-handler.js';
export {
  HaveibeenpwnedConfiguration,
  HaveibeenpwnedHandler,
} from './handlers/haveibeenpwned-handler.js';
export {LengthConfiguration, LengthHandler} from './handlers/length-handler.js';
export {RegexConfiguration, RegexHandler} from './handlers/regex-handler.js';
