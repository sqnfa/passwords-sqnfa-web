import {BcryptHandler} from './bcrypt-handler';
import {LengthHandler} from './length-handler';
import {Failure, Result} from './result';
import {Handler} from './sqnfa';

export class PasswordsSqnfaWeb implements Handler {
  public readonly name = 'PasswordsSqnfaWeb';
  private handlers: [Handler, boolean][] = [];
  private failures: Failure[] = [];

  handle(password: string): Result {
    this.failures = [];
    for (const entity in this.handlers) {
      if (Object.prototype.hasOwnProperty.call(this.handlers, entity)) {
        const element = this.handlers[entity],
          handler = element[0],
          stopOnFailure = element[1],
          result = handler.handle(password);

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

  public use(handler: Handler, stopOnFailure = false): PasswordsSqnfaWeb {
    this.handlers.push([handler, stopOnFailure]);
    return this;
  }

  public getFailures(): Failure[] {
    return this.failures;
  }
}

export const test = new PasswordsSqnfaWeb()
  .use(new LengthHandler())
  .use(new BcryptHandler({salt: '$2a$12$RNbCt.Je2GAP4ub8FyX5le'}));
console.log(test.handle('correct'));
console.log(test.getFailures());
//console.log(test.handle('correct horse battery staple'));
//console.log(test.getFailures());
