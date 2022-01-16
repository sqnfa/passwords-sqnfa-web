import {Result} from '../result';
import {Handler} from '../types/sqnfa';
import {hash} from 'bcryptjs';
import {utf8Length} from '../util';
import * as jshashes from 'jshashes';

export class BcryptConfiguration {
  constructor(readonly salt: string) {}
}

export class BcryptHandler implements Handler {
  public readonly name: string = 'BcryptHandler';

  /**
   * Bcrypt can be used as a means for server releif. It is a feature
   * that allows the server to delegate the most expensive part of
   * hashing to the client. The server, however, still need to treat
   * the received value as a password and it has to undergo at least
   * a preimage-resistant function. Another benefit is that the users
   * original password is never sent to the server. Should the server
   * leak an bcrypt hashed password, then an adversary would not be
   * able to recover the actual password.
   *
   * Note: Bcrypt limits the password length to be 72 encoded in utf-8.
   * Should the users password be longer than this, then the password
   * will be hashed with SHA512/432 and encoded in base64 before being 
   * hashed by bcrypt.
   */
  constructor(private readonly config: BcryptConfiguration) {}

  public async handle(password: string): Promise<Result> {
    if (utf8Length(password) >= 72) {
      password = new jshashes.SHA512().b64(password).substring(0, 72);
    }
    const hashedPassword = await hash(password, this.config.salt);
    return Result.ok(hashedPassword);
  }
}
