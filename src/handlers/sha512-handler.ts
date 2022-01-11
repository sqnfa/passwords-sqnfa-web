import {HandlerSync} from '../types/sqnfa';
import {Result} from '../result';
import * as jshashes from 'jshashes';

export class Sha512Handler implements HandlerSync {
  public readonly name: string = 'Sha512Handler';
  /**
   * NIST 800-107: Some applications may require a value that
   * is shorter than the (full-length) message digest provided
   * by an approved hash function as specified in FIPS 180-4.
   * In such cases, it may be appropriate to use a subset of the
   * bits produced by the hash function as the (shortened) message
   * digest.
   *
   * This handler calculates the SHA512/432 of the password and encode
   * the result in base64. This makes the encoded digest 72 bytes
   * making it fit perfectly into bcrypt.
   */
  constructor() {}

  public handleSync(password: string): Result {
    const hash = new jshashes.SHA512().b64(password);
    return Result.ok(hash.substring(0, 72));
  }
}
