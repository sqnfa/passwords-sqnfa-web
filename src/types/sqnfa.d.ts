import {Result} from '../result';

export interface Handler {
  /**
   * Runs the actual implementation of how the password should be handled.
   * @param password The password to handle.
   */
  handle(password: string): Result;

  /**
   * The name of the handler that is safe to be used as part of an identifier in HTML.
   */
  name: string;
}

export interface HaveibeenpwnedHttpClient {
  get(url: string): string[];
}
