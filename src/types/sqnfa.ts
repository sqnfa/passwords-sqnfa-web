import type {Result} from '../result.js';

export interface HandlerSync {
  /**
   * Runs the actual implementation of how the password should be handled.
   * @param password The password to handle.
   */
  handleSync(password: string): Result;

  /**
   * The name of the handler that is safe to be used as part of an identifier in HTML.
   */
  name: string;
}

export interface Handler {
  /**
   * Runs the actual implementation of how the password should be handled.
   * @param password The password to handle.
   */
  handle(password: string): Promise<Result>;

  /**
   * The name of the handler that is safe to be used as part of an identifier in HTML.
   */
  name: string;
}

export interface HaveibeenpwnedHttpClient {
  /**
   * Return Pwned Passwords response rows in suffix:count format.
   * Request Add-Padding: true, apply a timeout, and reject HTTP failures.
   */
  get(url: string): Promise<string[]>;
}
