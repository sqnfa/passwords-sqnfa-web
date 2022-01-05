import { Result } from './result';
import {Handler} from './sqnfa';

export interface LengthConfiguration {
  minLength: number;
  maxLength: number | null;
}

export class LengthHandler implements Handler {
  private config: LengthConfiguration;

  public readonly name: string = 'LengthHandler';

  /**
   *
   */
  constructor(config: LengthConfiguration) {
    this.config = config;
  }

  public handle(password: string): Result {
    return Result.ok(password);
  }
}
