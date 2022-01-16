export interface Failure {
  handler: string;
  rule: string;
  expected: number;
  actual: number;
}

export class Result {
  private failures?: Failure[];

  private constructor(
    readonly isSuccess: boolean,
    failure?: Failure | Failure[],
    private password?: string
  ) {
    if (failure) {
      if (failure instanceof Array) {
        this.failures = failure;
      } else {
        this.failures = [failure];
      }
    }
  }

  public getPassword(): string {
    if (!this.isSuccess || this.password === undefined) {
      throw new Error(
        'Invalid operation: Cannot retreive the password from a failed result.'
      );
    }
    return this.password;
  }

  public getFailures(): Failure[] {
    if (this.isSuccess || !this.failures) {
      throw new Error(
        'Invalid operation: Cannot retreive the failure from a successful result.'
      );
    }
    return this.failures;
  }

  public static ok(password: string) {
    return new Result(true, undefined, password);
  }

  public static fail(failure: Failure | Failure[]) {
    return new Result(false, failure, undefined);
  }
}
