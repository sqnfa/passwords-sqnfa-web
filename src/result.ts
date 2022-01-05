export class Result {
  public isSuccess: boolean;
  public error: string | null;
  private password: string | null;

  private constructor(
    isSuccess: boolean,
    error: string | null,
    password: string | null
  ) {
    this.isSuccess = isSuccess;
    this.error = error;
    this.password = password;

    Object.freeze(this);
  }

  public getPassword(): string {
    if (!this.isSuccess) {
      throw new Error(
        'Invalid operation: Cannot retreive the password from a failed result.'
      );
    }
    if (!this.password) {
      throw new Error(
        'Runtime error: Password not set on a successful result.'
      );
    }
    return this.password;
  }

  public static ok(password: string) {
    return new Result(true, null, password);
  }

  public static fail(error: string) {
    return new Result(false, error, null);
  }
}
