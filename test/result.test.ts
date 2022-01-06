import {Result} from '../src/result';
const password = 'MyPassword';
const failure = {
  handler: 'SystemUnderTest',
  rule: 'unittest',
  expected: 1,
  actual: 2,
};

describe('a successful result', () => {
  const result = Result.ok(password);
  it('should set the attribute isSuccess to true.', () => {
    expect(result.isSuccess).toBeTruthy();
  });
  it('should make the password available.', () => {
    expect(result.getPassword()).toBe(password);
  });
  it('should not have the failure attribute set.', () => {
    expect(() => result.getFailures()).toThrowError(
      'Invalid operation: Cannot retreive the failure from a successful result.'
    );
  });
});

describe('a failure result', () => {
  const result = Result.fail(failure);
  it('should set the attribute isSuccess to false.', () => {
    expect(result.isSuccess).toBeFalsy();
  });
  it('should set the failure attribute with the given message.', () => {
    expect(result.getFailures()).toBeDefined();
    expect(result.getFailures()).toHaveLength(1);
    expect(result.getFailures()).toContain(failure);
  });
  it('should reject accessing the password.', () => {
    expect(() => result.getPassword()).toThrowError(
      'Invalid operation: Cannot retreive the password from a failed result.'
    );
  });
});
