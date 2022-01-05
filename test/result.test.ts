import {Result} from '../src/result';
const password = 'MyPassword';
const error = 'The quick brown fox jumps over the lazy dog';

describe('a successful result', () => {
  const result = Result.ok(password);
  it('should set the attribute isSuccess to true.', () => {
    expect(result.isSuccess).toBeTruthy();
  });
  it('should make the password available.', () => {
    expect(result.getPassword()).toBe(password);
  });
  it('should not have the error attribute set.', () => {
    expect(result.error).toBeNull();
  });
  it('should be immutable.', () => {
    expect(() => (result.isSuccess = !result.isSuccess)).toThrowError(
      "Cannot assign to read only property 'isSuccess' of object"
    );
  });
});

describe('a failure result', () => {
  const result = Result.fail(error);
  it('should set the attribute isSuccess to false.', () => {
    expect(result.isSuccess).toBeFalsy();
  });
  it('should set the error attribute with the given message.', () => {
    expect(result.error).toBe(error);
  });
  it('should reject accessing the password.', () => {
    expect(() => result.getPassword()).toThrowError(
      'Invalid operation: Cannot retreive the password from a failed result.'
    );
  });
  it('should be immutable.', () => {
    expect(() => (result.isSuccess = !result.isSuccess)).toThrowError(
      "Cannot assign to read only property 'isSuccess' of object"
    );
  });
});
