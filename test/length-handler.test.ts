import {LengthHandler} from '../src/length-handler';

describe('a valid password', () => {
  const handler = new LengthHandler();
  it('should return the original password in the result.', () => {
    const password = 'MyPassword';

    const result = handler.handle(password);

    expect(result.isSuccess).toBeTruthy();
    expect(result.getPassword()).toBe(password);
  });
});

describe('an invalid password', () => {
  // Each of the three wise monkeys take two charactar space per monkey in UTF16 and 4 bytes of space each in UTF8.
  const threeWiseMonkeys = '🙈🙉🙊';

  it('should reject short passwords.', () => {
    const handler = new LengthHandler();

    const result = handler.handle(threeWiseMonkeys);
    const failures = result.getFailures();

    expect(failures).toHaveLength(1);
    expect(failures[0].rule).toBe('minLength');
    expect(failures[0].expected).toBe(10);
    expect(failures[0].actual).toBe(6);
  });

  it('should reject large passwords.', () => {
    const handler = new LengthHandler({minLength: 3, maxByteSize: 10});

    const result = handler.handle(threeWiseMonkeys);
    const failures = result.getFailures();

    expect(failures).toHaveLength(1);
    expect(failures[0].rule).toBe('maxByteSize');
    expect(failures[0].expected).toBe(10);
    expect(failures[0].actual).toBe(12);
  });
});
