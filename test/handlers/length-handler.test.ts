import {LengthHandler} from '../../src/handlers/length-handler';

describe('a valid password', () => {
  const handler = new LengthHandler();
  it('should return the original password in the result.', () => {
    // Registered trademark is 2 bytes, ethiopic syllable phwa is 3 bytes and rocket is 4 bytes in UTF8.
    const password = 'UnicodeWelcome: ÂŽáˇđ';

    const result = handler.handleSync(password);

    expect(result.isSuccess).toBeTruthy();
    expect(result.getPassword()).toBe(password);
  });
});

describe('an invalid password', () => {
  // Each of the three wise monkeys take two charactar space per monkey in UTF16 and 4 bytes of space each in UTF8.
  const threeWiseMonkeys = 'đđđ';

  it('should reject short passwords.', () => {
    const handler = new LengthHandler();

    const result = handler.handleSync(threeWiseMonkeys);
    const failures = result.getFailures();

    expect(failures).toHaveLength(1);
    expect(failures[0].rule).toBe('minLength');
    expect(failures[0].expected).toBe(8);
    expect(failures[0].actual).toBe(6);
  });

  it('should reject large passwords.', () => {
    const handler = new LengthHandler({minLength: 3, maxByteSize: 10});

    const result = handler.handleSync(threeWiseMonkeys);
    const failures = result.getFailures();

    expect(failures).toHaveLength(1);
    expect(failures[0].rule).toBe('maxByteSize');
    expect(failures[0].expected).toBe(10);
    expect(failures[0].actual).toBe(12);
  });
});
