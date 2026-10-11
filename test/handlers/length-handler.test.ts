import {LengthHandler} from '../../src/handlers/length-handler';

describe('a valid password', () => {
  const handler = new LengthHandler();
  it('should return the original password in the result.', () => {
    // Registered trademark is 2 bytes, ethiopic syllable phwa is 3 bytes and rocket is 4 bytes in UTF8.
    const password = 'UnicodeWelcome: ®ጷ🚀';

    const result = handler.handleSync(password);

    expect(result.isSuccess).toBeTruthy();
    expect(result.getPassword()).toBe(password);
  });
});

describe('an invalid password', () => {
  // Each emoji is one Unicode code point and four UTF-8 bytes.
  const threeWiseMonkeys = '🙈🙉🙊';

  it('should reject short passwords.', () => {
    const handler = new LengthHandler();

    const result = handler.handleSync(threeWiseMonkeys);
    const failures = result.getFailures();

    expect(failures).toHaveLength(1);
    expect(failures[0].rule).toBe('minLength');
    expect(failures[0].expected).toBe(15);
    expect(failures[0].actual).toBe(3);
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

it('accepts 15 Unicode code points without counting surrogate pairs twice', () => {
  const handler = new LengthHandler();
  expect(handler.handleSync('🚀'.repeat(14)).isSuccess).toBe(false);
  expect(handler.handleSync('🚀'.repeat(15)).getPassword()).toBe(
    '🚀'.repeat(15)
  );
});

it('accepts passwords at the byte limit and rejects passwords exceeding it', () => {
  const handler = new LengthHandler();
  expect(handler.handleSync('🚀'.repeat(256)).isSuccess).toBe(true);
  expect(handler.handleSync('🚀'.repeat(257)).getFailures()[0]).toMatchObject({
    rule: 'maxByteSize',
    expected: 1024,
    actual: 1028,
  });
});
