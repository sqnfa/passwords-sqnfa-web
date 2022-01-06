import {PasswordsSqnfaWeb} from '../src/index';
import {LengthHandler} from '../src/length-handler';

describe('a successful handling with the chain of responsibility', () => {
  const handler = new PasswordsSqnfaWeb()
    .use(new LengthHandler())
    .use(new LengthHandler({minLength: 0, maxByteSize: 5000}));
  it('should return a successful result.', () => {
    const result = handler.handle('correct-horse-battery-staple');

    expect(result.isSuccess).toBeTruthy();
  });
});

describe('a failed handling with the chain of responsibility without stop on failure', () => {
  const handler = new PasswordsSqnfaWeb()
    .use(new LengthHandler({minLength: 0, maxByteSize: 1}))
    .use(new LengthHandler({minLength: 5000, maxByteSize: 5000}), true)
    .use(new LengthHandler({minLength: 0, maxByteSize: 1}));
  it('should only contain failures up until the point to stop.', () => {
    const result = handler.handle('correct-horse-battery-staple');

    expect(result.isSuccess).toBeFalsy();
    expect(result.getFailures()).toHaveLength(2);
  });
});
