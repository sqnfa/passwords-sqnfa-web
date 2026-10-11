import {PasswordsSqnfaWeb, Result} from '../src/index';
import type {Handler, HandlerSync} from '../src/index';

const failure = {
  handler: 'AsyncValidation',
  rule: 'test',
  expected: 0,
  actual: 1,
};

it('accepts public sync and async extension contracts and preserves the transformed value', async () => {
  const sync: HandlerSync = {
    name: 'SyncExtension',
    handleSync: (password) => Result.ok(password + '!'),
  };
  const asyncHandler: Handler = {
    name: 'AsyncExtension',
    handle: async (password) => Result.ok(password + '?'),
  };
  const pipeline = new PasswordsSqnfaWeb().use(sync).use(asyncHandler);
  expect((await pipeline.handle('passphrase')).getPassword()).toBe(
    'passphrase!?'
  );
});

it('preserves subclass methods across built-in and custom fluent calls', async () => {
  class ExtendedPipeline extends PasswordsSqnfaWeb {
    useOptionalExtension(handler: Handler): this {
      return this.use(handler, true);
    }
  }
  const pipeline = new ExtendedPipeline()
    .useLengthHandler()
    .useOptionalExtension({
      name: 'OptionalExtension',
      handle: async (password) => Result.ok(password),
    });
  expect((await pipeline.handle('long passphrase')).isSuccess).toBe(true);
});

it('isolates failures and stop-on-failure for overlapping async calls', async () => {
  let release!: (result: Result) => void;
  const gate = new Promise<Result>((resolve) => {
    release = resolve;
  });
  const pipeline = new PasswordsSqnfaWeb()
    .use(
      {
        name: 'AsyncValidation',
        handle: (password) =>
          password === 'pending' ? gate : Promise.resolve(Result.fail(failure)),
      },
      true
    )
    .use({
      name: 'Transform',
      handleSync: (password) => Result.ok(password + '!'),
    });
  const pending = pipeline.handle('pending');
  const rejected = await pipeline.handle('rejected');
  release(Result.ok('pending'));
  const accepted = await pending;
  expect(rejected.getFailures()).toEqual([failure]);
  expect(accepted.getPassword()).toBe('pending!');
  expect(pipeline.statistics).toHaveProperty('Transform');
});

it('applies handlers registered during an async call only to later calls', async () => {
  let release!: (result: Result) => void;
  const gate = new Promise<Result>((resolve) => {
    release = resolve;
  });
  const pipeline = new PasswordsSqnfaWeb().use({
    name: 'Gate',
    handle: () => gate,
  });
  const pending = pipeline.handle('first');
  pipeline.use({
    name: 'Later',
    handleSync: (password) => Result.ok(password + '!'),
  });
  release(Result.ok('first'));
  expect((await pending).getPassword()).toBe('first');
  expect((await pipeline.handle('second')).getPassword()).toBe('first!');
});

it('propagates async extension errors without reporting policy success', async () => {
  const pipeline = new PasswordsSqnfaWeb().use({
    name: 'NetworkExtension',
    handle: async () => {
      throw new Error('unavailable');
    },
  });
  await expect(pipeline.handle('passphrase')).rejects.toThrow('unavailable');
});

it('stops on validation failure before running an authentication extension by default', async () => {
  const authenticate = vi.fn(async (password: string) => Result.ok(password));
  const pipeline = new PasswordsSqnfaWeb()
    .useLengthHandler()
    .use({name: 'Authentication', handle: authenticate});
  expect((await pipeline.handle('short')).isSuccess).toBe(false);
  expect(authenticate).not.toHaveBeenCalled();
});
