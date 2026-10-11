import {PasswordsSqnfaWeb} from '../src/index';
import {LengthHandler} from '../src/handlers/length-handler';
import {
  BlackListConfiguration,
  BlackListHandler,
} from '../src/handlers/blacklist-handler';
import {HaveibeenpwnedHandler} from '../src/handlers/haveibeenpwned-handler';
import {MockHttpClient} from './mock-http-client';
import {
  EmailBlackListConfiguration,
  EmailBlackListHandler,
} from '../src/handlers/email-blacklist-handler';

describe('a successful handling with the chain of responsibility', () => {
  const handler = new PasswordsSqnfaWeb()
    .use(new LengthHandler())
    .use(new LengthHandler({minLength: 0, maxByteSize: 5000}))
    .useBlackListHandler(new BlackListConfiguration([]));
  it('should return a successful result.', async () => {
    const result = await handler.handle('correct-horse-battery-staple');

    expect(result.isSuccess).toBeTruthy();
  });
});

describe('a failed handling with the chain of responsibility without stop on failure', () => {
  const handler = new PasswordsSqnfaWeb()
    .use(new LengthHandler({minLength: 0, maxByteSize: 1}), false)
    .use(new LengthHandler({minLength: 5000, maxByteSize: 5000}), true)
    .use(new LengthHandler({minLength: 0, maxByteSize: 1}));
  it('should only contain failures up until the point to stop.', async () => {
    const result = await handler.handle('correct-horse-battery-staple');

    expect(result.isSuccess).toBeFalsy();
    expect(result.getFailures()).toHaveLength(2);
  });
});

describe('a normal usage', () => {
  const lengthHandler = new LengthHandler();
  const blacklistHandler = new BlackListHandler(
    new BlackListConfiguration(['sqnfa', 'password', 'web'])
  );
  const emailBlackListHandler = new EmailBlackListHandler(
    new EmailBlackListConfiguration('john-doe@example.com')
  );
  const haveibeenpwnedHandler = new HaveibeenpwnedHandler({
    httpClient: new MockHttpClient(),
    pwnedPasswordsUrl: '',
  });
  const handler = new PasswordsSqnfaWeb()
    .use(lengthHandler)
    .use(blacklistHandler, true)
    .use(emailBlackListHandler)
    .use(haveibeenpwnedHandler, true);

  it('should run all validators and preserve the original password.', async () => {
    const lengthHandlerSpy = vi.spyOn(lengthHandler, 'handleSync');
    const blacklistHandlerSpy = vi.spyOn(blacklistHandler, 'handleSync');
    const emailBlackListHandlerSpy = vi.spyOn(
      emailBlackListHandler,
      'handleSync'
    );
    const haveibeenpwnedHandlerSpy = vi.spyOn(haveibeenpwnedHandler, 'handle');
    const password = '@ecgS=C63fz>}f`b3_G3';

    const result = await handler.handle(password);

    expect(lengthHandlerSpy).toHaveBeenCalledWith(password);
    expect(blacklistHandlerSpy).toHaveBeenCalledWith(password);
    expect(emailBlackListHandlerSpy).toHaveBeenCalledWith(password);
    expect(haveibeenpwnedHandlerSpy).toHaveBeenCalledWith(password);
    expect(result.isSuccess).toBeTruthy();
    expect(result.getPassword()).toBe(password);
  });

  it('should work on an empty password', async () => {
    const emptyHandler = new PasswordsSqnfaWeb()
      .useLengthHandler()
      .useBlackListHandler({caseInsensitiveWords: []})
      .useRegexHandler({regExps: []})
      .useEmailBlackListHandler({
        email: 'john@example.com',
        minTokenLength: 1,
      })
      .useHaveibeenpwnedHandler({
        pwnedPasswordsUrl: '',
        httpClient: new MockHttpClient(),
      });

    const result = await emptyHandler.handle('');

    expect(result.isSuccess).toBeFalsy();
  });
});
