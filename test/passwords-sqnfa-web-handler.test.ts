import {PasswordsSqnfaWeb} from '../src/index';
import {LengthHandler} from '../src/handlers/length-handler';
import {
  BlackListConfiguration,
  BlackListHandler,
} from '../src/handlers/blacklist-handler';
import {HaveibeenpwnedHandler} from '../src/handlers/haveibeenpwned-handler';
import {MockHttpClient} from './handlers/haveibeenpwned-handler.test';
import {Sha512Handler} from '../src/handlers/sha512-handler';
import {BcryptHandler} from '../src/handlers/bcrypt-handler';
import {
  EmailBlackListConfiguration,
  EmailBlackListHandler,
} from '../src/handlers/email-blacklist-handler';

describe('a successful handling with the chain of responsibility', () => {
  const handler = new PasswordsSqnfaWeb()
    .useSync(new LengthHandler())
    .useSync(new LengthHandler({minLength: 0, maxByteSize: 5000}))
    .useBlackListHandler(new BlackListConfiguration([]));
  it('should return a successful result.', async () => {
    const result = await handler.handle('correct-horse-battery-staple');

    expect(result.isSuccess).toBeTruthy();
  });
});

describe('a failed handling with the chain of responsibility without stop on failure', () => {
  const handler = new PasswordsSqnfaWeb()
    .useSync(new LengthHandler({minLength: 0, maxByteSize: 1}))
    .useSync(new LengthHandler({minLength: 5000, maxByteSize: 5000}), true)
    .useSync(new LengthHandler({minLength: 0, maxByteSize: 1}));
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
    new EmailBlackListConfiguration('john-doe@example.com', 0, 0)
  );
  const haveibeenpwnedHandler = new HaveibeenpwnedHandler({
    httpClient: new MockHttpClient(),
    pwnedPasswordsUrl: '',
  });
  const sha512Handler = new Sha512Handler();
  const bcryptSalt = '$2a$12$RNbCt.Je2GAP4ub8FyX5le';
  const bcryptHandler = new BcryptHandler({salt: bcryptSalt});
  const handler = new PasswordsSqnfaWeb()
    .useSync(lengthHandler)
    .useSync(blacklistHandler, true)
    .useSync(emailBlackListHandler)
    .use(haveibeenpwnedHandler, true)
    .useSync(sha512Handler)
    .use(bcryptHandler);

  it('should use all handlers and hash the password.', async () => {
    const lengthHandlerSpy = jest.spyOn(lengthHandler, 'handleSync');
    const blacklistHandlerSpy = jest.spyOn(blacklistHandler, 'handleSync');
    const emailBlackListHandlerSpy = jest.spyOn(
      emailBlackListHandler,
      'handleSync'
    );
    const haveibeenpwnedHandlerSpy = jest.spyOn(
      haveibeenpwnedHandler,
      'handle'
    );
    const sha512HandlerSpy = jest.spyOn(sha512Handler, 'handleSync');
    const bcryptHandlerSpy = jest.spyOn(bcryptHandler, 'handle');
    const password = '@ecgS=C63fz>}f`b3_G3';

    const result = await handler.handle(password);

    expect(lengthHandlerSpy).toBeCalledWith(password);
    expect(blacklistHandlerSpy).toBeCalledWith(password);
    expect(emailBlackListHandlerSpy).toBeCalledWith(password);
    expect(haveibeenpwnedHandlerSpy).toBeCalledWith(password);
    expect(sha512HandlerSpy).toBeCalledWith(password);
    expect(bcryptHandlerSpy).toBeCalledWith(
      'xLkyfoQIFWkdySxClgzbDE+YEn7GI0xwkoBCOyL1z0ozQdloTVS04k1/bIaYFuouMqPq0rpD'
    );

    expect(result.isSuccess).toBeTruthy();
    expect(result.getPassword().startsWith(bcryptSalt)).toBeTruthy();
  });

  it('should work on an empty password', async () => {
    const emptyHandler = new PasswordsSqnfaWeb()
      .useLengthHandler()
      .useBlackListHandler({caseInsensitiveWords: []})
      .useRegexHandler({regExps: []})
      .useEmailBlackListHandler({
        email: 'john@example.com',
        slidingWindow: 0,
        minTokenLength: 0,
      })
      .useHaveibeenpwnedHandler({
        pwnedPasswordsUrl: '',
        httpClient: new MockHttpClient(),
      })
      .useSha512Handler()
      .useBcryptHandler({salt: '$2a$08$RNbCt.Je2GAP4ub8FyX5le'});

    const result = await emptyHandler.handle('');

    expect(result.isSuccess).toBeFalsy();
  });
});
