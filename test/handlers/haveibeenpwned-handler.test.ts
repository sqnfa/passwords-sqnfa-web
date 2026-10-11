import {
  HaveibeenpwnedConfiguration,
  HaveibeenpwnedHandler,
} from '../../src/handlers/haveibeenpwned-handler';
import {MockHttpClient} from '../mock-http-client';

// https://xkcd.com/936/
const pwnedPassword = 'tr0ub4dor&3';
// Please note that this password should no longer be consider OK, since it is publically available now
const okPassword = '@ecgS=C63fz>}f`b3_G3';

const handler = new HaveibeenpwnedHandler(
  new HaveibeenpwnedConfiguration(new MockHttpClient())
);

describe('a leaked password', () => {
  it('should fail the check.', async () => {
    const result = await handler.handle(pwnedPassword);
    const failures = result.getFailures();

    expect(failures).toHaveLength(1);
    expect(failures[0].handler).toEqual(handler.name);
    expect(failures[0].rule).toEqual('pwned');
    expect(failures[0].expected).toEqual(0);
    expect(failures[0].actual).toEqual(1);
  });
});

describe('a valid password', () => {
  it('should yield the same password.', async () => {
    const result = await handler.handle(okPassword);

    expect(result.getPassword()).toEqual(okPassword);
  });
});
