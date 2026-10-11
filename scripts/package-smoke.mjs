import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const esm = await import('passwords-sqnfa-web');
const cjs = require('passwords-sqnfa-web');
const context = vm.createContext({
  performance,
  TextEncoder,
  TextDecoder,
  crypto,
  setTimeout,
});
vm.runInContext(
  await readFile('build/passwords-sqnfa-web.min.js', 'utf8'),
  context
);
for (const api of [esm, cjs, context.PasswordsSqnfaWeb]) {
  assert.equal(typeof api.Result.ok, 'function');
  const testPassword = 'package breach test';
  const digest = createHash('sha1')
    .update(testPassword)
    .digest('hex')
    .toUpperCase();
  const breach = new api.HaveibeenpwnedHandler(
    new api.HaveibeenpwnedConfiguration({
      get: async (url) => {
        assert.equal(
          url,
          'https://api.pwnedpasswords.com/range/' + digest.slice(0, 5)
        );
        return [digest.slice(5) + ':1'];
      },
    })
  );
  assert.equal((await breach.handle(testPassword)).isSuccess, false);
  const pipeline = new api.PasswordsSqnfaWeb().useLengthHandler(
    undefined,
    true
  );
  assert.equal((await pipeline.handle('short')).isSuccess, false);
  assert.equal(
    (await pipeline.handle('correct-horse-battery-staple')).isSuccess,
    true
  );
}
console.log('ESM, CommonJS, and browser package entry points passed.');
