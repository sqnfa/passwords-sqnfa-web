import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {createServer} from 'node:http';
import {readFile} from 'node:fs/promises';
import {resolve, extname, sep} from 'node:path';
import {chromium} from 'playwright';

async function serve(directory) {
  const root = resolve(directory);
  const server = createServer(async (request, response) => {
    try {
      const url = new URL(request.url, 'http://localhost');
      const path = resolve(
        root,
        '.' +
          (url.pathname === '/'
            ? '/index.html'
            : decodeURIComponent(url.pathname))
      );
      if (!path.startsWith(root + sep)) {
        response.writeHead(403).end();
        return;
      }
      const mime = {
        '.html': 'text/html',
        '.js': 'text/javascript',
        '.css': 'text/css',
      };
      response
        .writeHead(200, {
          'Content-Type': mime[extname(path)] || 'application/octet-stream',
        })
        .end(await readFile(path));
    } catch {
      response.writeHead(404).end();
    }
  });
  await new Promise((resolveListen) =>
    server.listen(0, '127.0.0.1', resolveListen)
  );
  return {server, url: `http://127.0.0.1:${server.address().port}`};
}

const vanilla = await serve('.');
const angular = await serve('examples/angular/dist/password-demo/browser');
let browser;
try {
  browser = await chromium.launch({headless: true});
  for (const [name, url] of [
    ['vanilla', vanilla.url + '/examples/vanilla.html'],
    ['angular', angular.url],
  ]) {
    const page = await browser.newPage();
    const errors = [];
    page.on('pageerror', (error) => errors.push(error.message));
    await page.goto(url);
    await page.locator('#email').fill('user@demo.test');
    const password = 'correct horse battery staple';
    const suffix = createHash('sha1')
      .update(password)
      .digest('hex')
      .toUpperCase()
      .slice(5);
    let responseMode = 'padding';
    let requests = 0;
    await page.route(
      'https://api.pwnedpasswords.com/range/**',
      async (route) => {
        requests++;
        if (responseMode === 'error')
          return route.fulfill({status: 503, body: 'Unavailable'});
        await route.fulfill({
          status: 200,
          contentType: 'text/plain',
          body: suffix + (responseMode === 'breach' ? ':3\r\n' : ':0\r\n'),
        });
      }
    );

    async function submit(value, message) {
      await page.locator('#password').fill(value);
      await page.getByRole('button', {name: 'Validate password'}).click();
      await page.waitForFunction((expected) => {
        const input = document.querySelector('#password');
        const status = document.querySelector('[role="status"]');
        return input?.value === '' && status?.textContent === expected;
      }, message);
      assert.equal(await page.locator('#password').inputValue(), '');
      assert.equal(
        await page.locator('#password').getAttribute('type'),
        'password'
      );
      assert.equal(await page.getByRole('status').textContent(), message);
    }
    await page.locator('#password').fill(password);
    await page
      .getByRole('button', {name: 'Show password', exact: true})
      .click();
    await page.locator('#password[type="text"]').waitFor();
    assert.equal(await page.locator('#password').getAttribute('type'), 'text');
    await page
      .getByRole('button', {name: 'Hide password', exact: true})
      .click();
    await page.locator('#password[type="password"]').waitFor();
    assert.equal(
      await page.locator('#password').getAttribute('type'),
      'password'
    );
    await submit('short', 'Password did not pass the configured policies.');
    assert.match(
      await page.locator('#guidance').textContent(),
      /at least 15 characters/
    );
    assert.match(await page.locator('pre').textContent(), /minLength/);
    assert.equal(requests, 0);
    await submit(password, 'Password passed the configured policies.');
    assert.equal(requests, 0);
    await submit(
      'passwordpassword',
      'Password did not pass the configured policies.'
    );
    assert.match(
      await page.locator('#guidance').textContent(),
      /different passphrase/
    );
    await submit(
      'a passwordpassword passphrase',
      'Password passed the configured policies.'
    );
    await submit('🚀'.repeat(64), 'Password passed the configured policies.');
    await page.getByRole('checkbox').check();
    await submit('short', 'Password did not pass the configured policies.');
    assert.equal(requests, 0);
    await submit(password, 'Password passed the configured policies.');
    assert.equal(requests, 1);
    responseMode = 'breach';
    await submit(password, 'Password did not pass the configured policies.');
    assert.match(await page.locator('pre').textContent(), /pwned/);
    assert.match(
      await page.locator('#guidance').textContent(),
      /known to be compromised/
    );
    responseMode = 'error';
    await submit(
      password,
      'The breach check could not be completed. Please try again.'
    );
    assert.deepEqual(errors, []);
    console.log(
      `${name}: Unicode, complete-password policies, visibility, guidance, breach, and error checks passed.`
    );
    await page.close();
  }
} finally {
  await browser?.close();
  await Promise.all(
    [vanilla.server, angular.server].map(
      (server) => new Promise((resolveClose) => server.close(resolveClose))
    )
  );
}
