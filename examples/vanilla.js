/* global PasswordsSqnfaWeb */
const {PasswordsSqnfaWeb: PasswordPipeline, HaveibeenpwnedConfiguration} =
  PasswordsSqnfaWeb;
const form = document.querySelector('#password-form');
const passwordInput = document.querySelector('#password');
const submit = document.querySelector('#submit');
const status = document.querySelector('#status');
const details = document.querySelector('#details');
const guidance = document.querySelector('#guidance');
const showPassword = document.querySelector('#show-password');

showPassword.addEventListener('click', () => {
  const visible = passwordInput.type === 'password';
  passwordInput.type = visible ? 'text' : 'password';
  showPassword.textContent = visible ? 'Hide password' : 'Show password';
  showPassword.setAttribute('aria-pressed', String(visible));
});

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (submit.disabled) return;
  submit.disabled = true;
  status.textContent = 'Checking…';
  details.textContent = '';
  guidance.textContent = '';
  const pipeline = new PasswordPipeline()
    .useLengthHandler({minLength: 15, maxByteSize: 1024}, true)
    .useEmailBlackListHandler(
      {
        email: document.querySelector('#email').value,
        minTokenLength: 4,
      },
      true
    )
    .useBlackListHandler(
      {
        caseInsensitiveWords: [
          'password',
          'passwordpassword',
          'correcthorsebatterystaple',
        ],
      },
      true
    );

  if (document.querySelector('#breach-check').checked) {
    pipeline.useHaveibeenpwnedHandler(
      new HaveibeenpwnedConfiguration({
        async get(url) {
          const response = await fetch(url, {
            headers: {'Add-Padding': 'true'},
            signal: AbortSignal.timeout(15000),
          });
          if (!response.ok) throw new Error('Breach service unavailable');
          return (await response.text()).split(/\r?\n/);
        },
      }),
      true
    );
  }

  try {
    const result = await pipeline.handle(passwordInput.value);
    status.textContent = result.isSuccess
      ? 'Password passed the configured policies.'
      : 'Password did not pass the configured policies.';
    guidance.textContent = result.isSuccess
      ? ''
      : result
          .getFailures()
          .map((failure) => {
            if (failure.rule === 'minLength')
              return `Use at least ${failure.expected} characters. Try a longer passphrase.`;
            if (failure.rule === 'maxByteSize')
              return `Choose a passphrase within ${failure.expected} UTF-8 bytes. Your password was not shortened.`;
            return 'Choose a different passphrase. This complete value is common, expected, or known to be compromised; avoid simply adding a digit to it.';
          })
          .join(' ');
    details.textContent = JSON.stringify(
      {
        failures: result.isSuccess ? [] : result.getFailures(),
        milliseconds: pipeline.statistics,
      },
      null,
      2
    );
  } catch {
    status.textContent =
      'The breach check could not be completed. Please try again.';
  } finally {
    passwordInput.value = '';
    passwordInput.type = 'password';
    showPassword.textContent = 'Show password';
    showPassword.setAttribute('aria-pressed', 'false');
    submit.disabled = false;
  }
});
