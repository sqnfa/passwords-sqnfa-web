import {HttpClient} from '@angular/common/http';
import {Component, inject, signal} from '@angular/core';
import {FormsModule} from '@angular/forms';
import {firstValueFrom} from 'rxjs';
import {
  HaveibeenpwnedConfiguration,
  PasswordsSqnfaWeb,
} from 'passwords-sqnfa-web';
import type {HaveibeenpwnedHttpClient} from 'passwords-sqnfa-web';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [FormsModule],
  template: `
    <main>
      <p>Angular 21 LTS sample</p>
      <h1>Check a password</h1>
      <p>
        Use a passphrase of at least 15 characters. This demo validates locally
        and does not create an account.
      </p>
      <p>
        Unicode characters are normalized to NFC. Use a password manager for
        consistent entry across devices.
      </p>
      <form #form="ngForm" (ngSubmit)="validate()">
        <label for="email">Email address</label>
        <input
          id="email"
          name="email"
          type="email"
          autocomplete="email"
          [(ngModel)]="email"
          required
          email
        />
        <label for="password">Password</label>
        <input
          id="password"
          name="password"
          [type]="showPassword() ? 'text' : 'password'"
          autocomplete="new-password"
          autocapitalize="none"
          spellcheck="false"
          [(ngModel)]="password"
          required
        />
        <button
          type="button"
          [attr.aria-pressed]="showPassword()"
          (click)="togglePassword()"
        >
          {{ showPassword() ? 'Hide password' : 'Show password' }}
        </button>
        <label
          ><input
            name="breachCheck"
            type="checkbox"
            [(ngModel)]="breachCheck"
          />
          Check Pwned Passwords (sends the first five characters of a SHA-1 hash
          to the service)</label
        >
        <button type="submit" [disabled]="busy() || form.invalid">
          Validate password
        </button>
      </form>
      <p role="status" aria-live="polite">{{ status() }}</p>
      <p id="guidance">{{ guidance() }}</p>
      <pre>{{ details() }}</pre>
    </main>
  `,
})
export class AppComponent {
  private readonly http = inject(HttpClient);
  email = '';
  password = '';
  breachCheck = false;
  readonly busy = signal(false);
  readonly status = signal('');
  readonly details = signal('');
  readonly guidance = signal('');
  readonly showPassword = signal(false);

  togglePassword(): void {
    this.showPassword.update((visible) => !visible);
  }

  async validate(): Promise<void> {
    if (this.busy()) return;
    this.busy.set(true);
    this.status.set('Checking…');
    this.details.set('');
    this.guidance.set('');
    const pipeline = new PasswordsSqnfaWeb()
      .useLengthHandler({minLength: 15, maxByteSize: 1024}, true)
      .useEmailBlackListHandler({email: this.email, minTokenLength: 4}, true)
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

    if (this.breachCheck) {
      const client: HaveibeenpwnedHttpClient = {
        get: async (url) => {
          const text = await firstValueFrom(
            this.http.get(url, {
              responseType: 'text',
              headers: {'Add-Padding': 'true'},
              timeout: 15000,
            })
          );
          return text.split(/\r?\n/);
        },
      };
      pipeline.useHaveibeenpwnedHandler(
        new HaveibeenpwnedConfiguration(client),
        true
      );
    }

    try {
      const result = await pipeline.handle(this.password);
      this.status.set(
        result.isSuccess
          ? 'Password passed the configured policies.'
          : 'Password did not pass the configured policies.'
      );
      this.guidance.set(
        result.isSuccess
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
              .join(' ')
      );
      this.details.set(
        JSON.stringify(
          {
            failures: result.isSuccess ? [] : result.getFailures(),
            milliseconds: pipeline.statistics,
          },
          null,
          2
        )
      );
    } catch {
      this.status.set(
        'The breach check could not be completed. Please try again.'
      );
    } finally {
      this.password = '';
      this.showPassword.set(false);
      this.busy.set(false);
    }
  }
}
