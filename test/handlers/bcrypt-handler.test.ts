import {
  BcryptConfiguration,
  BcryptHandler,
} from '../../src/handlers/bcrypt-handler';

function generatePassword(length: number): string {
  const alphabet =
    '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#';
  const alphabetLength = alphabet.length;
  let password = '';

  for (let i = 0; i < length; i++) {
    password += alphabet.charAt(Math.floor(Math.random() * alphabetLength));
  }
  return password;
}

describe('a valid password', () => {
  const salt = '$2a$12$RNbCt.Je2GAP4ub8FyX5le';
  const handler = new BcryptHandler(new BcryptConfiguration(salt));
  it('should hash the password.', async () => {
    const result = await handler.handle('correct-horse-battery-staple');

    expect(result.getPassword()).toEqual(
      '$2a$12$RNbCt.Je2GAP4ub8FyX5leAs6cZ7tICJ4aj/j.bMvxDUOVlB/OAuC'
    );
  });

  it('should hash long passwords.', async () => {
    const password = generatePassword(100);

    const result = await handler.handle(password);

    expect(result.getPassword()).toMatch(
      new RegExp(/^\$2a\$12\$RNbCt\.Je2GAP4ub8FyX5le[a-zA-Z0-9./]{31}$/)
    );
  });
});
