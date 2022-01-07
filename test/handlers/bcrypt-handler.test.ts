import {BcryptHandler} from '../../src/handlers/bcrypt-handler';

describe('a valid password', () => {
  const handler = new BcryptHandler({salt: '$2a$12$RNbCt.Je2GAP4ub8FyX5le'});
  it('should hash the password.', () => {
    const result = handler.handle('correct-horse-battery-staple');

    expect(result.getPassword()).toEqual(
      '$2a$12$RNbCt.Je2GAP4ub8FyX5leAs6cZ7tICJ4aj/j.bMvxDUOVlB/OAuC'
    );
  });
});
