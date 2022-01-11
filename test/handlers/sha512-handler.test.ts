import {Sha512Handler} from '../../src/handlers/sha512-handler';

describe('a valid password', () => {
  const handler = new Sha512Handler();
  it('should hash the password.', () => {
    const result = handler.handleSync('correct-horse-battery-staple');

    expect(result.getPassword()).toEqual(
      'xA5y03NelhX8FOxHRRJRdBvEQVuvqL2UAa2VwG+Or5P/CU4sKtPu+zspQLq4hxox2jRiPtus'
    );
  });
});
