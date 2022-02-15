/**
 * Calculates the byte length of a string encoded as UTF8.
 *
 * This is a direct copy of the implemation from bcryptjs.
 * The only thing changes is the appliance of gts linting.
 *
 * @see https://github.com/dcodeIO/bcrypt.js/blob/7e2e93af99df2952253f9cf32db29aefa8f272f7/dist/bcrypt.js#L341
 * @param string The string to measure.
 * @returns The byte length of the string encoded as UTF8.
 */
export function utf8Length(string: string): number {
  let len = 0,
    c = 0;
  for (let i = 0; i < string.length; ++i) {
    c = string.charCodeAt(i);
    if (c < 128) len += 1;
    else if (c < 2048) len += 2;
    else if (
      (c & 0xfc00) === 0xd800 &&
      (string.charCodeAt(i + 1) & 0xfc00) === 0xdc00
    ) {
      ++i;
      len += 4;
    } else len += 3;
  }
  return len;
}
