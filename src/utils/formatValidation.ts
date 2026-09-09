// These are format checks for existing protocol fields, not authentication.
const UUID_ANY =
  /^(?:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|00000000-0000-0000-0000-000000000000|ffffffff-ffff-ffff-ffff-ffffffffffff)$/i;
const UUID_V4 =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HEXADECIMAL = /^(?:0[xh])?[0-9a-f]+$/i;

/** Existing generic fields accept UUID versions 1–8, nil and max. */
export const isUUID = (value: unknown, version?: 4): boolean =>
  typeof value === "string" &&
  value.length === 36 &&
  (version === 4 ? UUID_V4 : UUID_ANY).test(value);

/** Preserve optional 0x/0h prefixes; callers enforce protocol field lengths. */
export const isHexadecimal = (value: unknown): boolean => {
  if (typeof value !== "string") return false;
  // JavaScript's `$` also matches before a final line terminator. Require the
  // complete match so an otherwise valid field cannot carry trailing data.
  return HEXADECIMAL.exec(value)?.[0] === value;
};
