export const uint8ToHex = (array: Uint8Array) => {
  return [...array]
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("")
    .toLowerCase();
};

export const hexToUint8 = (hexString: string) => {
  // remove the leading 0x
  hexString = hexString.replace(/^0x/, "");

  // ensure even number of characters
  if (hexString.length % 2 != 0) hexString = "0" + hexString;

  // check for some non-hex characters
  const bad = hexString.match(/[G-Z\s]/i);
  if (bad) throw new Error(`Found non-hex characters ${bad}`);

  // split the string into pairs of octets
  const pairs = hexString.match(/[\dA-F]{2}/gi);
  if (!pairs) throw new Error("No hex characters in string");

  // convert the octets to integers
  const integers = pairs.map((s) => {
    return parseInt(s, 16);
  });

  return new Uint8Array(integers);
};
