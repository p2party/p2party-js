/**
 * Turns an array of Uint8Arrays into one Uint8Array.
 */
export const concatUint8Arrays = (
  arrays: Uint8Array[],
): Promise<Uint8Array> => {
  return new Promise((resolve) => {
    let offset = 0;
    const result = new Uint8Array(
      arrays.reduce((sum, arr) => sum + arr.length, 0),
    );
    for (const arr of arrays) result.set(arr, offset), (offset += arr.length);

    resolve(result);
  });
};

/**
 * Compares two Uint8Arrays.
 */
export const uint8ArraysAreEqual = (
  array1: Uint8Array,
  array2: Uint8Array,
): Promise<boolean> => {
  return new Promise((resolve) => {
    const arrLen = array1.length;
    if (arrLen !== array2.length) resolve(false);

    for (let i = 0; i < arrLen; i++) {
      if (array1[i] !== array2[i]) resolve(false);
    }

    resolve(true);
  });
};

/**
 * Converts Uint8Array to hex string.
 */
export const uint8ArrayToHex = (array: Uint8Array) => {
  return [...array]
    .map((x) => x.toString(16).toLocaleLowerCase().padStart(2, "0"))
    .join("");
};

/**
 * Converts hex string to Uint8Array.
 */
export const hexToUint8Array = (hexString: string) => {
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

/**
 * Converts a string or a File into a Uint8Array.
 */
export const serializer = (data: string | File): Promise<Uint8Array> => {
  return new Promise((resolve, reject) => {
    if (typeof data === "string") {
      const encoder = new TextEncoder();
      const array = encoder.encode(data);
      resolve(array);
    } else {
      const reader = new FileReader();

      reader.onload = (e: ProgressEvent<FileReader>) => {
        const arrayBuffer = e.target?.result;
        if (arrayBuffer && arrayBuffer instanceof ArrayBuffer) {
          const uint8Array = new Uint8Array(arrayBuffer);
          resolve(uint8Array);
        } else {
          reject(new Error("Failed to read file as ArrayBuffer"));
        }
      };

      reader.onerror = () => {
        reject(new Error("Error reading file"));
      };

      reader.readAsArrayBuffer(data);
    }
  });
};
