const alphabetSmall = "abcdefghijklmnopqrstuvwxyz";
const alphabetCapital = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const numbers = "0123456789";

export const randomNumberInRange = (
  min: number,
  max: number,
): Promise<number> => {
  return new Promise((resolve, reject) => {
    try {
      if (min === max) {
        resolve(min);
        return;
      }
      if (max < min) {
        throw new RangeError("randomNumberInRange: max must be >= min");
      }

      // Use BigInt so ranges up to Number.MAX_SAFE_INTEGER (2^53) sample
      // correctly. The previous implementation accumulated bytes with a
      // signed 32-bit `<<= 8`, which overflowed (and went negative) for any
      // range needing more than 4 bytes — e.g. the decoy chunkEndIndex range.
      const range = BigInt(max) - BigInt(min); // > 0
      const bytesNeeded = Math.ceil(range.toString(2).length / 8);
      const maxRange = 1n << BigInt(bytesNeeded * 8); // 2^(8 * bytesNeeded)
      // Largest multiple of `range` that fits in maxRange: reject above it to
      // avoid modulo bias.
      const limit = (maxRange / range) * range;

      const randomBytes = new Uint8Array(bytesNeeded);
      let value = limit; // force at least one draw
      while (value >= limit) {
        window.crypto.getRandomValues(randomBytes);
        value = 0n;
        for (let i = 0; i < bytesNeeded; i++) {
          value = (value << 8n) + BigInt(randomBytes[i]);
        }
      }

      resolve(min + Number(value % range));
    } catch (error) {
      reject(error instanceof Error ? error : new Error(String(error)));
    }
  });
};

export const randomBytesToString = (
  len: number,
  withAlphabetSmall = true,
  withAlphabetCapital = true,
  withNumbers = true,
): Promise<string> => {
  return new Promise((resolve, reject) => {
    try {
      let chars = "";
      if (withAlphabetSmall) chars += alphabetSmall;
      if (withAlphabetCapital) chars += alphabetCapital;
      if (withNumbers) chars += numbers;

      let outputString = "";

      // Use rejection sampling to avoid modular bias
      for (let i = 0; i < len; i++) {
        outputString += chars[uniformInt(0, chars.length)];
      }

      resolve(outputString);
    } catch (error) {
      reject(error instanceof Error ? error : new Error(String(error)));
    }
  });
};

export const generateRandomRoomUrl = async (
  lenMin: number,
  lenMax?: number,
  withAlphabetSmall = true,
  withAlphabetCapital = true,
  withNumbers = true,
): Promise<string> => {
  lenMax ??= lenMin;
  if (lenMax === 0 && lenMin === lenMax) return "";

  const len =
    lenMax > lenMin ? await randomNumberInRange(lenMin, lenMax) : lenMin;
  const url = await randomBytesToString(
    len,
    withAlphabetSmall,
    withAlphabetCapital,
    withNumbers,
  );

  return url;
};

export function uniformInt(min: number, max: number): number {
  if (!(max > min)) return min;
  const range = max - min; // > 0
  const maxU32 = 0x1_0000_0000; // 2^32
  const limit = Math.floor(maxU32 / range) * range;
  let x: number;
  do {
    x = crypto.getRandomValues(new Uint32Array(1))[0];
  } while (x >= limit);
  return min + (x % range);
}

export function fisherYatesShuffle<T>(arr: T[]): T[] {
  const a = arr.slice();
  for (let i = a.length - 1; i > 0; i--) {
    const j = uniformInt(0, i + 1); // j ∈ [0, i]
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

/**
 * @function
 * Fisher-Yates shuffle of array.
 *
 * @param array: The array to randomly shuffle.
 *
 * @returns Promise<T[]>
 */
// export const fisherYatesShuffle = async <T>(array: T[]): Promise<T[]> => {
//   const n = array.length;
//
//   // If array has <2 items, there is nothing to do
//   if (n < 2) return array;
//
//   const shuffled = [...array];
//
//   for (let i = n - 1; i > 0; i--) {
//     const j = await randomNumberInRange(0, i + 1);
//     const temp = shuffled[i];
//     shuffled[i] = shuffled[j];
//     shuffled[j] = temp;
//   }
//
//   return shuffled;
// };
