const alphabetSmall = "abcdefghijklmnopqrstuvwxyz";
const alphabetCapital = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const numbers = "0123456789";

export const randomNumberInRange = (
  min: number,
  max: number,
): Promise<number> => {
  return new Promise((resolve, reject) => {
    try {
      if (min === max) resolve(min);

      const RANGE = max - min;
      const BYTES_NEEDED = Math.ceil(Math.log2(RANGE) / 8);
      const MAX_RANGE = Math.pow(Math.pow(2, 8), BYTES_NEEDED);
      const EXTENDED_RANGE = Math.floor(MAX_RANGE / RANGE) * RANGE;

      let randomBytes = new Uint8Array(BYTES_NEEDED);

      let randomInteger = EXTENDED_RANGE;
      while (randomInteger >= EXTENDED_RANGE) {
        randomBytes = window.crypto.getRandomValues(randomBytes);

        randomInteger = 0;
        for (let i = 0; i < BYTES_NEEDED; i++) {
          randomInteger <<= 8;
          randomInteger += randomBytes[i];
        }

        if (randomInteger < EXTENDED_RANGE) {
          randomInteger %= RANGE;

          resolve(min + randomInteger);
        }
      }

      resolve(randomInteger);
    } catch (error) {
      reject(error);
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

      const randomBytes = window.crypto.getRandomValues(new Uint8Array(len));

      for (let i = 0; i < len; i++) {
        outputString += chars[randomBytes[i] % chars.length];
      }

      resolve(outputString);
    } catch (error) {
      reject(error);
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
  let x = 0;
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
