// Incremental SHA-512 (FIPS 180-4) for the database worker.
//
// The worker verifies a received file against the whole-file hash its message
// carries, reading the file once in chunk order. The WASM streaming hash
// (src/cryptography/hashStream.ts) lives on the main thread with the LibCrypto
// module, which the worker does not load, and WebCrypto has no streaming
// digest. This is a plain portable implementation: each 64-bit word is a
// (high, low) pair of 32-bit integers. The round constants and initial state
// are copied from the vendored libsodium
// (libsodium/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c, Krnd and
// sha512_initial_state). tests/db/sha512Stream.test.ts checks the output
// against WebCrypto.

const K = Int32Array.of(
  0x428a2f98,
  0xd728ae22,
  0x71374491,
  0x23ef65cd,
  0xb5c0fbcf,
  0xec4d3b2f,
  0xe9b5dba5,
  0x8189dbbc,
  0x3956c25b,
  0xf348b538,
  0x59f111f1,
  0xb605d019,
  0x923f82a4,
  0xaf194f9b,
  0xab1c5ed5,
  0xda6d8118,
  0xd807aa98,
  0xa3030242,
  0x12835b01,
  0x45706fbe,
  0x243185be,
  0x4ee4b28c,
  0x550c7dc3,
  0xd5ffb4e2,
  0x72be5d74,
  0xf27b896f,
  0x80deb1fe,
  0x3b1696b1,
  0x9bdc06a7,
  0x25c71235,
  0xc19bf174,
  0xcf692694,
  0xe49b69c1,
  0x9ef14ad2,
  0xefbe4786,
  0x384f25e3,
  0x0fc19dc6,
  0x8b8cd5b5,
  0x240ca1cc,
  0x77ac9c65,
  0x2de92c6f,
  0x592b0275,
  0x4a7484aa,
  0x6ea6e483,
  0x5cb0a9dc,
  0xbd41fbd4,
  0x76f988da,
  0x831153b5,
  0x983e5152,
  0xee66dfab,
  0xa831c66d,
  0x2db43210,
  0xb00327c8,
  0x98fb213f,
  0xbf597fc7,
  0xbeef0ee4,
  0xc6e00bf3,
  0x3da88fc2,
  0xd5a79147,
  0x930aa725,
  0x06ca6351,
  0xe003826f,
  0x14292967,
  0x0a0e6e70,
  0x27b70a85,
  0x46d22ffc,
  0x2e1b2138,
  0x5c26c926,
  0x4d2c6dfc,
  0x5ac42aed,
  0x53380d13,
  0x9d95b3df,
  0x650a7354,
  0x8baf63de,
  0x766a0abb,
  0x3c77b2a8,
  0x81c2c92e,
  0x47edaee6,
  0x92722c85,
  0x1482353b,
  0xa2bfe8a1,
  0x4cf10364,
  0xa81a664b,
  0xbc423001,
  0xc24b8b70,
  0xd0f89791,
  0xc76c51a3,
  0x0654be30,
  0xd192e819,
  0xd6ef5218,
  0xd6990624,
  0x5565a910,
  0xf40e3585,
  0x5771202a,
  0x106aa070,
  0x32bbd1b8,
  0x19a4c116,
  0xb8d2d0c8,
  0x1e376c08,
  0x5141ab53,
  0x2748774c,
  0xdf8eeb99,
  0x34b0bcb5,
  0xe19b48a8,
  0x391c0cb3,
  0xc5c95a63,
  0x4ed8aa4a,
  0xe3418acb,
  0x5b9cca4f,
  0x7763e373,
  0x682e6ff3,
  0xd6b2b8a3,
  0x748f82ee,
  0x5defb2fc,
  0x78a5636f,
  0x43172f60,
  0x84c87814,
  0xa1f0ab72,
  0x8cc70208,
  0x1a6439ec,
  0x90befffa,
  0x23631e28,
  0xa4506ceb,
  0xde82bde9,
  0xbef9a3f7,
  0xb2c67915,
  0xc67178f2,
  0xe372532b,
  0xca273ece,
  0xea26619c,
  0xd186b8c7,
  0x21c0c207,
  0xeada7dd6,
  0xcde0eb1e,
  0xf57d4f7f,
  0xee6ed178,
  0x06f067aa,
  0x72176fba,
  0x0a637dc5,
  0xa2c898a6,
  0x113f9804,
  0xbef90dae,
  0x1b710b35,
  0x131c471b,
  0x28db77f5,
  0x23047d84,
  0x32caab7b,
  0x40c72493,
  0x3c9ebe0a,
  0x15c9bebc,
  0x431d67c4,
  0x9c100d4c,
  0x4cc5d4be,
  0xcb3e42b6,
  0x597f299c,
  0xfc657e2a,
  0x5fcb6fab,
  0x3ad6faec,
  0x6c44198c,
  0x4a475817,
);

const IV = Int32Array.of(
  0x6a09e667,
  0xf3bcc908,
  0xbb67ae85,
  0x84caa73b,
  0x3c6ef372,
  0xfe94f82b,
  0xa54ff53a,
  0x5f1d36f1,
  0x510e527f,
  0xade682d1,
  0x9b05688c,
  0x2b3e6c1f,
  0x1f83d9ab,
  0xfb41bd6b,
  0x5be0cd19,
  0x137e2179,
);

const TWO_32 = 0x1_0000_0000;

export class Sha512Stream {
  private readonly state = Int32Array.from(IV);
  private readonly schedule = new Int32Array(160);
  private readonly block = new Uint8Array(128);
  private buffered = 0;
  private length = 0;
  private finished = false;

  update(data: Uint8Array): this {
    if (this.finished) throw new Error("sha512: update after digest");
    this.length += data.length;
    let offset = 0;
    if (this.buffered > 0) {
      const take = Math.min(128 - this.buffered, data.length);
      this.block.set(data.subarray(0, take), this.buffered);
      this.buffered += take;
      offset = take;
      if (this.buffered < 128) return this;
      this.compress(this.block, 0);
      this.buffered = 0;
    }
    for (; data.length - offset >= 128; offset += 128)
      this.compress(data, offset);
    if (offset < data.length) {
      this.block.set(data.subarray(offset), 0);
      this.buffered = data.length - offset;
    }
    return this;
  }

  digest(): Uint8Array {
    if (this.finished) throw new Error("sha512: digest called twice");
    this.finished = true;
    const block = this.block;
    block[this.buffered++] = 0x80;
    if (this.buffered > 112) {
      block.fill(0, this.buffered);
      this.compress(block, 0);
      this.buffered = 0;
    }
    block.fill(0, this.buffered);
    // The message length in bits, as the low 64 bits of the 128-bit field.
    const bitsHigh = Math.floor(this.length / 0x2000_0000);
    const bitsLow = (this.length % 0x2000_0000) * 8;
    writeWord(block, 120, bitsHigh);
    writeWord(block, 124, bitsLow);
    this.compress(block, 0);
    const out = new Uint8Array(64);
    for (let i = 0; i < 16; i++) writeWord(out, 4 * i, this.state[i]);
    return out;
  }

  private compress(m: Uint8Array, p: number): void {
    const w = this.schedule;
    for (let i = 0; i < 32; i++) {
      const j = p + 4 * i;
      w[i] = (m[j] << 24) | (m[j + 1] << 16) | (m[j + 2] << 8) | m[j + 3];
    }
    for (let i = 32; i < 160; i += 2) {
      // σ0(W[t-15]) = ROTR1 ^ ROTR8 ^ SHR7
      let xh = w[i - 30];
      let xl = w[i - 29];
      const s0h =
        ((xh >>> 1) | (xl << 31)) ^ ((xh >>> 8) | (xl << 24)) ^ (xh >>> 7);
      const s0l =
        ((xl >>> 1) | (xh << 31)) ^
        ((xl >>> 8) | (xh << 24)) ^
        ((xl >>> 7) | (xh << 25));
      // σ1(W[t-2]) = ROTR19 ^ ROTR61 ^ SHR6
      xh = w[i - 4];
      xl = w[i - 3];
      const s1h =
        ((xh >>> 19) | (xl << 13)) ^ ((xl >>> 29) | (xh << 3)) ^ (xh >>> 6);
      const s1l =
        ((xl >>> 19) | (xh << 13)) ^
        ((xh >>> 29) | (xl << 3)) ^
        ((xl >>> 6) | (xh << 26));
      // W[t] = W[t-16] + σ0 + W[t-7] + σ1
      const lo =
        (w[i - 31] >>> 0) + (s0l >>> 0) + (w[i - 13] >>> 0) + (s1l >>> 0);
      w[i] = (w[i - 32] + s0h + w[i - 14] + s1h + ((lo / TWO_32) | 0)) | 0;
      w[i + 1] = lo | 0;
    }

    const s = this.state;
    let ah = s[0],
      al = s[1],
      bh = s[2],
      bl = s[3];
    let ch = s[4],
      cl = s[5],
      dh = s[6],
      dl = s[7];
    let eh = s[8],
      el = s[9],
      fh = s[10],
      fl = s[11];
    let gh = s[12],
      gl = s[13],
      hh = s[14],
      hl = s[15];
    for (let i = 0; i < 160; i += 2) {
      // Σ1(e) = ROTR14 ^ ROTR18 ^ ROTR41
      const bigS1h =
        ((eh >>> 14) | (el << 18)) ^
        ((eh >>> 18) | (el << 14)) ^
        ((el >>> 9) | (eh << 23));
      const bigS1l =
        ((el >>> 14) | (eh << 18)) ^
        ((el >>> 18) | (eh << 14)) ^
        ((eh >>> 9) | (el << 23));
      const choiceH = (eh & fh) ^ (~eh & gh);
      const choiceL = (el & fl) ^ (~el & gl);
      // T1 = h + Σ1(e) + Ch(e, f, g) + K[t] + W[t]
      const t1l =
        (hl >>> 0) +
        (bigS1l >>> 0) +
        (choiceL >>> 0) +
        (K[i + 1] >>> 0) +
        (w[i + 1] >>> 0);
      const t1h =
        (hh + bigS1h + choiceH + K[i] + w[i] + ((t1l / TWO_32) | 0)) | 0;
      // Σ0(a) = ROTR28 ^ ROTR34 ^ ROTR39
      const bigS0h =
        ((ah >>> 28) | (al << 4)) ^
        ((al >>> 2) | (ah << 30)) ^
        ((al >>> 7) | (ah << 25));
      const bigS0l =
        ((al >>> 28) | (ah << 4)) ^
        ((ah >>> 2) | (al << 30)) ^
        ((ah >>> 7) | (al << 25));
      const majorityH = (ah & bh) ^ (ah & ch) ^ (bh & ch);
      const majorityL = (al & bl) ^ (al & cl) ^ (bl & cl);
      // T2 = Σ0(a) + Maj(a, b, c)
      const t2l = (bigS0l >>> 0) + (majorityL >>> 0);
      const t2h = (bigS0h + majorityH + ((t2l / TWO_32) | 0)) | 0;

      hh = gh;
      hl = gl;
      gh = fh;
      gl = fl;
      fh = eh;
      fl = el;
      let lo = (dl >>> 0) + (t1l >>> 0);
      eh = (dh + t1h + ((lo / TWO_32) | 0)) | 0;
      el = lo | 0;
      dh = ch;
      dl = cl;
      ch = bh;
      cl = bl;
      bh = ah;
      bl = al;
      lo = (t1l >>> 0) + (t2l >>> 0);
      ah = (t1h + t2h + ((lo / TWO_32) | 0)) | 0;
      al = lo | 0;
    }

    addWord(s, 0, ah, al);
    addWord(s, 2, bh, bl);
    addWord(s, 4, ch, cl);
    addWord(s, 6, dh, dl);
    addWord(s, 8, eh, el);
    addWord(s, 10, fh, fl);
    addWord(s, 12, gh, gl);
    addWord(s, 14, hh, hl);
  }
}

const addWord = (s: Int32Array, i: number, high: number, low: number): void => {
  const lo = (s[i + 1] >>> 0) + (low >>> 0);
  s[i] = (s[i] + high + ((lo / TWO_32) | 0)) | 0;
  s[i + 1] = lo | 0;
};

const writeWord = (out: Uint8Array, at: number, value: number): void => {
  out[at] = value >>> 24;
  out[at + 1] = value >>> 16;
  out[at + 2] = value >>> 8;
  out[at + 3] = value;
};
