/** A quick TS implementation for testing the CashAssembly. I might pull this
 * into Libauth later. */

import {
  binsAreEqual,
  flattenBinArray,
  numberToBinUint16BE,
  numberToBinUint32BE,
  sha256,
  range,
  binToHex,
} from '@bitauth/libauth';

/**
 * Instantiate a Leighton‑Micali One‑Time Signature (LM‑OTS) system as specified
 * by RFC 8554.
 *
 * @privateRemarks – For ease of comparison against RFC 8554, this
 * implementation avoids renaming variable or function names for clarity;
 * names are instead clarified via comments.
 */
export const instantiateLmOts = ({
  baseW: w,
  hash,
}: {
  /**
   * Winternitz parameter (A.K.A. `w`); configures base‑w encoding. Larger bases
   * reduce signature size but increase hashing requirements.
   */
  baseW: 1 | 2 | 4 | 8;
  /**
   * The hash function, e.g. `sha256`. */
  hash: typeof sha256.hash;
}) => {
  /**
   * RFC 8554 `n` – The output length of the hash function.
   */
  const n = hash(Uint8Array.of()).length;
  /**
   * RFC 8554 `u` – The number of hash chains needed to express the message
   * in base-{@link w}.
   */
  const u = Math.ceil((8 * n) / w);
  /**
   * RFC 8554 `v` – The number of hash chains needed to express the checksum
   * in base-{@link w}.
   */
  const v = Math.ceil((Math.floor(Math.log2(((1 << w) - 1) * u)) + 1) / w);
  /**
   * RFC 8554 `ls` – The number of bits to left shift when packing the checksum.
   */
  const ls = 16 - v * w;
  /**
   * RFC 8554 `p` – The total number of hash chains.
   */
  const p = u + v;
  /**
   * RFC 8554 `D_PBLC` domain-separator, used when computing the hash of
   * the iterates.
   */
  const D_PBLC = Uint8Array.of(0x80, 0x80);
  /**
   * RFC 8554 `D_MESG` domain-separator, used when computing the hash of
   * the message.
   */
  const D_MESG = Uint8Array.of(0x81, 0x81);
  const u32str = numberToBinUint32BE;
  const u16str = numberToBinUint16BE;

  /**
   *  Coefficient extraction – extracts the `i`-th base-{@link w} digit from an
   * encoded Uint8Array.
   */
  const coef = (
    /**
     * The Uint8Array to interpret as a sequence of {@link w}-bit values.
     */
    S: Uint8Array,
    /**
     * The index of the digit to extract.
     */
    i: number
  ) => {
    if (w === 8) return S[i];
    const byteIdx = Math.floor((i * w) / 8);
    const offset = i % (8 / w);
    const shift = 8 - w * (offset + 1);
    return (S[byteIdx] >> shift) & ((1 << w) - 1);
  };

  const step = (
    data: Uint8Array,
    I: Uint8Array,
    q: number,
    i: number,
    j: number
  ) => hash(flattenBinArray([I, u32str(q), u16str(i), Uint8Array.of(j), data]));

  const checksum = (Q: Uint8Array) => {
    let sum = 0;
    for (const i of range(u)) sum += (1 << w) - 1 - coef(Q, i);
    return (sum << ls) & 0xffff;
  };

  const generatePrivateKey = (seed: Uint8Array, I: Uint8Array, q: number) =>
    range(p).map((i) =>
      hash(
        flattenBinArray([I, u32str(q), u16str(i), Uint8Array.of(0xff), seed])
      )
    );

  const derivePublicKey = (x: Uint8Array[], I: Uint8Array, q: number) => {
    const y = x.map((xi, i) => {
      let tmp = xi;
      for (const j of range((1 << w) - 1)) tmp = step(tmp, I, q, i, j);
      return tmp;
    });
    return hash(flattenBinArray([I, u32str(q), D_PBLC, ...y]));
  };

  const sign = (
    message: Uint8Array,
    x: Uint8Array[],
    I: Uint8Array,
    q: number,
    C: Uint8Array
  ) => {
    if (C.length !== n) throw new Error(`C must be ${n} bytes.`);
    const preImage = flattenBinArray([I, u32str(q), D_MESG, C, message]);
    const Q = hash(preImage);
    const sum = checksum(Q);
    const encodedMessageHash = flattenBinArray([Q, u16str(sum)]);
    const Y = x.map((xi, i) => {
      let tmp = xi;
      const inPart = binToHex(tmp);
      const steps = coef(encodedMessageHash, i);
      for (const j of range(steps)) tmp = step(tmp, I, q, i, j);
      const out = binToHex(tmp);
      return tmp;
    });
    return {
      /**
       * The computed checksum of `Q` (useful for debugging).
       */
      checksum: sum,
      /**
       * The message hash concatenated with the checksum, ready for encoding in
       * the hash chains (useful for debugging).
       */
      encodedMessageHash,
      /**
       * The pre-image of the encoded message (useful for debugging).
       */
      preImage,
      /**
       * The hash of `preImage`.
       */
      Q,
      signature: {
        /**
         * The random value used in this signature.
         */
        C,
        /**
         * The signature elements.
         */
        Y,
      },
    };
  };

  const verify = (
    message: Uint8Array,
    sig: { C: Uint8Array; Y: Uint8Array[] },
    I: Uint8Array,
    q: number,
    K: Uint8Array
  ) => {
    if (sig.C.length !== n) return false;

    const preImage = flattenBinArray([I, u32str(q), D_MESG, sig.C, message]);
    const Q = hash(preImage);
    const sum = checksum(Q);
    const encodedMessageHash = flattenBinArray([Q, u16str(sum)]);

    const z = sig.Y.map((Yi, i) => {
      let tmp = Yi;
      const startingStep = coef(encodedMessageHash, i);
      for (let j = startingStep; j < (1 << w) - 1; j++)
        tmp = step(tmp, I, q, i, j);
      return tmp;
    });

    /**
     * "Key Candidate"
     */
    const Kc = hash(flattenBinArray([I, u32str(q), D_PBLC, ...z]));
    return binsAreEqual(Kc, K);
  };

  return { coef, checksum, generatePrivateKey, derivePublicKey, sign, verify };
};

/**
 * The Leighton‑Micali One‑Time Signature (LM‑OTS) system as specified
 * by RFC 8554 instantiated with the `LMOTS_SHA256_N32_W4` parameter set
 * (SHA-256, w=4).
 */
export const lmOtsSha256n32w4 = instantiateLmOts({
  hash: sha256.hash,
  baseW: 4,
});

/**
 *
 * The Leighton‑Micali One‑Time Signature (LM‑OTS) system as specified
 * by RFC 8554 instantiated with the `LMOTS_SHA256_N32_W8` parameter set
 * (SHA-256, w=8).
 */
export const lmOtsSha256n32w8 = instantiateLmOts({
  hash: sha256.hash,
  baseW: 8,
});
