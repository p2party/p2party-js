type PinZeroizer = (pin: Uint8Array) => void;

const defaultZeroizer: PinZeroizer = (pin) => {
  pin.fill(0);
};

const assertRoomContext = (roomContext: string): void => {
  if (typeof roomContext !== "string" || roomContext.length === 0)
    throw new Error("roomPinVault: room context must be a non-empty string");
};

const assertPin = (pin: Uint8Array): void => {
  if (!(pin instanceof Uint8Array))
    throw new Error("roomPinVault: PIN must be a Uint8Array");
  if (pin.length === 0) throw new Error("roomPinVault: PIN must not be empty");
};

/**
 * In-memory-only PIN owner. The production instance below is module-scoped;
 * this class is exported only so its copy/zeroization contract can be tested
 * without exposing the production map.
 *
 * No Redux, database, localStorage, logging, or serialization path touches
 * these bytes. Callers receive copies and should wipe them after handshake use.
 *
 * @internal
 */
export class TransientRoomPinVault {
  readonly #pins = new Map<string, Uint8Array>();
  readonly #zeroize: PinZeroizer;

  constructor(zeroize: PinZeroizer = defaultZeroizer) {
    this.#zeroize = zeroize;
  }

  put(roomContext: string, pin: Uint8Array): void {
    assertRoomContext(roomContext);
    assertPin(pin);

    const replacement = Uint8Array.from(pin);
    const previous = this.#pins.get(roomContext);
    if (previous) this.#zeroize(previous);
    this.#pins.set(roomContext, replacement);
  }

  get(roomContext: string): Uint8Array | undefined {
    assertRoomContext(roomContext);
    const pin = this.#pins.get(roomContext);
    return pin ? Uint8Array.from(pin) : undefined;
  }

  has(roomContext: string): boolean {
    assertRoomContext(roomContext);
    return this.#pins.has(roomContext);
  }

  delete(roomContext: string): boolean {
    assertRoomContext(roomContext);
    const pin = this.#pins.get(roomContext);
    if (!pin) return false;
    this.#zeroize(pin);
    return this.#pins.delete(roomContext);
  }

  clear(): void {
    for (const pin of this.#pins.values()) this.#zeroize(pin);
    this.#pins.clear();
  }
}

const roomPinVault = new TransientRoomPinVault();

export const putRoomPin = (roomContext: string, pin: Uint8Array): void => {
  roomPinVault.put(roomContext, pin);
};

export const getRoomPin = (roomContext: string): Uint8Array | undefined =>
  roomPinVault.get(roomContext);

export const hasRoomPin = (roomContext: string): boolean =>
  roomPinVault.has(roomContext);

export const deleteRoomPin = (roomContext: string): boolean =>
  roomPinVault.delete(roomContext);

export const clearRoomPins = (): void => {
  roomPinVault.clear();
};
