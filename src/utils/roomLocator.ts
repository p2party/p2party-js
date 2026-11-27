import { Sha512Stream } from "../db/sha512Stream";
import { uint8ArrayToHex } from "./uint8array";

export const ROOM_LOCATOR_PATTERN = /^[0-9a-f]{128}$/u;

/** Matches the existing server identifier: SHA-512 of the canonical hex text. */
export const deriveRoomLocator = (capabilityHex: string): string => {
  if (!/^[0-9a-f]{64}$/u.test(capabilityHex))
    throw new Error("roomUrl must be 32-byte lowercase hex");
  return uint8ArrayToHex(
    new Sha512Stream().update(new TextEncoder().encode(capabilityHex)).digest(),
  );
};
