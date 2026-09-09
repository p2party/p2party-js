/**
 * Identity restore, expressed as effects rather than as calls into the store,
 * the database worker and the signaling API.
 *
 * Restoring a recovery phrase rotates the Ed25519 account key underneath a
 * running mesh, so the order of what happens is the whole of the security
 * argument: transports carrying the outgoing identity are terminal before the
 * incoming one is adopted, and nothing is torn down until a key has actually
 * been derived. Keeping that order here, behind an injectable surface, is what
 * makes it assertable without a socket, a WebRTC stack or IndexedDB.
 */

import {
  generateMnemonic,
  validateMnemonicPhrase,
} from "../cryptography/mnemonic";
import { runTerminalSettlement } from "./terminalSettlement";
import { uint8ArrayToHex } from "./uint8array";

import type { TerminalSettlementStep } from "./terminalSettlement";

/**
 * A recovery phrase that cannot derive an identity: an unknown word, the wrong
 * number of words, or a failed checksum. Typed so a caller can tell a mistyped
 * phrase apart from a storage or transport failure and keep the user in the
 * form instead of showing them a purge.
 */
export class InvalidRecoveryPhraseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InvalidRecoveryPhraseError";
  }
}

/** Raw Ed25519 account key material, owned by the restore that derived it. */
export interface DerivedIdentityKeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

export interface IdentityRestoreEffects {
  /** Stretch the phrase into the Ed25519 identity it encodes (argon2id). */
  readonly deriveIdentity: (
    mnemonic: string,
    password?: string,
  ) => Promise<DerivedIdentityKeyPair>;
  /**
   * Run the identity swap under the same exclusive boundary a purge uses, so
   * no connection attempt, room operation or bootstrap can interleave with it.
   */
  readonly runExclusive: <T>(operation: () => Promise<T>) => Promise<T>;
  readonly disconnectSignaling: TerminalSettlementStep;
  /**
   * Close every authenticated WebRTC transport. Rooms, their messages and the
   * address book are kept: this rotates the account key, it does not purge the
   * account.
   */
  readonly teardownRooms: TerminalSettlementStep;
  /**
   * D2=B: the X25519 identity is cross-signed by the outgoing Ed25519 key, so
   * it must not outlive it. The next bootstrap regenerates and re-cross-signs.
   */
  readonly deleteIdentityX25519: TerminalSettlementStep;
  readonly writeIdentityEd25519: (
    identity: DerivedIdentityKeyPair,
  ) => void | Promise<void>;
  /** Record that this key came from a phrase, so it can be backed up again. */
  readonly recordDerivation: TerminalSettlementStep;
  /** Drop the previous identity's peer id, challenge and signature. */
  readonly resetIdentityState: TerminalSettlementStep;
  readonly adoptIdentity: (publicKey: string, secretKey: string) => void;
}

/** What a caller needs to show the user, and nothing that could identify them further. */
export interface RestoredIdentity {
  publicKey: string;
}

export interface CreateRecoverableIdentityOptions {
  /** Entropy bits: 128 gives a 12-word phrase, 256 a 24-word one. */
  strength?: 128 | 256;
  /**
   * Folded into the derivation as the argon2id salt. It is never stored and
   * never checked, so restoring with a different password silently produces a
   * different identity — the phrase alone is not enough to get back in.
   */
  password?: string;
}

export interface CreatedRecoverableIdentity extends RestoredIdentity {
  /**
   * Shown to the user exactly once. Neither the SDK nor its storage keeps a
   * copy, by design: a phrase at rest is the whole identity at rest.
   */
  mnemonic: string;
}

/**
 * Adopt the identity a recovery phrase encodes, replacing whatever identity is
 * currently in use.
 *
 * The phrase is checked, then derived, before any effect runs, so a mistyped
 * phrase costs the caller nothing. Only then does the exclusive boundary open:
 * signaling is disconnected, every room transport is brought to a terminal
 * state, and the cross-signed X25519 identity is dropped — all three settle
 * even if one of them fails, and a failure there aborts the swap rather than
 * moving the identity out from under a transport that may still be live.
 *
 * The remaining steps are fail-fast in dependency order: the Ed25519 key is
 * persisted first, because the derivation flag binds to whatever key is stored
 * when it is written; the in-memory identity is adopted last, because an
 * identity that could not be persisted must not survive only until a reload.
 *
 * @param effects - The storage, transport and state seams to drive
 * @param mnemonic - The recovery phrase, in any transcription
 * @param password - The optional passphrase the phrase was created with
 * @returns The restored Ed25519 public key, hex-encoded
 */
export const restoreIdentityFromMnemonicWith = async (
  effects: IdentityRestoreEffects,
  mnemonic: string,
  password?: string,
): Promise<RestoredIdentity> => {
  const validation = await validateMnemonicPhrase(mnemonic);
  if (!validation.ok)
    throw new InvalidRecoveryPhraseError(
      validation.reason ?? "The recovery phrase is invalid.",
    );

  const identity = await effects.deriveIdentity(mnemonic, password);
  try {
    return await effects.runExclusive(async () => {
      await runTerminalSettlement(
        "Identity restore could not reach a terminal boundary",
        [
          effects.disconnectSignaling,
          effects.teardownRooms,
          effects.deleteIdentityX25519,
        ],
      );

      await effects.writeIdentityEd25519(identity);
      await effects.recordDerivation();

      const publicKey = uint8ArrayToHex(identity.publicKey);
      const secretKey = uint8ArrayToHex(identity.secretKey);
      await effects.resetIdentityState();
      effects.adoptIdentity(publicKey, secretKey);

      return { publicKey };
    });
  } finally {
    identity.secretKey.fill(0);
  }
};

/**
 * Generate a recovery phrase and adopt the identity it encodes, so the phrase
 * the user writes down is provably the one that restores this account.
 *
 * The phrase is returned once and kept nowhere. A caller that loses it before
 * the user has copied it has lost the only backup.
 *
 * @param effects - The storage, transport and state seams to drive
 * @param options - Entropy bits and an optional passphrase
 * @returns The phrase and the Ed25519 public key it now derives
 */
export const createRecoverableIdentityWith = async (
  effects: IdentityRestoreEffects,
  options?: CreateRecoverableIdentityOptions,
): Promise<CreatedRecoverableIdentity> => {
  const mnemonic = await generateMnemonic(options?.strength ?? 256);
  const { publicKey } = await restoreIdentityFromMnemonicWith(
    effects,
    mnemonic,
    options?.password,
  );

  return { mnemonic, publicKey };
};
