import { MAX_COVER_LANES } from "../roomPolicy";

/**
 * The scheduler may overlap four policy-maximal cycle generations while close
 * events drain. Keep the receiver at that same derived geometry even when an
 * authenticated peer opens lanes outside the agreed schedule.
 */
export const MAX_COVER_CHANNELS_PER_EDGE = MAX_COVER_LANES * 4;

export const registerCoverChannel = <T>(
  coverChannels: Set<T>,
  channel: T,
): void => {
  if (
    !coverChannels.has(channel) &&
    coverChannels.size >= MAX_COVER_CHANNELS_PER_EDGE
  )
    throw new Error("Too many cover DataChannels on one peer edge");
  coverChannels.add(channel);
};

export interface CloseObservableChannel extends EventTarget {
  readonly readyState: string;
}

/**
 * Remove exactly one concrete lane from both registries. Labels repeat every
 * cover cycle, so label-based removal can evict a replacement and leak the
 * channel that actually closed.
 */
export const unregisterCoverChannel = <T>(
  coverChannels: Set<T> | undefined,
  openChannels: T[],
  channel: T,
): void => {
  coverChannels?.delete(channel);
  for (let index = openChannels.length - 1; index >= 0; index--)
    if (openChannels[index] === channel) openChannels.splice(index, 1);
};

/**
 * Register the lane and its exact close cleanup as one synchronous operation,
 * before callers perform any await. Returns the idempotent cleanup closure for
 * parse failures and higher-level teardown.
 */
export const registerCoverChannelUntilClose = <
  T extends CloseObservableChannel,
>(
  coverChannels: Set<T>,
  channel: T,
  openChannels: T[] = [],
): (() => void) => {
  registerCoverChannel(coverChannels, channel);
  const cleanup = (): void => {
    unregisterCoverChannel(coverChannels, openChannels, channel);
  };
  channel.addEventListener("close", cleanup);
  if (channel.readyState === "closed") {
    cleanup();
    throw new Error("Cover DataChannel closed during setup");
  }
  return cleanup;
};
