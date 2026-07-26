/**
 * Opt-in diagnostic logging.
 *
 * The library previously called console.log directly in 36 places across the
 * signaling, WebRTC and middleware paths. That is useful while debugging a
 * connection and unacceptable in a dependency: an application embedding this
 * had its console filled with `[roomListenerMiddleware] setRoom: {...}` on
 * every room change, with no way to turn it off.
 *
 * Diagnostics are kept — they are genuinely hard to reconstruct after the fact
 * — but silent unless asked for. Errors and warnings still go out
 * unconditionally through console.error/console.warn; those are for the
 * application, not for us.
 *
 * Enable at runtime:
 *   p2party.setDebugLogging(true)
 *
 * or persistently, before the library loads:
 *   localStorage.setItem("p2party:debug", "1")
 */

let enabled = false;

const readPersistedFlag = (): boolean => {
  try {
    // Wrapped: a non-browser host, or a page whose storage is blocked, must not
    // take the library down over a logging preference.
    return globalThis.localStorage?.getItem("p2party:debug") === "1";
  } catch {
    return false;
  }
};

enabled = readPersistedFlag();

/** Turn diagnostic logging on or off for the rest of the session. */
export const setDebugLogging = (value: boolean): void => {
  enabled = value;
};

export const isDebugLogging = (): boolean => enabled;

/** console.log, but only when diagnostics are switched on. */
export const debugLog = (...args: unknown[]): void => {
  if (enabled) console.log(...args);
};
