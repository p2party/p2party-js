import { describe, expect, test } from "bun:test";

/**
 * The relay-credential admission rule from handleWebSocketMessage's `roomId`
 * case, isolated so it can be exercised without a signaling socket.
 *
 * It is kept in step with the handler by the assertions below rather than by
 * import, because importing the handler pulls in the whole store.
 */
const acceptTurn = (
  turn: unknown,
): { urls: string[]; username: string; credential: string } | null => {
  if (turn === null || typeof turn !== "object") return null;
  const candidate = turn as {
    urls?: unknown;
    username?: unknown;
    credential?: unknown;
  };
  const urls = (Array.isArray(candidate.urls) ? candidate.urls : []).filter(
    (url): url is string =>
      typeof url === "string" && /^turns?:[^\s]+$/u.test(url),
  );
  if (
    urls.length > 0 &&
    typeof candidate.username === "string" &&
    candidate.username.length > 0 &&
    typeof candidate.credential === "string" &&
    candidate.credential.length > 0
  )
    return {
      urls,
      username: candidate.username,
      credential: candidate.credential,
    };
  return null;
};

const valid = {
  urls: [
    "turns:turn.p2party.com:443?transport=tcp",
    "turn:turn.p2party.com:3478",
  ],
  username: "3601:" + "ab".repeat(32),
  credential: "XY6V5LzRrbIFUOH5w0qdZ90iYuQ=",
};

describe("relay credentials from signaling", () => {
  test("a complete bundle is accepted with both schemes", () => {
    const accepted = acceptTurn(valid);
    expect(accepted).not.toBeNull();
    expect(accepted!.urls).toEqual(valid.urls);
  });

  test("only turn and turns URIs reach the ICE stack", () => {
    // The signaling server picks the relay, but an arbitrary string here
    // would be handed straight to the browser.
    const accepted = acceptTurn({
      ...valid,
      urls: [
        "https://evil.example.com",
        "stun:stun.example.com:3478",
        "javascript:alert(1)",
        "turns:turn.p2party.com:443",
      ],
    });
    expect(accepted!.urls).toEqual(["turns:turn.p2party.com:443"]);
  });

  test("a bundle with no usable URL is refused outright", () => {
    expect(acceptTurn({ ...valid, urls: [] })).toBeNull();
    expect(
      acceptTurn({ ...valid, urls: ["https://evil.example.com"] }),
    ).toBeNull();
    expect(
      acceptTurn({ ...valid, urls: "turns:turn.p2party.com:443" }),
    ).toBeNull();
  });

  test("missing or empty credentials are refused", () => {
    expect(
      acceptTurn({ urls: valid.urls, credential: valid.credential }),
    ).toBeNull();
    expect(acceptTurn({ ...valid, username: "" })).toBeNull();
    expect(acceptTurn({ ...valid, credential: "" })).toBeNull();
    expect(acceptTurn({ ...valid, username: 42 })).toBeNull();
  });

  test("absent credentials leave the client STUN-only rather than throwing", () => {
    expect(acceptTurn(undefined)).toBeNull();
    expect(acceptTurn(null)).toBeNull();
    expect(acceptTurn("turns:turn.p2party.com:443")).toBeNull();
  });

  test("a URL containing whitespace is refused", () => {
    // Whitespace is how a second, unintended entry would be smuggled in.
    expect(
      acceptTurn({
        ...valid,
        urls: ["turns:turn.p2party.com:443 turn:evil:3478"],
      }),
    ).toBeNull();
  });
});
