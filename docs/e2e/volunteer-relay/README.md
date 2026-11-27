# Volunteer forwarding on loopback

Alice sends one application message to Carol through a volunteer browser, Bob. Alice and Carol use the released P2Party 0.15.1 store-free session API with the protocol-v4 hybrid ML-KEM-768 handshake. Three separate Chromium contexts hold their own temporary identity keys. Two WebRTC DataChannels carry the application traffic, Alice to Bob and Bob to Carol.

Bob’s browser starts with forwarding disabled. Clicking **Enable forwarding** grants up to two records or two seconds. Clicking **Stop forwarding** ends the grant immediately. The forwarding function accepts one fixed-size, versioned P2Party record and has one preconnected outgoing channel. It drops unsupported input or a busy channel synchronously. It keeps no work queue. A record already handed to WebRTC can finish in transit.

## Run

The driver needs Node 26.13.1, Playwright with Chromium installed, and the published SDK package files. A checkout of the [website source](https://github.com/p2party/p2party.com-source) supplies the tested Playwright dependency and vendored SDK archive. Run `npm ci` and `npx playwright install chromium` in that checkout first. From this SDK repository, run

```sh
P2PARTY_RELAY_DEPS=/absolute/path/to/p2party.com-source \
  node docs/e2e/volunteer-relay/run.mjs
```

The driver serves a local page and its release-matched WASM from memory. It allows only IPv4 loopback UDP host candidates in the SDP it passes between peers and checks the browser-selected local and remote candidates at both ends. The Chromium contexts receive a test microphone permission to enumerate loopback interfaces. Chromium uses fake devices and the fixture never opens a media stream. The driver rejects external HTTP and WebSocket requests. No signaling service, TURN service or public room is used.

## Observed result

On November 27, 2026, Chromium 159.0.8154.6 delivered 1,024 random plaintext bytes exactly across both loopback hops. The released SDK produced a 65,490-byte encrypted frame. A 64-byte authenticated Merkle root and five fixture framing bytes brought the forwarded record to 65,559 bytes.

| Check | Result |
| --- | --- |
| Disabled volunteer | Refused the valid record |
| Text, short record and unknown version while enabled | Refused all three, spending zero quota |
| Endpoint authentication | Carol recovered every byte. Bob opened a control message in his own separate session with Alice and failed to decrypt Alice’s message to Carol |
| Corrupted ciphertext | Carol rejected a fresh message with its last ciphertext byte changed |
| Byte allowance | Bob forwarded two records totaling 131,118 bytes and refused the next record |
| Withdrawal and time limit | A fresh grant refused the next record after Stop. A separate idle grant expired after two seconds and refused the next record |
| Network scope | Both selected links used UDP on 127.0.0.1; zero external page requests |

The local driver supplies pinned endpoint identities, random channel bindings and handshake transport. Real users would need authenticated endpoint discovery and signaling. Bob can observe the adjacent peers, timing, record count and encrypted headers. A volunteer can decline or drop delivery. This experiment measures neither anonymity nor wide-area availability. It creates no wallet, proof of useful work, payment, peer discovery or automatic forwarding. No relay code is added to the shipped package.
