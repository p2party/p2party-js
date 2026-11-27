# Volunteer forwarding and per-relay payments on loopback

Alice sends one application message to Carol through a volunteer browser, Bob. Alice and Carol use the released P2Party 0.15.1 store-free session API with the protocol-v4 hybrid ML-KEM-768 handshake. Three separate Chromium contexts hold their own temporary identity keys. Two WebRTC DataChannels carry the application traffic, Alice to Bob and Bob to Carol.

Bob’s browser starts with forwarding disabled. Clicking **Enable forwarding** grants up to two records or two seconds. Clicking **Stop forwarding** ends the grant immediately. The forwarding function accepts one fixed-size, versioned P2Party record and has one preconnected outgoing channel. It drops unsupported input or a busy channel synchronously. It keeps no work queue. A record already handed to WebRTC can finish in transit.

## Run the single-relay check

The driver needs Node 26.13.1, Playwright with Chromium installed, and the published SDK package files. A checkout of the [website source](https://github.com/p2party/p2party.com) supplies the tested Playwright dependency and vendored SDK archive. Run `npm ci` and `npx playwright install chromium` in that checkout first. From this SDK repository, run

```sh
P2PARTY_RELAY_DEPS=/absolute/path/to/p2party.com \
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

The local driver supplies pinned endpoint identities, random channel bindings and handshake transport. Real users would need authenticated endpoint discovery and signaling. Bob can observe the adjacent peers, timing, record count and encrypted headers. A volunteer can decline or drop delivery. This experiment measures neither anonymity nor wide-area availability. This single-relay check runs entirely in Chromium and Node. The released SDK supplies its authenticated session and encryption.

## Choose a paid route

The payer chooses an ordered list of two or three volunteers from B, D and E and a maximum total in whole test P2PARTY. The fixture charges one existing unit per selected relay after a signed delivery acknowledgment. For example, `--via=D,B --max=2` requests A → D → B → C for two units. `--via=B,E,D --max=3` requests four WebRTC links and three payments. Duplicate volunteers and a budget below the sum of the quotes fail before a wallet or ledger is opened.

Use the SDK branch `research/multi-relay-payout-local` and server branch `research/certified-dag-ordering` for these research drivers. Install the browser dependencies above. Install the signaling server dependencies with `bun install --frozen-lockfile` and build its wallet client with `npm ci --prefix clients/evm` and `npm run build --prefix clients/evm` from the server repository. Build the native verifier from the libdemos research branch `feat/ledger-sparse-state` with `cmake -S ledger -B build/ledger` and `cmake --build build/ledger --target demos-ledger-verify`. Put Node 26.13.1 and Bun on PATH. Start a disposable PostgreSQL server as described in the server's testing instructions. [Server PostgreSQL setup](https://github.com/p2party/p2party-server#testing-against-postgresql) · [Native verifier build](https://github.com/p2party/libdemos/tree/master/ledger)

```sh
export P2PARTY_RELAY_DEPS=/absolute/path/to/p2party.com
export P2PARTY_RELAY_SERVER=/absolute/path/to/p2party-server
export P2PARTY_TEST_LEDGER_VERIFIER=/absolute/path/to/libdemos/build/ledger/demos-ledger-verify
export P2PARTY_TEST_POSTGRES_URL=postgresql://test@127.0.0.1:55434/postgres
node docs/e2e/volunteer-relay/paid-route.mjs --via=D,B --max=2
```

To choose and authorize a purchase in a visible local Chromium window, use the same environment and run

```sh
node docs/e2e/volunteer-relay/paid-route.mjs --interactive
```

Select two or three distinct volunteers in forwarding order and set the maximum total. **Review signed quotes** shows the verified ML-DSA-65 offers, price, deadline, native input and fresh receive commitment for every relay. **Approve purchase** authorizes that exact order. **Cancel purchase** ends the trial with zero forwarded records and zero payments. Each confirmed credit on the results screen includes the forwarding signature, encrypted record digest, native transaction and output ID. Click **Close test wallet** to finish. The payer page runs in a local browser context and the driver fulfills its HTML and cat icon from memory without listening on a public port.

For a repeatable mobile-width UI check, run `node docs/e2e/volunteer-relay/paid-route.mjs --test-ui` and `node docs/e2e/volunteer-relay/paid-route.mjs --test-ui-cancel`. The first selects B → E → D with a four-unit ceiling and pays three units. The second selects the same terms, cancels before forwarding and verifies the chain is still at genesis.

The CLI driver prints the accepted quotes to stderr before forwarding. The final JSON on stdout lists each relay, reward, native transaction ID, output ID, suite and receive commitment. It creates a random local chain with one valueless input for each chosen relay, runs the server's actual RPC and PostgreSQL ledger with native C verification, and drops its own database on exit. The test harness holds the wallet and quote keys. On a deployed network, each operator would need to generate and protect their own keys and authenticate their quote key to users.

### What the payer verifies

Each provider signs a domain-separated SHA-512 commitment to the whole ordered request and its hop index using a separately pinned ML-DSA-65 key. The request binds the chain and genesis, request nonce, both endpoint identities, recipient receipt key, content and challenge hashes, time and ledger height limits, budget and byte allowance. Each hop binds its browser identity, browser witness key and provider quote key, distinct funding input, and one unit payable to a fresh native receive commitment. The wallet derives the blinded ownership commitment through the existing native `receiveOwner` scheme and the verifier checks the input opening and transfer signature.

Each volunteer’s button grants one 65,559-byte application record for up to two seconds and can be stopped. The 1,024-byte encrypted plaintext contains a 64-byte route ID, a fresh 32-byte challenge and 928 application bytes. The sender computes a domain-separated SHA-512 digest over the exact encrypted record handed to WebRTC. Each selected volunteer signs the route ID, its assigned hop index and that record digest with its pinned browser Ed25519 witness key after its outgoing DataChannel accepts the record. The recipient signs the route ID, recovered challenge, SHA-512 commitment to all 928 application bytes and the digest of the exact encrypted record it successfully opened. The payer compares its own encrypted record digest with each signed witness and the recipient acknowledgment, and verifies all provider quotes before preparing any transfer. The browser observations use classical Ed25519 authentication. The provider quotes and native spends use post-quantum signatures.

The payer durably stores every exact signed transfer in one SQLite transaction before submitting the first one. Separate native inputs and fresh output commitments keep one relay's reward distinct from another's. Each transfer binds the chain, selected input, weight, output suite/commitment and expiry height. Retrying after a lost response or restarting between payments reuses the same signed bytes. The ledger settles each leg independently. A payer going offline can leave partial settlement, and a remaining transfer can expire during the interruption.

### Local outcomes on November 27, 2026

| Requested route | Charged | Ledger height after recovery and repeated submissions |
| --- | --- | --- |
| A → D → B → C | D and B received 1 each | 2 |
| A → B → E → D → C | B, E and D received 1 each | 3 |

Chromium 159.0.8154.6 recovered the complete plaintext on both successful routes. The negative checks include changed payout commitments, route reordering, a wrong chain, missing quotes, missing, swapped or duplicated forwarding witnesses, witnesses replayed against a different order or ciphertext, a stopped hop, a downstream volunteer declining after its upstream neighbor forwarded, expired authorization and an invalid delivery acknowledgment. The declined route consumed the upstream allowance and left the ledger at height zero.

The recipient acknowledges possession of the challenge and content under its pinned key. Every selected witness attests to forwarding the same ciphertext at its assigned position. The driver also observes the selected WebRTC links independently on this machine. Colluding witnesses and endpoints can fabricate the off-chain record, and a payer can withhold a transfer after service. Distinct keys do not establish distinct operators, physical links or networks. The on-chain record contains an ordinary transfer without the route, content or receipt, and timing and payment correlations may still reveal associations. Operator-controlled wallets, directory enrollment, conditional multi-party settlement, independent path evidence and public-network measurements remain open.
