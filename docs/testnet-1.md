# P2Party Testnet 1

The public RPC is live. On November 27 a fresh installation of the wallet client verified both chain IDs and read the genesis head at height zero. The published genesis contains 128 valueless units of weight one. One validator orders accepted native post-quantum transfers. You can request a test unit, sign locally and look up the resulting receipt. Chat rooms, peer identities and files use no ledger. [Web release article](https://p2party.com/blog/rooms-after-signaling-v5) · [Native verifier source](https://github.com/p2party/libdemos/tree/ceef24a8bf1f5dee045e72c838ffdbf080d9cd83/ledger)

| Setting                                    | Testnet value                                                         |
| ------------------------------------------ | --------------------------------------------------------------------- |
| JSON-RPC 2.0                               | `https://signaling.p2party.com/rpc`                                   |
| Health                                     | [Validator health endpoint](https://signaling.p2party.com/rpc/health) |
| Numeric provider chain ID                  | `1345474644` (`0x50325054`)                                           |
| Native chain ID signed into every transfer | `0x09a0ffa8e6af6aeb11d26671c6c76648965d60509cc3b7a1a4b454b6ec73c760`  |
| Native signature suites                    | `1` ML-DSA-65; `2` SLH-DSA-SHA2-192s                                  |

## Read the network without a wallet

```sh
curl -fsS -H 'Content-Type: application/json' \
  --data '[{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]},{"jsonrpc":"2.0","id":2,"method":"demos_getHead","params":[]}]' \
  https://signaling.p2party.com/rpc
```

The first reply gives the numeric chain ID. The second gives the full native chain ID and the validator's current height. Compare both IDs with the table before signing. The genesis digest is SHA-256 `38d42d50a5a6d5ceb43fd6f63235e542716b1df5ccff59161c5fd7810aed17c6`. [Public genesis](https://p2party.com/downloads/testnet-1/genesis.json) · [Genesis checksum](https://p2party.com/downloads/testnet-1/genesis.json.sha256)

### Verify the first public transfers

Height 1 granted one existing weight-one unit. At height 2 an ethers client spent it with ML-DSA-65 into a suite-2 commitment. At height 3 a viem client spent the same unit with SLH-DSA-SHA2-192s into a fresh suite-1 commitment. Both clients checked historical balances. Replaying their exact signed bytes returned their existing receipts. The final output retained weight one.

```sh
curl -fsS -H 'Content-Type: application/json' \
  --data '[{"jsonrpc":"2.0","id":2,"method":"demos_getTransferByHeight","params":["0x2"]},{"jsonrpc":"2.0","id":3,"method":"demos_getTransferByHeight","params":["0x3"]}]' \
  https://signaling.p2party.com/rpc |
  jq 'sort_by(.id) | map(.result | {height, id, inputId, outputId})'
```

Compare the height-2 `outputId` with the height-3 `inputId`. Query `demos_getUnit` with the height-3 `outputId` to read its suite and `0x1` weight. The by-height queries identify the transfers even after a later spend.

## Install the wallet client

Use Node 26.13.1 or later in a new local directory. Download the package and checksum, verify the archive, then install that file. The expected wallet SHA-256 is `8f1c5ac9fd9fe2ea4a192c6b541a273d2c168057ad75bafd75f251ac1236700b`. The source archive includes the client implementation, lockfile and tests. [Client source](https://p2party.com/downloads/testnet-1/ledger-client-source.tar.gz) · [Source checksum](https://p2party.com/downloads/testnet-1/ledger-client-source.tar.gz.sha256)

```sh
base=https://p2party.com/downloads/testnet-1
pkg=p2party-ledger-client-0.1.0-testnet.0.tgz
curl -fsSLO "$base/$pkg"
curl -fsSLO "$base/$pkg.sha256"
shasum -a 256 -c "$pkg.sha256"
npm install "./$pkg"
```

## Request one test unit

Save the following as `receive.mjs`. Run `node receive.mjs` once per new wallet directory. It writes the private key and nonce into a new owner-only directory and prints the public receive descriptor. Keep both files private and backed up. A second recipient needs their own freshly generated descriptor.

```js
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { receiveOwner } from "@p2party/ledger-client";
import { nodeSigner } from "@p2party/ledger-client/node";

mkdirSync("wallet", { mode: 0o700 });
const { privateKey } = generateKeyPairSync("ml-dsa-65");
const nonce = randomBytes(32);
writeFileSync(
  "wallet/key.pk8",
  privateKey.export({ type: "pkcs8", format: "der" }),
  { mode: 0o600, flag: "wx" },
);
writeFileSync("wallet/nonce", nonce, { mode: 0o600, flag: "wx" });
console.log(JSON.stringify(receiveOwner(nodeSigner(privateKey), nonce)));
```

For suite 2, generate a `slh-dsa-sha2-192s` key in a fresh directory. Open an issue titled **Testnet unit request** with just the public suite number and the full 64-byte commitment. The operator can transfer one available genesis unit and reply with its output ID. The request and receipt are public. [Request a test unit](https://github.com/p2party/p2party-js/issues/new?title=Testnet%20unit%20request)

## Verify and spend a unit

Use `demos_getUnit` with the returned output ID. Confirm that the response matches your suite and commitment, weight is `0x1`, and `spentHeight` is `null`. Each commitment is single-use. A recipient supplies a fresh descriptor, including its full commitment and suite.

The package exports `createLedgerTransport`, `signTransfer` and `transferIds`. Pin both chain IDs when creating the transport. Signing requires the original private key and nonce. Specify the last acceptable ledger height or use `0n` for no expiry. The wallet signs locally. Submit the resulting hex bytes with `demos_sendRawTransfer` and read `demos_getTransfer` using its returned 64-byte move ID. Check the receipt's input and output IDs and read the new unit with `demos_getUnit`.

```js
import { createLedgerTransport } from "@p2party/ledger-client";

const transport = await createLedgerTransport({
  url: "https://signaling.p2party.com/rpc",
  chainId: "0x09a0ffa8e6af6aeb11d26671c6c76648965d60509cc3b7a1a4b454b6ec73c760",
  rpcChainId: 1345474644,
});
console.log(await transport.request({ method: "demos_getHead", params: [] }));
```

If submission times out, retain the exact signed bytes. Calculate their move ID with `transferIds(wire, chainId).id` and query it, or resubmit those same bytes. Signing again may create a competing spend. The client source includes ethers and viem examples for preparing a spend and checking its receipt. [Download the client source and examples](https://p2party.com/downloads/testnet-1/ledger-client-source.tar.gz)

## What the receipt establishes

A receipt records acceptance in this validator's log. Proof of stake, independent validator agreement, economic finality, public minting and mainnet monetary rules are outside this testnet. The Ethereum-compatible read methods expose the network ID, height and native unit weight for a read handle. The RPC does not execute EVM contracts or accept Ethereum transactions.
