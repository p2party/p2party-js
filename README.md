# p2party-js

<!-- [![codecov][codecov-image]][codecov-url] -->

[![Known Vulnerabilities](https://snyk.io/test/github/p2party/p2party-js/badge.svg?targetFile=package.json)](https://snyk.io/test/github/p2party/p2party-js?targetFile=package.json)
<br>
![NPM Version](https://img.shields.io/npm/v/p2party)
![NPM License](https://img.shields.io/npm/l/p2party)
[![code-style-prettier][code-style-prettier-image]][code-style-prettier-url]
<br>
![NPM Downloads](https://img.shields.io/npm/dw/p2party)

<!-- [![](https://data.jsdelivr.com/v1/package/npm/@deliberative/crypto/badge)](https://www.jsdelivr.com/package/npm/@deliberative/crypto) -->

<!-- [codecov-image]: https://codecov.io/gh/deliberative/crypto/branch/master/graph/badge.svg -->
<!-- [codecov-url]: https://codecov.io/gh/deliberative/crypto -->

[code-style-prettier-image]: https://img.shields.io/badge/code_style-prettier-ff69b4.svg?style=flat-square
[code-style-prettier-url]: https://github.com/prettier/prettier

> Peer-to-peer WebRTC mesh communication with offensive cryptographic encoding.

**p2party** connects peers visiting the same URL into a WebRTC mesh network and enables secure, chunked message exchange over ephemeral data channels. Unlike traditional privacy libraries, `p2party` actively obfuscates traffic using randomized padding and byte-level noise, making message signatures indistinguishable and message intent opaque. Of course it also adds a layer of ChaChaPoly1305 end-to-end encryption.

---

## Disclaimer

The API is not completely stable and the code has not undergone external security audits. Use at your own risk.

## Features

- 📡 Auto-connect peers based on shared URLs
- 🔀 WebRTC mesh topology (no central servers except for signaling and STUN/TURN)
- 🔐 Offensive cryptography: every message can be split in multiple 64KB chunks so the attacker needs to store a lot of useless info
- 🧩 Supports `File` and `string` messages via chunked encoding
- 🧠 Built-in address book, blacklist, and room memory, all stored in the browser's IndexedDB
- 🛠 Easy API and integration with React via custom hooks

---

## Dependencies

This library relies heavily on [libsodium](https://github.com/jedisct1/libsodium) for cryptographic operations, which is a battle-tested project, compiled to WebAssembly for speed.

The library offers mnemonic generation, validation and Ed25519 key pair from mnemonic functionality that was inspired by [bip39](https://github.com/bitcoinjs/bip39) but instead of Blake2b we use Argon2 and instead of SHA256 we use SHA512, both of which can be found in libsodium.

On the js side, the library depends on [Redux](https://githun.com/redux) for state management,

## Install

```bash
npm install p2party
```

## Usage

The official website [p2party.com](https://p2party.com), which is an SPA written in React, consumes the library with a hook in the following way:

```tsx
import p2party from "p2party";

import { useState } from "react";
import { useNavigate } from "react-router";
import { useSelector } from "react-redux";

import type { Message } from "p2party";

export interface MessageWithData extends Message {
  data: string | File;
}

export const useRoom = () => {
  const navigate = useNavigate();

  const [roomIndex, setRoomIndex] = useState(-1);
  const keyPair = useSelector(p2party.keyPairSelector);
  const rooms = useSelector(p2party.roomSelector);
  const signalingServerConnection = useSelector(
    p2party.signalingServerSelector,
  );

  const goToRandomRoom = async (replace = false) => {
    const random = await p2party.generateRandomRoomUrl();
    navigate("/rooms/" + random, { replace });
  };

  const openChannel = async (name: string) => {
    if (roomIndex === -1) throw new Error("No room was selected");

    await p2party.openChannel(
      rooms[roomIndex].id,
      name,
      rooms[roomIndex].peers,
    );
  };

  const sendMessage = (message: string | File, channel: string) => {
    if (roomIndex === -1) throw new Error("No room was selected");

    p2party.sendMessage(
      message,
      channel,
      rooms[roomIndex].id,
      percentageFilledChunk / 100,
      chunks,
    );
  };

  return {
    keyPair,
    peerId: keyPair.peerId,
    signalingServerURL: signalingServerConnection.serverUrl,
    signalingServerConnectionState: signalingServerConnection,
    peers: roomIndex > -1 ? rooms[roomIndex].peers : [],
    channels: roomIndex > -1 ? rooms[roomIndex].channels : [],
    messages: roomIndex > -1 ? rooms[roomIndex].messages : [],
    goToRandomRoom,
    connect: p2party.connect,
    connectToSignalingServer: p2party.connectToSignalingServer,
    disconnect: p2party.disconnectFromRoom,
    disconnectFromSignalingServer: p2party.disconnectFromSignalingServer,
    disconnectFromRoom: p2party.disconnectFromRoom,
    disconnectFromAllRooms: p2party.disconnectFromAllRooms,
    disconnectFromPeer: p2party.disconnectFromPeer,
    openChannel,
    selectChannel: setSelectedChannel,
    sendMessage,
    readMessage: p2party.readMessage,
    cancelMessage: p2party.cancelMessage,
    deleteMessage: p2party.deleteMessage,
    purge: p2party.purge,
    purgeRoom: p2party.purgeRoom,
    purgeIdentity: p2party.purgeIdentity,
  };
};
```

For a complete reference of the API you can check the library output file [index.ts](src/index.ts).

The most important functions with their types, which can be called as p2party.fn are:

```typescript

/**
 * Connects peer to a room.
 * A room URL is 64 chars long. We use the sha256 of the sha512 of random data.
 */
const connect = (
  roomUrl: string,
  signalingServerUrl = "wss://signaling.p2party.com/ws",
  rtcConfig: RTCConfiguration = {
    iceServers: [
      {
        urls: [
          "stun:stun.p2party.com:3478",
        ],
      },
    ],
    iceTransportPolicy: "all",
  },
) => void;

const connectToSignalingServer = (
  roomUrl: string,
  signalingServerUrl = "wss://signaling.p2party.com/ws",
) => void;

/**
 * If no toChannel then broadcast the message everywhere to everyone.
 * If toChannel then broadcast to all peers with that channel.
 */
const sendMessage = (
  data: string | File,
  toChannel: string,
  roomId: string,
  percentageFilledChunk = 0.9,
  minChunks = 3,
  chunkSize = CHUNK_LEN,
  metadataSchemaVersion = 1,
) => void;

const readMessage = async (
  merkleRootHex?: string,
  hashHex?: string,
) => Promise<{
  message: string | Blob;
  percentage: number;
  size: number;
  filename: string;
  mimeType: MimeType;
  extension: FileExtension;
  category: string;
}>;

const cancelMessage = async (
  channelLabel: string,
  merkleRoot?: string | Uint8Array,
  hash?: string | Uint8Array,
) => void;

```

To load all the past room data you call

```typescript
const rooms = await p2party.getAllExistingRooms();
```

To load the contents of a private message you can do the following from the react hook:

```tsx
// {{ message }} comes from const { messages } = useRoom();
const MessageItem: FC<MessageItemProps> = ({ message }) => {
  const [state, setState] = useState<{
    msg: string;
    msgSize: number;
    msgFilename: string;
    msgCategory: string;
    msgPercentage: number;
    msgLoadingText: string;
    msgExtension: FileExtension;
  }>({
    msg: "",
    msgSize: 0,
    msgFilename: "",
    msgCategory: p2party.MessageCategory.Text,
    msgLoadingText: "",
    msgPercentage: 0,
    msgExtension: "",
  });

  useEffect(() => {
    const controller = new AbortController();

    const setMessage = async () => {
      const m = await readMessage(message.merkleRootHex, message.sha512Hex);

      if (
        message.fromPeerId === peerId &&
        message.totalChunks > 0 &&
        message.chunksCreated < message.totalChunks
      ) {
        setState((prevState) => ({
          ...prevState,
          msg:
            typeof m.message === "string"
              ? m.message
              : m.message
                ? URL.createObjectURL(m.message)
                : "",
          msgLoadingText:
            "Split " +
            message.chunksCreated +
            " chunks of " +
            message.totalChunks,
          msgFilename: m.filename,
          msgCategory: m.category,
          msgExtension: m.extension,
          msgPercentage: Math.floor(
            (message.chunksCreated / message.totalChunks) * 100,
          ),
        }));
      } else {
        if (m.percentage === 100) {
          setState((prevState) => ({
            ...prevState,
            msg:
              typeof m.message === "string"
                ? m.message
                : m.message
                  ? URL.createObjectURL(m.message)
                  : "",
            msgSize: m.size,
            msgLoadingText: "",
            msgFilename: m.filename,
            msgCategory: m.category,
            msgExtension: m.extension,
            msgPercentage: m.percentage, // 100,
          }));
        } else {
          setState((prevState) => ({
            ...prevState,
            msgSize: m.size,
            msgLoadingText:
              "Received " +
              formatBytes(message.savedSize) +
              " of " +
              formatBytes(message.totalSize),
            msgFilename: m.filename,
            msgCategory: m.category,
            msgExtension: m.extension,
            msgPercentage: m.percentage,
          }));
        }
      }
    };

    setMessage();

    return () => {
      controller.abort();

      if (msg.length > 0 && msgCategory !== p2party.MessageCategory.Text)
        URL.revokeObjectURL(msg);
    };
  }, [
    message.merkleRootHex,
    message.sha512Hex,
    message.savedSize,
    message.chunksCreated,
  ]);

  const {
    msg,
    msgSize,
    msgCategory,
    msgPercentage,
    msgExtension,
    msgLoadingText,
    msgFilename,
  } = state;

  return (
    <div>
      {msgCategory === p2party.MessageCategory.Text && url.length === 0 && (
        <Text
          className={`text-left tracking-wide break-words whitespace-pre-line ${message.fromPeerId === peerId ? "font-medium text-black dark:font-semibold dark:text-black" : "font-normal text-white dark:text-white"} text-pretty break-words text-clip hyphens-auto antialiased select-text`}
        >
          {msg as string}
        </Text>
      )}

      {msgCategory === p2party.MessageCategory.Text && url.length > 0 && (
        <Text
          className={`text-left font-semibold tracking-wide text-pretty break-words break-all text-clip hyphens-auto whitespace-normal text-sky-700 underline decoration-sky-400 antialiased select-text dark:font-normal dark:text-sky-400`}
        >
          {msg as string}
        </Text>
      )}

      {msgCategory !== p2party.MessageCategory.Text && (
        <Text
          className={`text-left tracking-wide break-words whitespace-pre-wrap ${message.fromPeerId === peerId ? "font-medium text-black dark:font-semibold dark:text-black" : "font-normal text-white dark:text-white"} antialiased`}
        >
          {msgFilename}
        </Text>
      )}
    </div>
  );
};
```

For privacy features like whitelist, blacklist and room purging we have the following APIs:

```typescript

const purgeIdentity = () => void;
const purgeRoom = (roomUrl: string) => void;
const purge = async () => void;

const deleteMessage = async (
  merkleRoot?: string | Uint8Array,
  hash?: string | Uint8Array,
) => void;

const addPeerToAddressBook = async (
  username: string,
  peerId: string,
  peerPublicKey: string,
) => void;
const onlyAllowConnectionsFromAddressBook = async (
  roomUrl: string,
  onlyAllow: boolean,
) => void;
const deletePeerFromAddressBook = async (
  username?: string,
  peerId?: string,
  peerPublicKey?: string,
) => void;
const blacklistPeer = async (peerId: string, peerPublicKey: string) => void;

```

## Development

If you want to bundle the library yourselves, you need to have [Emscripten](https://github.com/emscripten-core/emscripten)
installed on your machine in order to compile the C code into WebAssembly.
We have the `-s SINGLE_FILE=1` option for the `emcc` compiler, which converts the `wasm` file to a `base64` string
that will be compiled by the glue js code into a WebAssembly module. This was done for the purpose of interoperability
and modularity.

Clone the repo, download the libsodium submodule and install packages:

```
git clone https://github.com/p2party/p2party-js.git
cd p2party-js
git submodule init
git submodule update
npm i
```

Once you have all the dependencies installed, you can run

```
npm run dist
```

and [Rollup](https://github.com/rollup/rollup) will generate the UMD, ESM and CJS bundles.

## License

The source code is licensed under the terms of the Affero General Public License version 3.0 (see [LICENSE](LICENSE)).

## Copyright

Copyright (C) 2025 Deliberative Technologies P.C.
