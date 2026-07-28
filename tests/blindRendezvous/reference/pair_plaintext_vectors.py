#!/usr/bin/env python3
"""Independent PairPlaintextV1 and PairStepEnvelopeV1 reference vectors.

This script intentionally knows only the normative v1 declaration order and
primitive framing. It does not import or inspect the TypeScript implementation.
"""

from __future__ import annotations

import hashlib
import json
import struct


KINDS = (
    "IDENTITY_HELLO",
    "IDENTITY_ACCEPT",
    "TRANSPORT_OFFER",
    "TRANSPORT_ANSWER",
    "V4_HANDSHAKE",
    "PQ_CONTROL",
    "QUIESCE_PROPOSE",
    "QUIESCE_ACK",
    "HEAL_COMPLETE",
    "PAIR_CHECKPOINT",
)


def fill(value: int, length: int = 32) -> bytes:
    return bytes((value,)) * length


def u8(value: int) -> bytes:
    return struct.pack(">B", value)


def u16(value: int) -> bytes:
    return struct.pack(">H", value)


def u32(value: int) -> bytes:
    return struct.pack(">I", value)


def u64(value: int) -> bytes:
    return struct.pack(">Q", value)


def optional(value: bytes | None) -> bytes:
    return b"\x00" if value is None else b"\x01" + value


def sequence(values: list[bytes]) -> bytes:
    return u16(len(values)) + b"".join(values)


def var_bytes(value: bytes) -> bytes:
    return u32(len(value)) + value


def hash_with_domain(domain: str, *parts: bytes) -> bytes:
    return hashlib.sha256(domain.encode("ascii") + b"".join(parts)).digest()


def stable_identity(ed: int, x: int, cross: int) -> bytes:
    return fill(ed) + fill(x) + fill(cross, 64)


def stable_edge_claim(start: int) -> bytes:
    return (
        u8(1)
        + fill(start)
        + fill(start + 1)
        + fill(start + 2)
        + fill(start + 3)
        + u64(0x0102030405060708)
        + u64(0x1112131415161718)
        + fill(start + 4, 64)
    )


def transport_candidate(
    kind: int,
    *,
    sdp: bytes | None = None,
    adapter_protocol_id: int | None = None,
    local: bytes | None = None,
) -> bytes:
    # Closed union tag, then the selected record's version and kind enum.
    encoded = u8(kind) + u8(1) + u8(kind)
    if kind == 0:
        assert sdp is not None
        return encoded + var_bytes(sdp)
    if kind == 1:
        return encoded
    assert kind == 2 and adapter_protocol_id is not None and local is not None
    return encoded + u16(adapter_protocol_id) + var_bytes(local)


def body(kind: int) -> bytes:
    # PairStepBodyV1 closed-union tag and selected record's repeated kind enum.
    prefix = u8(kind) + u8(kind)
    if kind == 0:
        value = (
            u8(1)
            + u8(0)  # planner
            + stable_identity(0x70, 0x71, 0x72)
            + fill(0x73)
            + optional(None)
            + fill(0x74, 1216)
            + fill(0x75, 64)
        )
    elif kind == 1:
        value = (
            u8(1)
            + stable_identity(0x76, 0x77, 0x78)
            + fill(0x79)
            + optional(None)
            + fill(0x7A, 64)
        )
    elif kind == 2:
        value = (
            u8(1)
            + stable_edge_claim(0x80)
            + sequence([transport_candidate(1)])
        )
    elif kind == 3:
        value = (
            u8(1)
            + stable_edge_claim(0x86)
            + fill(0x8B)
            + transport_candidate(0, sdp=b"v=0\r\ns=p2party\r\n")
        )
    elif kind == 4:
        # Exact ML-KEM-768 HELLO handshake-frame geometry: tag + 2,464 bytes.
        value = var_bytes(b"\x01" + fill(0x8C, 2464))
    elif kind == 5:
        value = fill(0x8D, 65490)
    elif kind == 6:
        value = u8(1) + u64(0x2122232425262728)
    elif kind == 7:
        value = u8(1) + u64(0x3132333435363738)
    elif kind == 8:
        value = u8(1) + u64(0x4142434445464748)
    else:
        assert kind == 9
        value = u8(1) + u64(0x5152535455565758)
    return prefix + value


def slot(kind: int) -> tuple[int, int, bytes | None, list[bytes]]:
    if kind == 0:
        return 0, 0, None, []
    if kind == 1:
        return 1, 0, None, [fill(0x61)]
    if kind == 2:
        return 0, 1, fill(0x42), [fill(0x62)]
    if kind == 3:
        return 1, 1, fill(0x43), [fill(0x63)]
    if kind == 4:
        return 0, 2, fill(0x44), [fill(0x64)]
    if kind == 5:
        return 1, 2, fill(0x45), [fill(0x65)]
    if kind == 6:
        return 0, 3, fill(0x46), []
    if kind == 7:
        return 1, 3, fill(0x47), [fill(0x67)]
    if kind == 8:
        return 0, 4, fill(0x48), [fill(0x68)]
    assert kind == 9
    return 1, 4, fill(0x49), [fill(0x69)]


def pair_plaintext(kind: int, padding: bytes = b"") -> bytes:
    direction, pair_sequence, predecessor, dependencies = slot(kind)
    return (
        u8(1)
        + u8(kind)
        + fill(0x10 + kind)
        + sequence([fill(0x20), fill(0x30)])
        + u8(direction)
        + u64(pair_sequence)
        + optional(predecessor)
        + sequence(dependencies)
        + body(kind)
        + var_bytes(padding)
    )


def small_pair_plaintext(padding: bytes = b"") -> bytes:
    return (
        u8(1)
        + u8(9)
        + fill(0x11)
        + sequence([fill(0x22), fill(0x33)])
        + u8(0)
        + u64(2)
        + optional(fill(0x44))
        + sequence([fill(0x55)])
        + u8(9)
        + u8(9)
        + u8(1)
        + u64(3)
        + var_bytes(padding)
    )


def identity_accept_projection(padding: bytes) -> bytes:
    unsigned_accept = (
        u8(1)
        + stable_identity(0x50, 0x51, 0x52)
        + fill(0x53)
        + optional(None)
    )
    return (
        u8(1)
        + u8(1)
        + fill(0x10)
        + sequence([fill(0x20), fill(0x30)])
        + u8(1)
        + u64(0)
        + optional(None)
        + sequence([fill(0x40)])
        + u8(1)
        + u8(1)
        + unsigned_accept
        + var_bytes(padding)
    )


def pair_outer_prebinding() -> bytes:
    return (
        u8(1)
        + fill(0x60)
        + fill(0x61)
        + u64(0x0102030405060708)
        + u64(0x1112131415161718)
        + u8(2)  # PAIR_CAUSAL
        + fill(0x62)
        + u64(0)
        + optional(None)
        + u8(2)  # PAIR_STEP
        + sequence([])
        + u8(0)
        + fill(0x63)
        + optional(None)
    )


def ancillary_vectors() -> dict[str, object]:
    small = small_pair_plaintext()
    small_padding = bytes(4017 - len(small))
    padded_small = small_pair_plaintext(small_padding)

    carrier = transport_candidate(1)
    pair_routing_tag = fill(0x64)
    semantic_slot = hash_with_domain(
        "p2party/pair-slot/v1", pair_routing_tag
    )
    binding = (
        pair_outer_prebinding() + pair_routing_tag + semantic_slot
    )
    # PairIdentityAcceptV1 is 64 bytes longer than its unsigned projection.
    identity_padding = bytes(2543)
    projection = identity_accept_projection(identity_padding)
    transcript_hash = hash_with_domain(
        "p2party/pair-identity-transcript/v1", binding, projection
    )
    unsigned_claim = (
        u8(1)
        + fill(0xA1)
        + fill(0xA2)
        + fill(0xA3)
        + fill(0xA4)
        + u64(0x0102030405060708)
        + u64(0x1112131415161718)
    )

    return {
        "plaintextTargets": {
            "bootstrapClass0": 2919,
            "establishedClass0": 4017,
            "establishedClass1": 69553,
        },
        "smallPairPlaintext": {
            "hex": small.hex(),
            "sha256": hashlib.sha256(small).hexdigest(),
            "paddingLength": len(small_padding),
            "paddedSha256": hashlib.sha256(padded_small).hexdigest(),
        },
        "operationCarrier": {
            "hex": carrier.hex(),
            "candidateId": hash_with_domain(
                "p2party/transport-offer-candidate/v1", carrier
            ).hex(),
        },
        "pairEdgeId": hash_with_domain(
            "p2party/pair-edge/v1", fill(0x01), fill(0x02), fill(0x03)
        ).hex(),
        "stableEdgeId": hash_with_domain(
            "p2party/stable-edge/v1", fill(0x01), fill(0x04), fill(0x05)
        ).hex(),
        "confirmedPairTranscriptId": hash_with_domain(
            "p2party/confirmed-pair-transcript/v1",
            fill(0x06),
            fill(0x07),
        ).hex(),
        "transportNegotiationTranscriptId": hash_with_domain(
            "p2party/transport-negotiation-transcript/v1",
            fill(0x08),
            fill(0x09),
        ).hex(),
        "stableEdgeClaimSignedMessage": (
            b"p2party/stable-edge-attempt-claim-signature/v1"
            + hashlib.sha256(unsigned_claim).digest()
        ).hex(),
        "identityAcceptProjection": {
            "length": len(projection),
            "sha256": hashlib.sha256(projection).hexdigest(),
            "prefixHex": projection[:96].hex(),
            "suffixHex": projection[-96:].hex(),
            "paddingLength": len(identity_padding),
        },
        "pairSemanticSlot": semantic_slot.hex(),
        "pairAad": {
            "length": len(b"p2party/pair-aad/v1" + binding),
            "sha256": hashlib.sha256(
                b"p2party/pair-aad/v1" + binding
            ).hexdigest(),
        },
        "identityTranscriptHash": transcript_hash.hex(),
        "identitySignedMessage": (
            b"p2party/pair-identity-signature/v1"
            + u8(1)
            + transcript_hash
        ).hex(),
    }


def vector(kind: int) -> dict[str, object]:
    unpadded = pair_plaintext(kind)
    bootstrap = kind in (0, 1)
    operation_class = 0 if bootstrap or len(unpadded) <= 4017 else 1
    target = 2919 if bootstrap else (4017 if operation_class == 0 else 69553)
    padding_length = target - len(unpadded)
    padded = pair_plaintext(kind, bytes(padding_length))
    assert len(padded) == target
    return {
        "kind": KINDS[kind],
        "bootstrap": bootstrap,
        "operationClass": operation_class,
        "unpaddedLength": len(unpadded),
        "unpaddedSha256": hashlib.sha256(unpadded).hexdigest(),
        "unpaddedPrefixHex": unpadded[:96].hex(),
        "unpaddedSuffixHex": unpadded[-96:].hex(),
        "paddingLength": padding_length,
        "paddedSha256": hashlib.sha256(padded).hexdigest(),
    }


def pair_step_envelope(operation_class: int, bootstrap: bool) -> bytes:
    ciphertext_length = (
        2935 if bootstrap else (4033 if operation_class == 0 else 69569)
    )
    encoded = u8(1)
    if bootstrap:
        encoded += (
            fill(0xA0)
            + optional(u8(1) + u8(1) + fill(0xA1, 1120))
            + optional(None)
            + var_bytes(fill(0xA2, ciphertext_length))
        )
    else:
        encoded += (
            fill(0xB0)
            + optional(None)
            + optional(fill(0xB1, 24))
            + var_bytes(fill(0xB2, ciphertext_length))
        )
    return encoded


def envelope_vector(operation_class: int, bootstrap: bool) -> dict[str, object]:
    encoded = pair_step_envelope(operation_class, bootstrap)
    return {
        "operationClass": operation_class,
        "bootstrap": bootstrap,
        "length": len(encoded),
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "prefixHex": encoded[:96].hex(),
        "suffixHex": encoded[-96:].hex(),
    }


print(
    json.dumps(
        {
            "ancillary": ancillary_vectors(),
            "plaintexts": [vector(kind) for kind in range(len(KINDS))],
            "envelopes": [
                envelope_vector(0, True),
                envelope_vector(0, False),
                envelope_vector(1, False),
            ],
        },
        indent=2,
    )
)
