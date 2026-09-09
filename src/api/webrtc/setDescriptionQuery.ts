import { debugLog } from "../../utils/debug";
import signalingServerApi from "../signalingServerApi";

import { attachDataChannelHandler } from "./dataChannelHandler";
import { runRoomPeerExclusive } from "./negotiationLock";
import { findRoomPeerConnectionIndex } from "./roomPeer";
import {
  discardIceCandidatesForAttempt,
  takePendingIceCandidates,
} from "./pendingIceCandidates";
import {
  decideRemoteTransportChangeResponse,
  detectRemoteTransportChange,
  resetEdgeAuthenticationForNewRemoteTransport,
} from "./remoteTransportChange";
import {
  forgetRetiredRemoteTransport,
  isRetiredRemoteTransport,
  retireRemoteTransport,
} from "./retiredRemoteTransports";
import { awaitPcOperation } from "./settleOnClose";
import { isIdentityInitiator } from "../../utils/identityRole";
import { PROTOCOL_VERSION } from "../../utils/constants";

import { handleConnectToPeer } from "../../handlers/handleConnectToPeer";
import { handleOpenChannel } from "../../handlers/handleOpenChannel";
import { requestPeersAfterEdgeTeardown } from "../../handlers/edgeTeardownFollowUp";
import { setPeer } from "../../reducers/roomSlice";

import type { BaseQueryFn } from "@reduxjs/toolkit/query";
import type { State } from "../../store";
import type {
  RTCSetDescriptionParams,
  IRTCPeerConnection,
  IRTCIceCandidate,
  IRTCDataChannel,
  DisconnectPeerTransport,
} from "./interfaces";
import type { WebSocketMessageDescriptionSend } from "../../utils/interfaces";

export interface RTCSetDescriptionParamsExtension extends RTCSetDescriptionParams {
  peerConnections: IRTCPeerConnection[];
  iceCandidates: IRTCIceCandidate[];
  dataChannels: IRTCDataChannel[];
  /**
   * Tears one room/peer transport down through the same path as a transport
   * failure (disconnectFromPeer). Injected, like the bulk teardown queries
   * do, so this module needs no import of the API that registers it and a
   * test can bind the real query to its own transport registry.
   */
  disconnectPeer: DisconnectPeerTransport;
}

// A predicate rather than inline checks: the PC may close during the awaits
// in the query body, and TypeScript's control-flow narrowing from the early
// `signalingState === "closed"` return would otherwise flag the later re-check
// as unreachable.
const isTransportClosed = (epc: IRTCPeerConnection): boolean =>
  epc.signalingState === "closed" || epc.connectionState === "closed";

const webrtcSetDescriptionQuery: BaseQueryFn<
  RTCSetDescriptionParamsExtension,
  undefined
> = async (
  {
    peerId,
    peerPublicKey,
    roomId,
    description,
    rtcConfig,
    peerConnections,
    iceCandidates,
    dataChannels,
    disconnectPeer,
  },
  api,
) => {
  return runRoomPeerExclusive(roomId, peerId, async () => {
    const { keyPair } = api.getState() as State;

    let connectionIndex = findRoomPeerConnectionIndex(
      peerConnections,
      roomId,
      peerId,
    );

    // A CLOSED transport can never hold a description again, and reusing it
    // drops the frame on the floor: awaitPcOperation abandons every session
    // description operation on a closed PC, and the `signalingState ===
    // "closed"` check below simply returns. Nothing owns the follow-up either
    // — a terminal handshake failure detaches `main`'s close handler on
    // purpose and leaves the closed transport in the registry (C2) — so a peer
    // that corrects a mistyped PIN and re-offers on a FRESH transport stays
    // stranded until an unrelated signaling reconnect happens to rebuild the
    // edge. Retire it here, exactly as the certificate-change "replace" path
    // does, so this description lands on a transport that can hold it.
    if (
      connectionIndex > -1 &&
      isTransportClosed(peerConnections[connectionIndex])
    ) {
      await disconnectPeer({ roomId, peerId });
      connectionIndex = findRoomPeerConnectionIndex(
        peerConnections,
        roomId,
        peerId,
      );
    }

    // An ANSWER produced on a remote transport this side has already retired
    // is refused before anything is built or applied.
    //
    // detectRemoteTransportChange below only guards a transport that ALREADY
    // carries a remote description: on a fresh or replaced RTCPeerConnection
    // the first setRemoteDescription has nothing to compare a fingerprint
    // against, and nothing on the wire correlates an answer with the offer it
    // answers (the SDK cannot add signaling fields without a server change).
    // A queued answer from the peer's retired transport therefore binds our
    // brand-new PC to a certificate that is dead on the far side, and the
    // peer's correct answer that follows is then dropped as stale because the
    // PC is already "stable" — an edge deadlock nothing recovers from, since
    // neither transport ever connects and no failure path re-dials.
    //
    // Only answers: an OFFER is not a reply to anything we hold. Retirement
    // is this side's unilateral decision (a grace-timer teardown while the
    // peer's transport was merely unreachable), so the peer offering on it is
    // the evidence that the decision was premature, and answering rebinds the
    // edge immediately instead of waiting out an ICE failure — measured on
    // the process-freeze harness as a 2 s heal instead of 13 s. Wrongly
    // accepting an offer is recoverable anyway: the transport then HAS a
    // remote description, so the peer's next offer takes the fingerprint-
    // change path above, while a wrongly accepted answer is terminal.
    //
    // Discarding leaves the transport exactly as it was: an unanswered first
    // offer stays unanswered, so its watchdog still fires and re-dials.
    if (
      description.type === "answer" &&
      isRetiredRemoteTransport(roomId, peerId, description.sdp)
    ) {
      console.warn(
        `Ignoring ${description.type} from a retired remote transport of ${peerId} in ${roomId}`,
      );
      discardIceCandidatesForAttempt(
        connectionIndex > -1
          ? peerConnections[connectionIndex].iceCandidates
          : [],
        iceCandidates,
        roomId,
        peerId,
      );
      return { data: undefined };
    }

    // Reassigned exactly once, when a stale authenticated transport is
    // replaced below. discardIceForAttempt reads this binding, so it follows
    // the replacement; the ondatachannel handler is bound per transport.
    let epc =
      connectionIndex > -1
        ? peerConnections[connectionIndex]
        : await handleConnectToPeer(
            {
              peerId,
              peerPublicKey,
              roomId,
              peerConnections,
              rtcConfig,
            },
            api,
          );

    if (
      connectionIndex === -1 ||
      peerConnections[connectionIndex].ondatachannel == undefined
    )
      attachDataChannelHandler(epc, dataChannels, api);

    // Compare the incoming fingerprint against the remote description applied
    // RIGHT NOW, before any rollback/ignore decision below can touch it. A
    // different DTLS certificate means the peer rebuilt its RTCPeerConnection
    // while ours survived (e.g. it tore the edge down during a radio-off
    // freeze shorter than the ICE consent timeout); everything this side
    // authenticated against the old certificate must go once the description
    // is actually applied. A fresh PC has nothing to compare.
    const remoteTransportChanged =
      connectionIndex > -1 &&
      detectRemoteTransportChange(epc.remoteDescription?.sdp, description.sdp);

    const offerCollision =
      description.type === "offer" &&
      (epc.makingOffer || epc.signalingState !== "stable");
    // Polite peer has the lexicographically smaller peerId, EXCEPT that an
    // outstanding offer on a transport that has never had a remote description
    // has nothing to lose, so its owner always yields. Invariant behind that
    // exception: only the identity initiator offers on a fresh transport (the
    // responder creates no channel there, so onnegotiationneeded never fires
    // for it), hence both sides can never be in that state at once. Without
    // it, an impolite initiator that re-dialed while the peer was unreachable
    // (its first offer lost) would ignore the peer's own offer on wake and
    // hold its never-answered PC forever, while the peer's older PC sits in
    // have-local-offer waiting for an answer that never comes.
    const isPolite =
      epc.remoteDescription == null || keyPair.peerId < epc.withPeerId;
    const ignoreOffer = !isPolite && offerCollision;
    epc.ignoreOffer = ignoreOffer;

    const discardIceForAttempt = (): void => {
      discardIceCandidatesForAttempt(
        epc.iceCandidates,
        iceCandidates,
        roomId,
        peerId,
      );
    };

    if (ignoreOffer) {
      discardIceForAttempt();
      return { data: undefined };
    }

    // Every SDP operation below is awaited through awaitPcOperation. A
    // connection that closes underneath an in-flight setLocalDescription /
    // setRemoteDescription aborts it WITHOUT settling its promise and fires no
    // event, so a plain await would hold this room/peer mutex — and, through
    // the socket's strictly serial ingress queue, every later signaling frame
    // on that socket — forever. "closed" abandons the attempt (nothing can be
    // applied to a dead transport, and its own close path owns the follow-up);
    // "timeout" is reported into the operation's existing failure branch.

    // Polite peer must rollback its local description before accepting remote offer
    if (offerCollision && isPolite) {
      try {
        const rolledBack = await awaitPcOperation(
          epc,
          epc.setLocalDescription({ type: "rollback" }),
          { name: `rollback(${roomId}, ${peerId})` },
        );
        if (rolledBack === "closed") {
          discardIceForAttempt();
          return { data: undefined };
        }
        if (rolledBack === "timeout")
          throw new Error(`rollback did not settle for ${peerId}`);
        debugLog(`Polite peer rolled back local description for ${peerId}`);
      } catch (e) {
        console.error(`Failed to rollback for ${peerId}:`, e);
      }
    }

    epc.iceCandidates.push(
      ...takePendingIceCandidates(iceCandidates, roomId, peerId),
    );

    if (findRoomPeerConnectionIndex(peerConnections, roomId, peerId) === -1)
      peerConnections.push(epc);

    if (epc.signalingState === "closed") {
      discardIceForAttempt();
      return { data: undefined };
    }

    if (
      description.type === "answer" &&
      epc.signalingState !== "have-local-offer"
    ) {
      console.warn(
        `Ignoring stale answer from ${peerId} in signaling state ${epc.signalingState}`,
      );
      discardIceForAttempt();
      return { data: undefined };
    }

    // The description is going to be applied. If it binds a new remote DTLS
    // certificate, decide what happens to the transport that carries the old
    // one (see decideRemoteTransportChangeResponse for the full argument):
    //
    // - "reset-in-place": nothing proven against the old certificate has to
    //   be opened on the old SCTP association, so the browser renegotiates
    //   DTLS on this PC and the edge simply re-authenticates on it. Every
    //   channel of the generation it retires — `main` and the per-message
    //   channels, which are gated on the lease being replaced — is closed and
    //   unregistered with it, which is why `dataChannels` is handed over. At
    //   most one such re-bind is granted before the transport must prove an
    //   authentication, so this branch can never loop.
    // - "replace": this transport was authenticated and the peer's new
    //   certificate means our SCTP association is dead on the far side while
    //   still writable here. It is torn down through the transport-failure
    //   path (disconnectFromPeer: PC closed, roster entry and non-failed
    //   handshake status dropped, per-message channels die with it and the
    //   send path's resume-on-replaced-PC logic takes over). An OFFER then
    //   continues on a fresh PC exactly as the no-transport path would; an
    //   ANSWER belonged to the stale PC's own offer and cannot be applied to
    //   any other PC, so it is discarded and the room is re-dialed.
    //
    // The teardown runs INSIDE the room/peer critical section on purpose:
    // disconnectFromPeer is synchronous, never takes this negotiation mutex,
    // and its releaseRoomPeerMutex only forgets the registry key once the
    // mutex is idle (i.e. after this operation itself releases it), so no
    // deadlock is possible, while a concurrent candidate or description for
    // the same edge queues behind the lock and can never observe a
    // half-replaced transport.
    if (remoteTransportChanged) {
      const amInitiator = isIdentityInitiator(
        keyPair.publicKey,
        epc.withPeerPublicKey,
      );
      const response = decideRemoteTransportChangeResponse({
        epc,
        roomId,
        peerId,
        descriptionType: description.type,
        isInitiator: amInitiator,
      });
      if (response === "replace") {
        debugLog(
          `Remote DTLS certificate changed for ${peerId} in ${roomId} on an authenticated transport; replacing it`,
        );
        // We stop believing in the certificate this transport was bound to
        // right here, before the teardown that owns the same retirement can
        // read it off a closed connection: any later description the peer
        // still produces on it (a queued ICE restart it answers after a
        // freeze) must never bind the replacement.
        retireRemoteTransport(roomId, peerId, epc.remoteDescription?.sdp);
        await disconnectPeer({ roomId, peerId });
        if (description.type !== "offer") {
          // The re-dial's roster round re-introduces the peer and
          // connectWithPeer builds our fresh transport; the peer's fresh PC,
          // currently connecting towards our closed one, receives that new
          // offer and restarts ICE on it.
          requestPeersAfterEdgeTeardown(api, roomId);
          return { data: undefined };
        }
        try {
          epc = await handleConnectToPeer(
            { peerId, peerPublicKey, roomId, peerConnections, rtcConfig },
            api,
          );
        } catch (error) {
          // The authenticated edge is already gone and no transport-level
          // event will ever fire for it. Whatever refused the rebuild (an
          // inactive room, the room edge budget, a WASM or identity problem)
          // is reported to the caller as on the no-transport path, but the
          // next roster round must still get a chance to rebuild the edge.
          requestPeersAfterEdgeTeardown(api, roomId);
          throw error;
        }
        attachDataChannelHandler(epc, dataChannels, api);
        if (!peerConnections.includes(epc)) peerConnections.push(epc);
        // The peer proved it is live by offering: put it back on the roster
        // now, ahead of the fresh main's "authenticating" report, so no
        // handshake status ever describes a peer outside the roster.
        api.dispatch(setPeer({ roomId, peerId, peerPublicKey }));
      } else {
        resetEdgeAuthenticationForNewRemoteTransport({
          epc,
          roomId,
          peerId,
          api,
          dataChannels,
          // The deadline it arms rebuilds the edge through this very path if
          // the re-bind never re-authenticates.
          disconnectPeer,
          reason: new Error(
            `Remote DTLS certificate changed (${roomId}, ${peerId})`,
          ),
        });
      }
    }

    {
      try {
        const applied = await awaitPcOperation(
          epc,
          epc.setRemoteDescription(description),
          { name: `setRemoteDescription(${roomId}, ${peerId})` },
        );
        if (applied === "closed") {
          discardIceForAttempt();
          return { data: undefined };
        }
        if (applied === "timeout")
          throw new Error(`setRemoteDescription did not settle for ${peerId}`);
      } catch (e: unknown) {
        // Handle ICE restart mismatch - if we receive an offer with new ICE credentials
        // but didn't request a restart, we need to accept the restart gracefully
        const error = e as { message?: string };
        if (
          description.type === "answer" &&
          error.message?.includes("Called in wrong state")
        ) {
          console.warn(`Ignoring late answer from ${peerId}: ${error.message}`);
          discardIceForAttempt();
          return { data: undefined };
        }

        if (error.message?.includes("ICE restart")) {
          console.warn(
            `ICE restart mismatch with ${peerId}, accepting remote restart`,
          );
          try {
            // Rollback and accept the restart
            if (epc.signalingState !== "stable") {
              const rolledBack = await awaitPcOperation(
                epc,
                epc.setLocalDescription({ type: "rollback" }),
                { name: `restart rollback(${roomId}, ${peerId})` },
              );
              if (rolledBack === "closed") {
                discardIceForAttempt();
                return { data: undefined };
              }
              if (rolledBack === "timeout")
                throw new Error(`rollback did not settle for ${peerId}`, {
                  cause: e,
                });
            }
            const applied = await awaitPcOperation(
              epc,
              epc.setRemoteDescription(description),
              { name: `restart setRemoteDescription(${roomId}, ${peerId})` },
            );
            if (applied === "closed") {
              discardIceForAttempt();
              return { data: undefined };
            }
            if (applied === "timeout")
              throw new Error(
                `setRemoteDescription did not settle for ${peerId}`,
                { cause: e },
              );
          } catch (retryError) {
            console.error(
              `Failed to handle ICE restart for ${peerId}:`,
              retryError,
            );
            discardIceForAttempt();
            return { data: undefined };
          }
        } else {
          console.error(`setRemoteDescription failed for ${peerId}:`, e);
          discardIceForAttempt();
          return { data: undefined };
        }
      }
      // The description was applied: this transport is bound to that remote
      // certificate again, so it is no longer retired. Only an offer can
      // reach here while retired (an offer is not a reply to anything we
      // hold, so the peer offering on it proves it negotiates there), and
      // leaving it retired would discard the answer to our own next ICE
      // restart on this very binding.
      forgetRetiredRemoteTransport(roomId, peerId, description.sdp);
      if (description.type === "offer") {
        try {
          const answered = await awaitPcOperation(
            epc,
            epc.setLocalDescription(),
            { name: `setLocalDescription(${roomId}, ${peerId})` },
          );
          if (answered === "closed") {
            discardIceForAttempt();
            return { data: undefined };
          }
          if (answered === "timeout")
            throw new Error(`setLocalDescription did not settle for ${peerId}`);
        } catch (error) {
          console.error(`setLocalDescription failed for ${peerId}:`, error);
          discardIceForAttempt();
          return { data: undefined };
        }
        const answer = epc.localDescription;
        if (answer) {
          await api.dispatch(
            signalingServerApi.endpoints.sendMessage.initiate({
              content: {
                type: "description",
                description: answer,
                fromPeerId: keyPair.peerId,
                fromPeerPublicKey: keyPair.publicKey,
                toPeerId: peerId,
                roomId,
                protocolVersion: PROTOCOL_VERSION,
              } as WebSocketMessageDescriptionSend,
            }),
          );
        }
      }
    }

    // Open `main` for the identity initiator whenever this transport has no
    // live one. Deliberately NOT gated on connectionIndex > -1 or
    // connectionState === "connected": after a reconnect the responder may
    // legitimately offer first (its PC was rebuilt while ours survived, or
    // ours was just created from its inbound offer), so the initiator must
    // answer AND open main on that PC; and data channels may be created before
    // the transport reaches "connected" (SCTP opens them once DTLS completes).
    // When the transport reset above closed a stale main, epc.mainChannel is
    // already undefined, and a replacement transport starts with none, so
    // this opens exactly one main per call.
    if (
      !isTransportClosed(epc) &&
      isIdentityInitiator(keyPair.publicKey, epc.withPeerPublicKey) &&
      (!epc.mainChannel ||
        epc.mainChannel.readyState === "closing" ||
        epc.mainChannel.readyState === "closed")
    ) {
      const channel = epc.createDataChannel("main", {
        // Handshake HELLO/CONFIRM frames are a strict transcript sequence.
        ordered: true,
        protocol: "raw",
      });
      epc.mainChannel = await handleOpenChannel(
        { channel, epc, roomId: epc.roomId, dataChannels },
        api,
      );
    }

    return { data: undefined };
  });
};

export default webrtcSetDescriptionQuery;
