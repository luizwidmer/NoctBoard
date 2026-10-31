// SPDX-FileCopyrightText: 2026 Luiz Widmer
// SPDX-License-Identifier: AGPL-3.0-or-later

import CryptoKit
import Foundation
import NoctBoardCore
@preconcurrency import NoctweaveCore

/// An exact signed board record extracted from one authenticated Core envelope.
/// A history wrapper attests old bytes; it does not recreate the old sender's
/// Core receipt. The adapter keeps these two sources separate.
package struct NoctBoardVerifiedExtractedEventV2: @unchecked Sendable {
    package let event: NoctBoardEvent
    package let signedRecordBytes: Data
    package let directOuterEventID: UUID?
    package let historyOuterEventID: UUID?

    package init(
        event: NoctBoardEvent,
        signedRecordBytes: Data,
        directOuterEventID: UUID?,
        historyOuterEventID: UUID?
    ) {
        self.event = event
        self.signedRecordBytes = signedRecordBytes
        self.directOuterEventID = directOuterEventID
        self.historyOuterEventID = historyOuterEventID
    }
}

package enum NoctBoardVerifiedPolicyErrorV2: Error, Equatable, Sendable {
    case missingCheckpoint
    case invalidCheckpoint
    case staleCheckpoint
    case missingProof
    case conflictingProof
}

/// Application authorization follows an owner-signed order, with a Core-bound
/// frontier at every role cutoff. No sender clock or relay arrival order can
/// move a direct event across that cutoff.
package enum NoctBoardVerifiedPolicyV2 {
    package struct VerifiedResult: @unchecked Sendable {
        package let result: NoctBoardProjectionResult
        package let orderedEvents: [NoctBoardEvent]
        package let trustedCheckpointIDs: Set<UUID>
        package let latestCheckpointEvent: NoctBoardEvent
        /// Authenticated outer envelopes deliberately excluded from policy
        /// replay. The client must surface these as container rejections.
        package let quarantinedOuterIDs: Set<UUID>

        package var latestCheckpoint: NoctBoardPolicyCheckpointV2 {
            guard case .policyCheckpointV2(let value) = latestCheckpointEvent.operation else {
                preconditionFailure("The verified result always ends at a checkpoint")
            }
            return value
        }
    }

    private struct Entry {
        let event: NoctBoardEvent
        let signedRecordBytes: Data
        let digest: Data
        var directOuterID: UUID?
        var historyOuterIDs: Set<UUID>
        var directReceipt: GroupApplicationVerificationReceiptV2?

        var checkpoint: NoctBoardPolicyCheckpointV2? {
            guard case .policyCheckpointV2(let value) = event.operation else { return nil }
            return value
        }
    }

    private enum Mode {
        case normal
        case ownerRebind
        case atomicPin(UUID)
    }

    private static let historyDomain = Data("org.noctboard.policy-history-order.v2\0".utf8)

    /// The publisher must pass its already-verified replay order, including
    /// rejected author-chain events. Only the first 128 positions fit inline;
    /// larger existing-member histories are committed by this list's digest.
    package static func historyOrder(
        for events: [NoctBoardEvent]
    ) throws -> [NoctBoardHistoryPositionV2] {
        guard events.count <= NoctweaveArchitectureV2.groupEventRecentWindow,
              Set(events.map(\.id)).count == events.count,
              events.allSatisfy(\.isStructurallyValid) else {
            throw NoctBoardVerifiedPolicyErrorV2.invalidCheckpoint
        }
        return try events.map {
            NoctBoardHistoryPositionV2(
                eventID: $0.id, eventDigest: try NoctBoardCodec.digest($0)
            )
        }
    }

    /// A domain-separated commitment to the exact canonical ordered list.
    package static func historyDigest(
        _ order: [NoctBoardHistoryPositionV2]
    ) throws -> Data {
        guard order.count <= NoctweaveArchitectureV2.groupEventRecentWindow,
              order.allSatisfy(\.isStructurallyValid),
              Set(order.map(\.eventID)).count == order.count else {
            throw NoctBoardVerifiedPolicyErrorV2.invalidCheckpoint
        }
        return Data(SHA256.hash(
            data: historyDomain + (try NoctweaveCanonicalJSON.encode(order))
        ))
    }

    package static func project(
        record: GroupRuntimeRecord,
        board: NoctBoardReference,
        extracted: [NoctBoardVerifiedExtractedEventV2],
        configuration: NoctBoardConfiguration
    ) throws -> VerifiedResult {
        try project(record: record, board: board, extracted: extracted,
                    configuration: configuration, mode: .normal)
    }

    /// Maintenance-only view of a prior epoch. It cannot authorize new board
    /// writes, but lets the owner construct the new current-epoch root.
    package static func projectForOwnerRebind(
        record: GroupRuntimeRecord,
        board: NoctBoardReference,
        extracted: [NoctBoardVerifiedExtractedEventV2],
        configuration: NoctBoardConfiguration
    ) throws -> VerifiedResult {
        try project(record: record, board: board, extracted: extracted,
                    configuration: configuration, mode: .ownerRebind)
    }

    /// Dry-run one accepted direct checkpoint before Core atomically retains
    /// and binds it. Every other unpinned direct owner checkpoint fails closed.
    package static func projectForAtomicPin(
        record: GroupRuntimeRecord,
        board: NoctBoardReference,
        extracted: [NoctBoardVerifiedExtractedEventV2],
        configuration: NoctBoardConfiguration,
        addingCheckpointID: UUID
    ) throws -> VerifiedResult {
        try project(record: record, board: board, extracted: extracted,
                    configuration: configuration, mode: .atomicPin(addingCheckpointID))
    }

    private static func project(
        record: GroupRuntimeRecord,
        board: NoctBoardReference,
        extracted: [NoctBoardVerifiedExtractedEventV2],
        configuration: NoctBoardConfiguration,
        mode: Mode
    ) throws -> VerifiedResult {
        guard record.isStructurallyValid,
              record.groupId == board.groupID,
              configuration.isStructurallyValid,
              configuration.boardID == board.boardID,
              configuration.groupID == board.groupID,
              record.signedState.metadataDigest == Data(SHA256.hash(data: Data(
                "org.noctboard.metadata.v2\0\(board.boardID.uuidString.lowercased())".utf8
              ))),
              let owner = record.signedState.members.first(where: {
                $0.addedEpoch == 1 && $0.role == .owner && $0.removedEpoch == nil
              })?.id,
              let ownerCredential = record.signedState.memberCredentials.first(where: {
                $0.memberHandle == owner && $0.removedEpoch == nil
              })?.credentialHandle,
              configuration.members.contains(where: {
                $0.memberHandle == owner && $0.credentialHandle == ownerCredential
                    && $0.role == .coordinator
              }) else {
            throw NoctBoardVerifiedPolicyErrorV2.invalidCheckpoint
        }

        let outers = Dictionary(grouping: record.events, by: \.id)
        guard outers.values.allSatisfy({ $0.count == 1 }) else {
            throw NoctBoardVerifiedPolicyErrorV2.conflictingProof
        }
        var entries: [UUID: Entry] = [:]
        var usedOuterIDs = Set<UUID>()
        for occurrence in extracted {
            let event = occurrence.event
            guard event.isStructurallyValid,
                  event.boardID == board.boardID,
                  event.groupID == board.groupID,
                  (occurrence.directOuterEventID == nil)
                    != (occurrence.historyOuterEventID == nil),
                  occurrence.signedRecordBytes.count
                    <= NoctBoardSignedEventRecord.maximumEncodedBytes,
                  NoctweaveCanonicalJSON.isCanonical(occurrence.signedRecordBytes),
                  let signed = try? NoctweaveCoder.decode(
                    NoctBoardSignedEventRecord.self,
                    from: occurrence.signedRecordBytes
                  ),
                  let decoded = try? NoctBoardCodec.decode(signed.eventBytes),
                  decoded == event,
                  let canonicalEvent = try? NoctBoardCodec.encode(event),
                  canonicalEvent == signed.eventBytes,
                  let credential = record.signedState.memberCredentials.first(where: {
                    $0.memberHandle == event.authorMemberHandle
                        && $0.credentialHandle == event.authorCredentialHandle
                  }),
                  SigningKeyPair.verify(
                    signature: signed.authorSignature,
                    data: NoctBoardClient.eventSignaturePayload(signed.eventBytes),
                    publicKeyData: credential.signingPublicKey
                  ),
                  let digest = try? NoctBoardCodec.digest(event) else {
                throw NoctBoardVerifiedPolicyErrorV2.missingProof
            }
            let outerID = occurrence.directOuterEventID
                ?? occurrence.historyOuterEventID!
            guard usedOuterIDs.insert(outerID).inserted,
                  let outer = outers[outerID]?.first,
                  outer.groupID == board.groupID,
                  outer.kind == .application,
                  outer.relation == nil,
                  outer.content.parameters.isEmpty,
                  outer.content.fallbackText == nil,
                  outer.content.disposition == .silent else {
                throw NoctBoardVerifiedPolicyErrorV2.conflictingProof
            }
            if occurrence.directOuterEventID != nil {
                guard outer.content.type == NoctBoardClient.contentType,
                      outer.content.payload == occurrence.signedRecordBytes,
                      outer.id == event.id,
                      outer.clientTransactionID == event.clientTransactionID,
                      outer.authorMemberHandle == event.authorMemberHandle,
                      outer.authorCredentialHandle == event.authorCredentialHandle,
                      Int64(NoctweaveRendezvousV2.canonicalTimestamp(
                        outer.createdAt
                      ).timeIntervalSince1970 * 1_000)
                        == event.createdAtUnixMilliseconds else {
                    throw NoctBoardVerifiedPolicyErrorV2.missingProof
                }
            } else {
                guard outer.content.type == NoctBoardClient.historyContentType,
                      outer.authorMemberHandle == owner,
                      outer.authorCredentialHandle == ownerCredential,
                      NoctweaveCanonicalJSON.isCanonical(outer.content.payload),
                      let history = try? NoctweaveCoder.decode(
                        NoctBoardHistoryRecord.self, from: outer.content.payload
                      ),
                      history.boardID == board.boardID,
                      history.groupID == board.groupID,
                      history.signedEventRecordBytes == occurrence.signedRecordBytes else {
                    throw NoctBoardVerifiedPolicyErrorV2.missingProof
                }
            }

            let receipt = record.applicationVerificationReceipt(for: outerID)
            if let receipt {
                guard receiptMatches(receipt, outer: outer) else {
                    throw NoctBoardVerifiedPolicyErrorV2.missingProof
                }
            }
            if var prior = entries[event.id] {
                guard prior.signedRecordBytes == occurrence.signedRecordBytes,
                      prior.digest == digest else {
                    throw NoctBoardVerifiedPolicyErrorV2.conflictingProof
                }
                if occurrence.directOuterEventID != nil {
                    guard prior.directOuterID == nil else {
                        throw NoctBoardVerifiedPolicyErrorV2.conflictingProof
                    }
                    prior.directOuterID = outerID
                    prior.directReceipt = receipt
                } else {
                    prior.historyOuterIDs.insert(outerID)
                }
                entries[event.id] = prior
            } else {
                entries[event.id] = Entry(
                    event: event, signedRecordBytes: occurrence.signedRecordBytes,
                    digest: digest, directOuterID: occurrence.directOuterEventID,
                    historyOuterIDs: occurrence.historyOuterEventID == nil
                        ? [] : [outerID],
                    directReceipt: occurrence.directOuterEventID == nil ? nil : receipt
                )
            }
        }

        // A malformed or omitted owner board envelope may conceal a policy
        // event. Never continue under an earlier role policy in that case.
        var quarantinedOuterIDs = Set<UUID>()
        for outer in record.events where !usedOuterIDs.contains(outer.id)
            && (outer.content.type == NoctBoardClient.contentType
                || outer.content.type == NoctBoardClient.historyContentType) {
            if outer.authorMemberHandle == owner
                && outer.content.type == NoctBoardClient.contentType {
                // An omitted owner direct event might have been a policy
                // checkpoint. Its ambiguity cannot be treated as junk.
                throw NoctBoardVerifiedPolicyErrorV2.missingProof
            }
            quarantinedOuterIDs.insert(outer.id)
        }

        // A member may submit a signed checkpoint-shaped payload, but only
        // the immutable Core owner can create policy. Quarantine the member's
        // event instead of letting one hostile envelope freeze the board.
        let unauthorizedCheckpointIDs = entries.values.compactMap { entry -> UUID? in
            entry.checkpoint != nil && entry.event.authorMemberHandle != owner
                ? entry.event.id : nil
        }
        for eventID in unauthorizedCheckpointIDs {
            guard let entry = entries.removeValue(forKey: eventID) else { continue }
            if let directID = entry.directOuterID {
                quarantinedOuterIDs.insert(directID)
            }
            quarantinedOuterIDs.formUnion(entry.historyOuterIDs)
        }

        var candidates: [(entry: Entry, receipt: GroupApplicationVerificationReceiptV2)] = []
        let nominatedID: UUID?
        if case .atomicPin(let id) = mode { nominatedID = id } else { nominatedID = nil }
        let nominatedReceipt = nominatedID.flatMap { entries[$0]?.directReceipt }
        if nominatedID != nil && nominatedReceipt == nil {
            throw NoctBoardVerifiedPolicyErrorV2.missingProof
        }
        var deferredCheckpointIDs = Set<UUID>()
        for entry in entries.values where entry.checkpoint != nil {
            guard entry.event.schema == NoctBoardEvent.verifiedSchema,
                  entry.event.authorMemberHandle == owner,
                  entry.event.authorCredentialHandle == ownerCredential,
                  let checkpoint = entry.checkpoint,
                  checkpoint.owner == owner,
                  checkpoint.frontiers.allSatisfy({ $0.groupID == board.groupID }) else {
                throw NoctBoardVerifiedPolicyErrorV2.invalidCheckpoint
            }
            guard let directID = entry.directOuterID else { continue }
            let pinned = record.protectedApplicationEventIDs.contains(directID)
            let retired = record.retiredProtectedApplicationEventIDs.contains(directID)
            if !pinned && !retired && nominatedID != directID {
                if let nominatedReceipt,
                   let receipt = entry.directReceipt,
                   receipt.epoch > nominatedReceipt.epoch
                    || (receipt.epoch == nominatedReceipt.epoch
                        && receipt.messageCounter > nominatedReceipt.messageCounter) {
                    // Atomic pin is a maintenance-only prefix dry-run. A sync
                    // page can contain several owner checkpoints; the caller
                    // pins them in authenticated owner-counter order.
                    deferredCheckpointIDs.insert(entry.event.id)
                    continue
                }
                throw NoctBoardVerifiedPolicyErrorV2.missingCheckpoint
            }
            if retired { continue }
            guard let receipt = entry.directReceipt,
                  checkpoint.groupEpoch == receipt.epoch,
                  checkpoint.groupTranscriptHash == receipt.transcriptHash,
                  checkpointHasOwnerPreEventFrontier(checkpoint, receipt: receipt) else {
                throw NoctBoardVerifiedPolicyErrorV2.missingProof
            }
            if pinned {
                guard record.protectedVerificationFrontiers(for: directID)
                    == checkpoint.frontiers else {
                    throw NoctBoardVerifiedPolicyErrorV2.missingProof
                }
            } else {
                guard nominatedID == directID,
                      checkpoint.frontiers.allSatisfy({
                        frontierMatches($0, record: record)
                      }) else {
                    throw NoctBoardVerifiedPolicyErrorV2.missingProof
                }
            }
            candidates.append((entry, receipt))
        }
        guard !candidates.isEmpty else {
            throw NoctBoardVerifiedPolicyErrorV2.missingCheckpoint
        }
        candidates.sort {
            if $0.receipt.epoch != $1.receipt.epoch {
                return $0.receipt.epoch < $1.receipt.epoch
            }
            return $0.receipt.messageCounter < $1.receipt.messageCounter
        }
        guard let latest = candidates.last,
              let latestPolicy = latest.entry.checkpoint else {
            throw NoctBoardVerifiedPolicyErrorV2.missingCheckpoint
        }
        if let nominatedID, latest.entry.event.id != nominatedID {
            throw NoctBoardVerifiedPolicyErrorV2.invalidCheckpoint
        }
        if case .ownerRebind = mode {
            // This exception exists only for an actual Core epoch advance.
            // A damaged current-epoch root cannot be repaired by treating it
            // as a stale prior policy.
            guard latestPolicy.groupEpoch < record.signedState.epoch else {
                throw NoctBoardVerifiedPolicyErrorV2.staleCheckpoint
            }
        } else {
            guard latestPolicy.groupEpoch == record.signedState.epoch,
                  latestPolicy.groupTranscriptHash
                    == record.signedState.confirmedTranscriptHash,
                  Set(latestPolicy.frontiers.map(\.credentialHandle))
                    == Set(record.signedState.activeCredentials.map(\.credentialHandle)) else {
                throw NoctBoardVerifiedPolicyErrorV2.staleCheckpoint
            }
        }
        let digestOnlyOrder = latestPolicy.precedingHistoryOrder == nil
        var orderedPrefix: [NoctBoardEvent] = []
        if let latestOrder = latestPolicy.precedingHistoryOrder {
            guard try historyDigest(latestOrder) == latestPolicy.precedingHistoryDigest,
                  !latestOrder.contains(where: {
                    $0.eventID == latest.entry.event.id
                  }) else {
                throw NoctBoardVerifiedPolicyErrorV2.invalidCheckpoint
            }
            orderedPrefix.reserveCapacity(latestOrder.count + 1)
            for position in latestOrder {
                guard let entry = entries[position.eventID],
                      entry.digest == position.eventDigest else {
                    throw NoctBoardVerifiedPolicyErrorV2.missingProof
                }
                orderedPrefix.append(entry.event)
            }
            orderedPrefix.append(latest.entry.event)
        } else {
            orderedPrefix = try reconstructRetainedDirectOrder(
                entries: entries, latest: latest.entry,
                deferredCheckpointIDs: deferredCheckpointIDs
            )
        }
        let trustedIDs = Set(orderedPrefix.compactMap { event -> UUID? in
            if case .policyCheckpointV2 = event.operation { return event.id }
            return nil
        })
        guard trustedIDs.count == entries.values.filter({
            $0.checkpoint != nil && !deferredCheckpointIDs.contains($0.event.id)
        }).count else {
            throw NoctBoardVerifiedPolicyErrorV2.invalidCheckpoint
        }

        var priorCheckpointDigest: Data?
        for (index, event) in orderedPrefix.enumerated() {
            if event.schema == NoctBoardEvent.currentSchema,
               priorCheckpointDigest != nil {
                // A later owner root must not ratify legacy post-root events.
                // Honest publishers omit them from the signed history order.
                throw NoctBoardVerifiedPolicyErrorV2.invalidCheckpoint
            }
            guard case .policyCheckpointV2(let checkpoint) = event.operation else {
                continue
            }
            let prefix = Array(orderedPrefix[..<index])
            let expectedOrder = try historyOrder(for: prefix)
            let orderIsValid: Bool
            if let inline = checkpoint.precedingHistoryOrder {
                orderIsValid = inline == expectedOrder
            } else {
                // A digest-only order is for retained existing members. A
                // joiner with re-encrypted history needs the inline proof and
                // stays under the separate 128-event admission limit.
                orderIsValid = digestOnlyOrder && expectedOrder.count
                    > NoctBoardClient.maximumAdmissionHistoryEvents
            }
            guard orderIsValid,
                  checkpoint.precedingHistoryDigest == (try historyDigest(expectedOrder)),
                  checkpoint.previousCheckpointDigest == priorCheckpointDigest,
                  (priorCheckpointDigest != nil || checkpoint.kind == .snapshot),
                  checkpoint.owner == owner else {
                throw NoctBoardVerifiedPolicyErrorV2.invalidCheckpoint
            }
            priorCheckpointDigest = try NoctBoardCodec.digest(event)
        }

        // Every direct receipt must agree with every signed cutoff. This
        // catches a late sender event hidden in a backdated history list and
        // catches an omitted event already consumed before a checkpoint.
        guard let firstRoot = orderedPrefix.first(where: {
            if case .policyCheckpointV2 = $0.operation { return true }
            return false
        }), case .policyCheckpointV2(let rootPolicy) = firstRoot.operation else {
            throw NoctBoardVerifiedPolicyErrorV2.invalidCheckpoint
        }
        let policyChain = orderedPrefix.compactMap { event
            -> NoctBoardPolicyCheckpointV2? in
            guard case .policyCheckpointV2(let value) = event.operation else {
                return nil
            }
            return value
        }
        let policyGapIDs = Set(entries.values.compactMap { entry -> UUID? in
            guard entry.checkpoint == nil,
                  entry.event.schema == NoctBoardEvent.verifiedSchema,
                  let receipt = entry.directReceipt,
                  isPolicyGap(receipt, checkpoints: policyChain) else {
                return nil
            }
            return entry.event.id
        })
        guard !orderedPrefix.contains(where: { policyGapIDs.contains($0.id) }) else {
            throw NoctBoardVerifiedPolicyErrorV2.invalidCheckpoint
        }
        for eventID in policyGapIDs {
            guard let entry = entries[eventID] else { continue }
            if let directID = entry.directOuterID {
                quarantinedOuterIDs.insert(directID)
            }
            quarantinedOuterIDs.formUnion(entry.historyOuterIDs)
        }
        let legacyAfterRoot = Set(entries.values.compactMap { entry -> UUID? in
            guard entry.event.schema == NoctBoardEvent.currentSchema,
                  let receipt = entry.directReceipt,
                  !receiptPrecedes(receipt, checkpoint: rootPolicy) else {
                return nil
            }
            return entry.event.id
        })
        for eventID in legacyAfterRoot {
            guard let entry = entries[eventID] else { continue }
            if let directID = entry.directOuterID {
                quarantinedOuterIDs.insert(directID)
            }
            quarantinedOuterIDs.formUnion(entry.historyOuterIDs)
        }
        for (index, checkpointEvent) in orderedPrefix.enumerated() {
            guard case .policyCheckpointV2(let checkpoint) = checkpointEvent.operation
                else { continue }
            for entry in entries.values where entry.event.id != checkpointEvent.id
                && !legacyAfterRoot.contains(entry.event.id)
                && !policyGapIDs.contains(entry.event.id) {
                guard let receipt = entry.directReceipt else { continue }
                let listedBefore = orderedPrefix[..<index].contains {
                    $0.id == entry.event.id
                }
                guard listedBefore == receiptPrecedes(receipt, checkpoint: checkpoint) else {
                    throw NoctBoardVerifiedPolicyErrorV2.invalidCheckpoint
                }
            }
        }

        let signedIDs = Set(orderedPrefix.map(\.id))
        var tail: [NoctBoardEvent] = []
        if case .atomicPin = mode {
            // The candidate's signed order is the entire proof under review.
            // Post-candidate events must wait for the next successful pin;
            // replaying them under a provisional role would be unsafe.
        } else {
            for entry in entries.values where !signedIDs.contains(entry.event.id) {
                if legacyAfterRoot.contains(entry.event.id)
                    || policyGapIDs.contains(entry.event.id) { continue }
                guard entry.checkpoint == nil,
                      entry.historyOuterIDs.isEmpty || entry.directOuterID != nil,
                      let receipt = entry.directReceipt,
                      entry.event.schema == NoctBoardEvent.verifiedSchema,
                      receipt.epoch == latestPolicy.groupEpoch,
                      !receiptPrecedes(receipt, checkpoint: latestPolicy) else {
                    throw NoctBoardVerifiedPolicyErrorV2.missingProof
                }
                tail.append(entry.event)
            }
        }
        tail.sort(by: NoctBoardProjector.deterministicOrder)
        let orderedEvents = orderedPrefix + tail
        let result = try NoctBoardProjector.projectVerifiedOrder(
            events: orderedEvents, configuration: configuration,
            trustedCheckpointIDs: trustedIDs
        )
        guard result.ledger.entries.filter({ trustedIDs.contains($0.eventID) }).count
                == trustedIDs.count,
              result.ledger.entries.allSatisfy({ entry in
                !trustedIDs.contains(entry.eventID) || entry.outcome == .accepted
              }) else {
            throw NoctBoardVerifiedPolicyErrorV2.invalidCheckpoint
        }
        return VerifiedResult(
            result: result, orderedEvents: orderedEvents,
            trustedCheckpointIDs: trustedIDs,
            latestCheckpointEvent: latest.entry.event,
            quarantinedOuterIDs: quarantinedOuterIDs
        )
    }

    /// The larger legacy migration uses one Core-bound digest instead of a
    /// 3,000-position inline payload. A member needs every original signed
    /// direct legacy event, or a prior inline root that attested a smaller
    /// re-encrypted bootstrap. Later intervals require direct Core receipts.
    private static func reconstructRetainedDirectOrder(
        entries: [UUID: Entry],
        latest: Entry,
        deferredCheckpointIDs: Set<UUID>
    ) throws -> [NoctBoardEvent] {
        let checkpointEntries = entries.values.filter {
            $0.checkpoint != nil
                && !deferredCheckpointIDs.contains($0.event.id)
        }
        var byDigest: [Data: Entry] = [:]
        for entry in checkpointEntries {
            if case .some = byDigest[entry.digest] {
                throw NoctBoardVerifiedPolicyErrorV2.conflictingProof
            }
            byDigest[entry.digest] = entry
        }
        var backwards: [Entry] = []
        var seen = Set<UUID>()
        var cursor = latest
        while true {
            guard seen.insert(cursor.event.id).inserted,
                  let checkpoint = cursor.checkpoint else {
                throw NoctBoardVerifiedPolicyErrorV2.invalidCheckpoint
            }
            backwards.append(cursor)
            guard let previousDigest = checkpoint.previousCheckpointDigest else { break }
            guard let prior = byDigest[previousDigest] else {
                throw NoctBoardVerifiedPolicyErrorV2.missingProof
            }
            cursor = prior
        }
        guard backwards.count == checkpointEntries.count,
              let first = backwards.last,
              let root = first.checkpoint,
              root.kind == .snapshot,
              root.previousCheckpointDigest == nil else {
            throw NoctBoardVerifiedPolicyErrorV2.invalidCheckpoint
        }
        let checkpoints = Array(backwards.reversed())
        let checkpointPolicies = checkpoints.compactMap(\.checkpoint)

        // Migrated v5 events can lack Core receipts. They are still retained
        // authenticated group events, and the owner reviewed their exact
        // deterministic order before signing the new v6 root. In contrast,
        // every newly sent event after the root has a Core receipt.
        var ordered: [NoctBoardEvent]
        let inlineAnchorIndex = checkpoints.lastIndex {
            $0.checkpoint?.precedingHistoryOrder != nil
        }
        let nextCheckpointIndex: Int
        if let inlineAnchorIndex,
           let inline = checkpoints[inlineAnchorIndex]
                .checkpoint?.precedingHistoryOrder {
            ordered = try inline.map { position in
                guard let entry = entries[position.eventID],
                      entry.digest == position.eventDigest else {
                    throw NoctBoardVerifiedPolicyErrorV2.missingProof
                }
                return entry.event
            }
            ordered.append(checkpoints[inlineAnchorIndex].event)
            nextCheckpointIndex = inlineAnchorIndex + 1
        } else {
            guard checkpoints.allSatisfy({ $0.directReceipt != nil }) else {
                throw NoctBoardVerifiedPolicyErrorV2.missingProof
            }
            let legacy = entries.values.filter { entry in
                entry.event.schema == NoctBoardEvent.currentSchema
                    && (entry.directReceipt == nil
                        || receiptPrecedes(entry.directReceipt!, checkpoint: root))
            }
            guard legacy.allSatisfy({ $0.directOuterID != nil }) else {
                throw NoctBoardVerifiedPolicyErrorV2.missingProof
            }
            ordered = legacy.map(\.event).sorted(
                by: NoctBoardProjector.deterministicOrder
            )
            nextCheckpointIndex = 0
        }
        var includedIDs = Set(ordered.map(\.id))
        for checkpointEntry in checkpoints.dropFirst(nextCheckpointIndex) {
            guard let checkpoint = checkpointEntry.checkpoint,
                  checkpointEntry.directReceipt != nil else {
                throw NoctBoardVerifiedPolicyErrorV2.invalidCheckpoint
            }
            let intervalEntries = entries.values.filter { entry in
                guard entry.checkpoint == nil,
                      entry.event.schema == NoctBoardEvent.verifiedSchema,
                      let receipt = entry.directReceipt,
                      !includedIDs.contains(entry.event.id) else { return false }
                return !isPolicyGap(receipt, checkpoints: checkpointPolicies)
                    && receiptPrecedes(receipt, checkpoint: checkpoint)
            }
            guard intervalEntries.allSatisfy({ $0.directOuterID != nil }) else {
                throw NoctBoardVerifiedPolicyErrorV2.missingProof
            }
            let interval = intervalEntries.map(\.event).sorted(
                by: NoctBoardProjector.deterministicOrder
            )
            ordered.append(contentsOf: interval)
            includedIDs.formUnion(interval.map(\.id))
            ordered.append(checkpointEntry.event)
            includedIDs.insert(checkpointEntry.event.id)
            guard ordered.count <= NoctweaveArchitectureV2.groupEventRecentWindow else {
                throw NoctBoardVerifiedPolicyErrorV2.invalidCheckpoint
            }
        }
        return ordered
    }

    private static func receiptMatches(
        _ receipt: GroupApplicationVerificationReceiptV2,
        outer: GroupConversationEventV2
    ) -> Bool {
        receipt.isStructurallyValid && receipt.outcome == .accepted
            && receipt.eventID == outer.id && receipt.groupID == outer.groupID
            && receipt.eventDigest == outer.digest
            && receipt.credentialHandle == outer.authorCredentialHandle
    }

    private static func checkpointHasOwnerPreEventFrontier(
        _ checkpoint: NoctBoardPolicyCheckpointV2,
        receipt: GroupApplicationVerificationReceiptV2
    ) -> Bool {
        checkpoint.frontiers.contains {
            $0.epoch == receipt.epoch
                && $0.transcriptHash == receipt.transcriptHash
                && $0.credentialHandle == receipt.credentialHandle
                && $0.nextCounter == receipt.messageCounter
                && $0.prefixDigest == receipt.previousPrefixDigest
        }
    }

    private static func receiptPrecedes(
        _ receipt: GroupApplicationVerificationReceiptV2,
        checkpoint: NoctBoardPolicyCheckpointV2
    ) -> Bool {
        if receipt.epoch != checkpoint.groupEpoch {
            return receipt.epoch < checkpoint.groupEpoch
        }
        guard receipt.transcriptHash == checkpoint.groupTranscriptHash,
              let frontier = checkpoint.frontiers.first(where: {
                $0.credentialHandle == receipt.credentialHandle
              }) else { return false }
        return receipt.messageCounter < frontier.nextCounter
    }

    /// An ordinary v2 event sent before the first policy root for its Core
    /// epoch has no role policy. It is quarantined rather than replayed under
    /// an older epoch's roles or allowed to block the owner's rebind.
    private static func isPolicyGap(
        _ receipt: GroupApplicationVerificationReceiptV2,
        checkpoints: [NoctBoardPolicyCheckpointV2]
    ) -> Bool {
        guard let first = checkpoints.first else { return true }
        if receipt.epoch < first.groupEpoch { return true }
        guard let firstInEpoch = checkpoints.first(where: {
            $0.groupEpoch == receipt.epoch
        }) else { return true }
        return receiptPrecedes(receipt, checkpoint: firstInEpoch)
    }

    private static func frontierMatches(
        _ expected: GroupApplicationVerificationFrontierV2,
        record: GroupRuntimeRecord
    ) -> Bool {
        guard expected.groupID == record.groupId,
              expected.isStructurallyValid else { return false }
        if record.verificationFrontier(
            epoch: expected.epoch, credential: expected.credentialHandle
        ) == expected { return true }
        if record.applicationVerificationReceipts.contains(where: {
            $0.epoch == expected.epoch
                && $0.transcriptHash == expected.transcriptHash
                && $0.credentialHandle == expected.credentialHandle
                && $0.messageCounter == expected.nextCounter
                && $0.previousPrefixDigest == expected.prefixDigest
        }) { return true }
        if expected.nextCounter > 0,
           record.applicationVerificationReceipts.contains(where: {
               $0.epoch == expected.epoch
                   && $0.transcriptHash == expected.transcriptHash
                   && $0.credentialHandle == expected.credentialHandle
                   && $0.messageCounter + 1 == expected.nextCounter
                   && $0.prefixDigest == expected.prefixDigest
           }) { return true }
        return record.protectedApplicationVerificationBindings.contains {
            $0.frontiers.contains(expected)
        }
    }
}
