// SPDX-FileCopyrightText: 2026 Luiz Widmer
// SPDX-License-Identifier: AGPL-3.0-or-later

import CryptoKit
import Foundation
import XCTest
import NoctBoardCore
@testable import NoctBoardTransport
@preconcurrency import NoctweaveCore

final class NoctBoardVerifiedPolicyV2Tests: XCTestCase {
    func testMigrationCapacityPreflightRejectsBeforeV1MetadataChanges() async throws {
        let fixture = try makeFixture(verifiedMetadata: false)
        let before = await fixture.runtime.snapshot()
        let root = NoctBoardEvent(
            boardID: fixture.board.boardID, groupID: fixture.board.groupID,
            authorMemberHandle: fixture.owner,
            authorCredentialHandle: fixture.credential.credentialHandle,
            logicalClock: 0, authorSequence: 0,
            previousAuthorEventDigest: nil,
            createdAtUnixMilliseconds: fixture.milliseconds,
            operation: .createThread(.init(title: "Capacity preflight"))
        )
        let currentBytes = try NoctweaveCoder.encode(before, sortedKeys: true).count
        XCTAssertThrowsError(try NoctBoardClient.preflightMigrationCapacity(
            state: before, root: root,
            maximumDurableBytes: currentBytes + 16 * 1_024 * 1_024 - 1
        )) {
            XCTAssertEqual(
                $0 as? NoctBoardTransportError,
                .verifiedPolicyCapacityExceeded
            )
        }
        let after = await fixture.runtime.snapshot()
        XCTAssertEqual(after.signedState.metadataDigest, before.signedState.metadataDigest)
        XCTAssertEqual(after.signedState.epoch, before.signedState.epoch)
        XCTAssertEqual(after.events, before.events)
    }

    func testSignedRootRequiresExactDurableCorePin() async throws {
        let fixture = try makeFixture()
        let root = try await publishRoot(fixture)
        let verified = try NoctBoardVerifiedPolicyV2.project(
            record: await fixture.runtime.snapshot(), board: fixture.board,
            extracted: [root.extracted], configuration: fixture.configuration
        )
        XCTAssertEqual(verified.orderedEvents.map(\.id), [root.event.id])
        XCTAssertEqual(verified.trustedCheckpointIDs, [root.event.id])
        XCTAssertEqual(verified.result.ledger.accepted.map(\.eventID), [root.event.id])
        let current = await fixture.runtime.snapshot()
        XCTAssertThrowsError(try NoctBoardVerifiedPolicyV2.projectForOwnerRebind(
            record: current, board: fixture.board,
            extracted: [root.extracted], configuration: fixture.configuration
        )) {
            XCTAssertEqual($0 as? NoctBoardVerifiedPolicyErrorV2, .staleCheckpoint)
        }

        try await fixture.runtime.removeProtectedApplicationEvent(eventID: root.event.id)
        let unpinned = await fixture.runtime.snapshot()
        XCTAssertThrowsError(try NoctBoardVerifiedPolicyV2.project(
            record: unpinned, board: fixture.board,
            extracted: [root.extracted], configuration: fixture.configuration
        )) {
            XCTAssertEqual($0 as? NoctBoardVerifiedPolicyErrorV2, .missingCheckpoint)
        }
    }

    func testSenderClockCannotMoveLaterDirectEventBeforeRoot() async throws {
        let fixture = try makeFixture()
        let root = try await publishRoot(fixture)
        let later = NoctBoardEvent(
            schema: NoctBoardEvent.verifiedSchema,
            boardID: fixture.board.boardID, groupID: fixture.board.groupID,
            authorMemberHandle: fixture.owner,
            authorCredentialHandle: fixture.credential.credentialHandle,
            logicalClock: 0, authorSequence: 1,
            previousAuthorEventDigest: try NoctBoardCodec.digest(root.event),
            createdAtUnixMilliseconds: fixture.milliseconds + 1_000,
            operation: .createThread(.init(title: "After root"))
        )
        let laterExtracted = try await publish(
            later, fixture: fixture, at: fixture.now.addingTimeInterval(1)
        )
        let verified = try NoctBoardVerifiedPolicyV2.project(
            record: await fixture.runtime.snapshot(), board: fixture.board,
            extracted: [laterExtracted, root.extracted],
            configuration: fixture.configuration
        )
        XCTAssertEqual(verified.orderedEvents.map(\.id), [root.event.id, later.id])
        XCTAssertEqual(verified.result.projection.threads.count, 1)

        // A schema-v1 event after a verified root has no admitted receipt
        // policy, even if its author clock is smaller than the root's clock.
        let legacy = NoctBoardEvent(
            boardID: fixture.board.boardID, groupID: fixture.board.groupID,
            authorMemberHandle: fixture.owner,
            authorCredentialHandle: fixture.credential.credentialHandle,
            logicalClock: 0, authorSequence: 2,
            previousAuthorEventDigest: try NoctBoardCodec.digest(later),
            createdAtUnixMilliseconds: fixture.milliseconds + 2_000,
            operation: .createThread(.init(title: "Legacy after root"))
        )
        let legacyExtracted = try await publish(
            legacy, fixture: fixture, at: fixture.now.addingTimeInterval(2)
        )
        let withLegacy = await fixture.runtime.snapshot()
        let quarantined = try NoctBoardVerifiedPolicyV2.project(
            record: withLegacy, board: fixture.board,
            extracted: [root.extracted, laterExtracted, legacyExtracted],
            configuration: fixture.configuration
        )
        XCTAssertEqual(quarantined.orderedEvents.map(\.id), [root.event.id, later.id])
        XCTAssertEqual(quarantined.quarantinedOuterIDs, [legacy.id])
        XCTAssertEqual(quarantined.result.projection.threads.count, 1)
    }

    func testOwnerHistoryWrapperDoesNotReplaceMissingCheckpointPin() async throws {
        let fixture = try makeFixture()
        let root = try await publishRoot(fixture)
        let historyID = UUID()
        let historyBytes = try NoctweaveCoder.encode(NoctBoardHistoryRecord(
            boardID: fixture.board.boardID,
            groupID: fixture.board.groupID,
            signedEventRecordBytes: root.extracted.signedRecordBytes
        ), sortedKeys: true)
        let historyOuter = GroupConversationEventV2(
            id: historyID, groupID: fixture.board.groupID,
            authorMemberHandle: fixture.owner,
            authorCredentialHandle: fixture.credential.credentialHandle,
            createdAt: fixture.now.addingTimeInterval(1), kind: .application,
            content: EncodedContent(
                type: NoctBoardClient.historyContentType, parameters: [:],
                payload: historyBytes, fallbackText: nil, disposition: .silent
            )
        )
        _ = try await fixture.runtime.prepareApplicationEvent(
            historyOuter, at: fixture.now.addingTimeInterval(1)
        )
        try await fixture.runtime.markApplicationPublished(eventID: historyID)
        let wrapped = NoctBoardVerifiedExtractedEventV2(
            event: root.event,
            signedRecordBytes: root.extracted.signedRecordBytes,
            directOuterEventID: nil,
            historyOuterEventID: historyID
        )
        let beforeRemoval = await fixture.runtime.snapshot()
        XCTAssertNoThrow(try NoctBoardVerifiedPolicyV2.project(
            record: beforeRemoval, board: fixture.board,
            extracted: [root.extracted, wrapped],
            configuration: fixture.configuration
        ))
        try await fixture.runtime.removeProtectedApplicationEvent(eventID: root.event.id)
        let afterRemoval = await fixture.runtime.snapshot()
        XCTAssertThrowsError(try NoctBoardVerifiedPolicyV2.project(
            record: afterRemoval, board: fixture.board,
            extracted: [root.extracted, wrapped],
            configuration: fixture.configuration
        )) {
            XCTAssertEqual($0 as? NoctBoardVerifiedPolicyErrorV2, .missingCheckpoint)
        }
    }

    func testHistoryDigestCommitsToOrderAndExactEventBytes() throws {
        let owner = GroupScopedMemberHandleV2.generate()
        let credential = GroupScopedCredentialHandleV2.generate()
        let board = UUID()
        let first = NoctBoardEvent(
            boardID: board, groupID: board,
            authorMemberHandle: owner, authorCredentialHandle: credential,
            logicalClock: 0, authorSequence: 0,
            previousAuthorEventDigest: nil,
            createdAtUnixMilliseconds: 1_789_000_000_000,
            operation: .createThread(.init(title: "First"))
        )
        let second = NoctBoardEvent(
            boardID: board, groupID: board,
            authorMemberHandle: owner, authorCredentialHandle: credential,
            logicalClock: 1, authorSequence: 1,
            previousAuthorEventDigest: try NoctBoardCodec.digest(first),
            createdAtUnixMilliseconds: 1_789_000_001_000,
            operation: .createThread(.init(title: "Second"))
        )
        let forward = try NoctBoardVerifiedPolicyV2.historyOrder(for: [first, second])
        let reverse = try NoctBoardVerifiedPolicyV2.historyOrder(for: [second, first])
        XCTAssertNotEqual(
            try NoctBoardVerifiedPolicyV2.historyDigest(forward),
            try NoctBoardVerifiedPolicyV2.historyDigest(reverse)
        )
        XCTAssertThrowsError(try NoctBoardVerifiedPolicyV2.historyOrder(
            for: [first, first]
        ))
        XCTAssertThrowsError(try NoctBoardVerifiedPolicyV2.historyDigest(
            [forward[0], forward[0]]
        ))
    }

    func testDigestOnlyOrderSupportsThreeThousandRetainedEvents() throws {
        let board = UUID()
        let owner = GroupScopedMemberHandleV2.generate()
        let credential = GroupScopedCredentialHandleV2.generate()
        var events: [NoctBoardEvent] = []
        events.reserveCapacity(3_000)
        var previous: Data?
        for sequence in 0 ..< 3_000 {
            let event = NoctBoardEvent(
                boardID: board, groupID: board,
                authorMemberHandle: owner,
                authorCredentialHandle: credential,
                logicalClock: UInt64(sequence),
                authorSequence: UInt64(sequence),
                previousAuthorEventDigest: previous,
                createdAtUnixMilliseconds: 1_789_000_000_000
                    + Int64(sequence * 1_000),
                operation: .createThread(.init(title: "Retained \(sequence)"))
            )
            previous = try NoctBoardCodec.digest(event)
            events.append(event)
        }
        let order = try NoctBoardVerifiedPolicyV2.historyOrder(for: events)
        XCTAssertEqual(order.count, 3_000)
        let digest = try NoctBoardVerifiedPolicyV2.historyDigest(order)
        XCTAssertEqual(digest.count, 32)
        XCTAssertEqual(digest, try NoctBoardVerifiedPolicyV2.historyDigest(
            NoctBoardVerifiedPolicyV2.historyOrder(for: events)
        ))
        let frontier = GroupApplicationVerificationFrontierV2.initial(
            groupID: board, epoch: 1,
            transcriptHash: Data(repeating: 0x42, count: 32),
            credentialHandle: credential
        )
        let checkpoint = NoctBoardPolicyCheckpointV2(
            kind: .snapshot, owner: owner, groupEpoch: 1,
            groupTranscriptHash: frontier.transcriptHash,
            previousCheckpointDigest: nil, frontiers: [frontier],
            precedingHistoryDigest: digest, precedingHistoryOrder: nil
        )
        let root = NoctBoardEvent(
            schema: NoctBoardEvent.verifiedSchema,
            boardID: board, groupID: board,
            authorMemberHandle: owner, authorCredentialHandle: credential,
            logicalClock: 3_000, authorSequence: 3_000,
            previousAuthorEventDigest: previous,
            createdAtUnixMilliseconds: 1_789_003_000_000,
            operation: .policyCheckpointV2(checkpoint)
        )
        let configuration = NoctBoardConfiguration(
            boardID: board, groupID: board,
            members: [.init(
                memberHandle: owner, credentialHandle: credential,
                role: .coordinator
            )]
        )
        let projected = try NoctBoardProjector.projectVerifiedOrder(
            events: events + [root], configuration: configuration,
            trustedCheckpointIDs: [root.id]
        )
        XCTAssertEqual(projected.projection.threads.count, 3_000)
        XCTAssertEqual(projected.ledger.accepted.count, 3_001)
        XCTAssertLessThanOrEqual(3_001, NoctweaveArchitectureV2.groupEventRecentWindow)
        let rootBytes = try NoctBoardCodec.encode(root)
        XCTAssertLessThanOrEqual(rootBytes.count, NoctBoardLimits.maximumEventBytes)
        let signer = try SigningKeyPair.generate()
        let signed = NoctBoardSignedEventRecord(
            eventBytes: rootBytes,
            authorSignature: try signer.sign(
                NoctBoardClient.eventSignaturePayload(rootBytes)
            )
        )
        let signedBytes = try NoctweaveCoder.encode(signed, sortedKeys: true)
        XCTAssertLessThanOrEqual(
            signedBytes.count, NoctBoardSignedEventRecord.maximumEncodedBytes
        )
        XCTAssertTrue(EncodedContent(
            type: NoctBoardClient.contentType, parameters: [:],
            payload: signedBytes, fallbackText: nil, disposition: .silent
        ).isStructurallyValid)
    }

    func testDigestOnlyRootReplaysRetainedHistoryAfterRestart() async throws {
        let fixture = try makeFixture()
        var extracted: [NoctBoardVerifiedExtractedEventV2] = []
        var legacy: [NoctBoardEvent] = []
        var previous: Data?
        for sequence in 0 ..< 129 {
            let event = NoctBoardEvent(
                boardID: fixture.board.boardID,
                groupID: fixture.board.groupID,
                authorMemberHandle: fixture.owner,
                authorCredentialHandle: fixture.credential.credentialHandle,
                logicalClock: UInt64(sequence),
                authorSequence: UInt64(sequence),
                previousAuthorEventDigest: previous,
                createdAtUnixMilliseconds: fixture.milliseconds
                    + Int64(sequence * 1_000),
                operation: .createThread(.init(title: "Legacy \(sequence)"))
            )
            extracted.append(try await publish(
                event, fixture: fixture,
                at: fixture.now.addingTimeInterval(TimeInterval(sequence))
            ))
            previous = try NoctBoardCodec.digest(event)
            legacy.append(event)
        }
        let before = await fixture.runtime.snapshot()
        let frontiers = try XCTUnwrap(before.currentVerificationFrontiers())
        let order = try NoctBoardVerifiedPolicyV2.historyOrder(for: legacy)
        let checkpoint = NoctBoardPolicyCheckpointV2(
            kind: .snapshot, owner: fixture.owner,
            groupEpoch: before.signedState.epoch,
            groupTranscriptHash: before.signedState.confirmedTranscriptHash,
            previousCheckpointDigest: nil, frontiers: frontiers,
            precedingHistoryDigest: try NoctBoardVerifiedPolicyV2.historyDigest(order),
            precedingHistoryOrder: nil
        )
        let root = NoctBoardEvent(
            schema: NoctBoardEvent.verifiedSchema,
            boardID: fixture.board.boardID,
            groupID: fixture.board.groupID,
            authorMemberHandle: fixture.owner,
            authorCredentialHandle: fixture.credential.credentialHandle,
            logicalClock: 129, authorSequence: 129,
            previousAuthorEventDigest: previous,
            createdAtUnixMilliseconds: fixture.milliseconds + 129_000,
            operation: .policyCheckpointV2(checkpoint)
        )
        extracted.append(try await publish(
            root, fixture: fixture,
            at: fixture.now.addingTimeInterval(129)
        ))
        try await fixture.runtime.replaceProtectedApplicationEvent(
            previousEventID: nil, with: root.id,
            verificationFrontiers: frontiers
        )
        let earlierID = UUID(uuidString: "ffffffff-ffff-4fff-8fff-ffffffffffff")!
        let laterID = UUID(uuidString: "00000000-0000-4000-8000-000000000001")!
        let second = try await publishNextSnapshot(
            fixture, preceding: legacy + [root], secondOffset: 130,
            eventID: earlierID, inlineOrder: false
        )
        let third = try await publishNextSnapshot(
            fixture, preceding: legacy + [root, second.event], secondOffset: 131,
            eventID: laterID, inlineOrder: false
        )
        extracted.append(contentsOf: [second.extracted, third.extracted])
        let batch = await fixture.runtime.snapshot()
        XCTAssertEqual(NoctBoardClient.checkpointPinOrder(
            state: batch, extracted: Array(extracted.reversed())
        ), [earlierID, laterID])
        XCTAssertThrowsError(try NoctBoardVerifiedPolicyV2.project(
            record: batch, board: fixture.board,
            extracted: extracted, configuration: fixture.configuration
        ))
        let secondDryRun = try NoctBoardVerifiedPolicyV2.projectForAtomicPin(
            record: batch, board: fixture.board,
            extracted: extracted, configuration: fixture.configuration,
            addingCheckpointID: earlierID
        )
        XCTAssertEqual(secondDryRun.latestCheckpointEvent.id, earlierID)
        guard case .policyCheckpointV2(let secondPayload) = second.event.operation,
              case .policyCheckpointV2(let thirdPayload) = third.event.operation else {
            return XCTFail("expected digest-only checkpoints")
        }
        try await fixture.runtime.replaceProtectedApplicationEvent(
            previousEventID: nil, with: earlierID,
            verificationFrontiers: secondPayload.frontiers
        )
        let thirdDryRun = try NoctBoardVerifiedPolicyV2.projectForAtomicPin(
            record: await fixture.runtime.snapshot(), board: fixture.board,
            extracted: extracted, configuration: fixture.configuration,
            addingCheckpointID: laterID
        )
        XCTAssertEqual(thirdDryRun.latestCheckpointEvent.id, laterID)
        try await fixture.runtime.replaceProtectedApplicationEvent(
            previousEventID: nil, with: laterID,
            verificationFrontiers: thirdPayload.frontiers
        )
        let reopened = try await NoctweavePQGroupRuntimeV2.open(
            persistence: fixture.store
        )
        let persisted = await reopened.snapshot()
        let verified = try NoctBoardVerifiedPolicyV2.project(
            record: persisted, board: fixture.board,
            extracted: Array(extracted.reversed()),
            configuration: fixture.configuration
        )
        XCTAssertEqual(verified.orderedEvents.map(\.id),
                       legacy.map(\.id) + [root.id, earlierID, laterID])
        XCTAssertEqual(verified.result.projection.threads.count, 129)
        XCTAssertEqual(verified.result.ledger.accepted.count, 132)
    }

    func testAtomicPinChecksOnlyNominatedPrefixWhenTwoCheckpointsArriveTogether() async throws {
        let fixture = try makeFixture()
        let root = try await publishRoot(fixture)
        let second = try await publishNextSnapshot(
            fixture, preceding: [root.event], secondOffset: 1
        )
        let third = try await publishNextSnapshot(
            fixture, preceding: [root.event, second.event], secondOffset: 2
        )
        let extracted = [root.extracted, second.extracted, third.extracted]
        let unpinned = await fixture.runtime.snapshot()
        XCTAssertThrowsError(try NoctBoardVerifiedPolicyV2.project(
            record: unpinned, board: fixture.board,
            extracted: extracted, configuration: fixture.configuration
        )) {
            XCTAssertEqual($0 as? NoctBoardVerifiedPolicyErrorV2, .missingCheckpoint)
        }
        let firstDryRun = try NoctBoardVerifiedPolicyV2.projectForAtomicPin(
            record: unpinned, board: fixture.board,
            extracted: extracted, configuration: fixture.configuration,
            addingCheckpointID: second.event.id
        )
        XCTAssertEqual(firstDryRun.orderedEvents.map(\.id), [
            root.event.id, second.event.id
        ])
        guard case .policyCheckpointV2(let secondPayload) = second.event.operation else {
            return XCTFail("expected the second checkpoint")
        }
        try await fixture.runtime.replaceProtectedApplicationEvent(
            previousEventID: nil, with: second.event.id,
            verificationFrontiers: secondPayload.frontiers
        )
        let secondDryRun = try NoctBoardVerifiedPolicyV2.projectForAtomicPin(
            record: await fixture.runtime.snapshot(), board: fixture.board,
            extracted: extracted, configuration: fixture.configuration,
            addingCheckpointID: third.event.id
        )
        XCTAssertEqual(secondDryRun.orderedEvents.map(\.id), [
            root.event.id, second.event.id, third.event.id
        ])
        guard case .policyCheckpointV2(let thirdPayload) = third.event.operation else {
            return XCTFail("expected the third checkpoint")
        }
        try await fixture.runtime.replaceProtectedApplicationEvent(
            previousEventID: nil, with: third.event.id,
            verificationFrontiers: thirdPayload.frontiers
        )
        let verified = try NoctBoardVerifiedPolicyV2.project(
            record: await fixture.runtime.snapshot(), board: fixture.board,
            extracted: extracted, configuration: fixture.configuration
        )
        XCTAssertEqual(verified.result.ledger.accepted.map(\.eventID), [
            root.event.id, second.event.id, third.event.id
        ])
    }

    private struct Fixture {
        let runtime: NoctweavePQGroupRuntimeV2
        let store: BoardPolicyTestStore
        let board: NoctBoardReference
        let configuration: NoctBoardConfiguration
        let owner: GroupScopedMemberHandleV2
        let credential: LocalGroupCredentialV2
        let now: Date
        let milliseconds: Int64
    }

    private func makeFixture(verifiedMetadata: Bool = true) throws -> Fixture {
        let now = NoctweaveRendezvousV2.canonicalTimestamp(
            Date(timeIntervalSince1970: 1_789_000_000)
        )
        let board = try NoctBoardReference(id: UUID())
        let owner = GroupScopedMemberHandleV2.generate()
        let signingKey = try SigningKeyPair.generate()
        let agreementKey = try AgreementKeyPair.generate()
        let admission = try GroupCredentialAdmissionV2.create(
            groupId: board.groupID, memberHandle: owner,
            credentialHandle: .generate(),
            groupSigningKey: signingKey, groupAgreementKey: agreementKey,
            contentTypes: ProtocolCapabilityManifest.defaultContentTypes
                + [NoctBoardClient.contentCapability,
                   NoctBoardClient.historyContentCapability],
            issuedAt: now, expiresAt: now.addingTimeInterval(3_600)
        )
        let leaf = try GroupMemberCredentialV2.fromVerifiedProjection(
            admission, addedEpoch: 1
        )
        let credential = LocalGroupCredentialV2(
            groupId: board.groupID, memberHandle: owner,
            credentialHandle: leaf.credentialHandle,
            admissionDigest: leaf.admissionDigest,
            signingKey: signingKey, agreementKey: agreementKey
        )
        let creator = GroupMemberV2(id: owner, role: .owner, addedEpoch: 1)
        let provider = NoctweavePQGroupExperimentalProviderV2()
        let membership = try provider.membership(
            groupId: board.groupID, epoch: 1,
            members: [creator], leaves: [leaf]
        )
        let prepared = try provider.prepareGenesis(
            membership: membership, localCredential: credential
        )
        let domain = verifiedMetadata
            ? "org.noctboard.metadata.v2\0"
            : "org.noctboard.metadata.v1\0"
        let metadata = Data(SHA256.hash(data: Data(
            "\(domain)\(board.boardID.uuidString.lowercased())".utf8
        )))
        let state = try SignedGroupStateV2.initial(
            groupId: board.groupID, creator: creator,
            creatorAdmission: admission, metadataDigest: metadata,
            providerGenesisDigest: try XCTUnwrap(prepared.providerCommitDigest),
            signingKey: signingKey, signedAt: now
        )
        let acceptance = GroupCryptoAcceptedEpochV2(
            proposal: prepared.proposal,
            providerCommitDigest: try XCTUnwrap(prepared.providerCommitDigest),
            signedCommitDigest: state.commitDigest,
            acceptedTranscriptHash: state.confirmedTranscriptHash
        )
        let cryptoState = try provider.finalizePreparedEpoch(
            prepared, acceptance: acceptance
        )
        let record = GroupRuntimeRecord(
            groupId: board.groupID, localCredential: credential,
            signedState: state, cryptoState: cryptoState
        )
        let store = BoardPolicyTestStore(record: record)
        let runtime = try NoctweavePQGroupRuntimeV2(
            record: record, persistence: store
        )
        let configuration = NoctBoardConfiguration(
            boardID: board.boardID, groupID: board.groupID,
            members: [.init(
                memberHandle: owner,
                credentialHandle: credential.credentialHandle,
                role: .coordinator
            )]
        )
        return Fixture(
            runtime: runtime, store: store,
            board: board, configuration: configuration,
            owner: owner, credential: credential, now: now,
            milliseconds: Int64(now.timeIntervalSince1970 * 1_000)
        )
    }

    private func publishRoot(
        _ fixture: Fixture
    ) async throws -> (event: NoctBoardEvent, extracted: NoctBoardVerifiedExtractedEventV2) {
        let before = await fixture.runtime.snapshot()
        let frontiers = try XCTUnwrap(before.currentVerificationFrontiers())
        let order = try NoctBoardVerifiedPolicyV2.historyOrder(for: [])
        let checkpoint = NoctBoardPolicyCheckpointV2(
            kind: .snapshot, owner: fixture.owner,
            groupEpoch: before.signedState.epoch,
            groupTranscriptHash: before.signedState.confirmedTranscriptHash,
            previousCheckpointDigest: nil, frontiers: frontiers,
            precedingHistoryDigest: try NoctBoardVerifiedPolicyV2.historyDigest(order),
            precedingHistoryOrder: order
        )
        let event = NoctBoardEvent(
            schema: NoctBoardEvent.verifiedSchema,
            boardID: fixture.board.boardID, groupID: fixture.board.groupID,
            authorMemberHandle: fixture.owner,
            authorCredentialHandle: fixture.credential.credentialHandle,
            logicalClock: 0, authorSequence: 0,
            previousAuthorEventDigest: nil,
            createdAtUnixMilliseconds: fixture.milliseconds,
            operation: .policyCheckpointV2(checkpoint)
        )
        let extracted = try await publish(event, fixture: fixture, at: fixture.now)
        try await fixture.runtime.replaceProtectedApplicationEvent(
            previousEventID: nil, with: event.id,
            verificationFrontiers: frontiers
        )
        return (event, extracted)
    }

    private func publishNextSnapshot(
        _ fixture: Fixture,
        preceding: [NoctBoardEvent],
        secondOffset: Int,
        eventID: UUID = UUID(),
        inlineOrder: Bool = true
    ) async throws -> (event: NoctBoardEvent, extracted: NoctBoardVerifiedExtractedEventV2) {
        let before = await fixture.runtime.snapshot()
        let frontiers = try XCTUnwrap(before.currentVerificationFrontiers())
        let order = try NoctBoardVerifiedPolicyV2.historyOrder(for: preceding)
        let priorDigest = try NoctBoardCodec.digest(
            XCTUnwrap(preceding.last)
        )
        let checkpoint = NoctBoardPolicyCheckpointV2(
            kind: .snapshot, owner: fixture.owner,
            groupEpoch: before.signedState.epoch,
            groupTranscriptHash: before.signedState.confirmedTranscriptHash,
            previousCheckpointDigest: priorDigest, frontiers: frontiers,
            precedingHistoryDigest: try NoctBoardVerifiedPolicyV2.historyDigest(order),
            precedingHistoryOrder: inlineOrder ? order : nil
        )
        let event = NoctBoardEvent(
            schema: NoctBoardEvent.verifiedSchema,
            id: eventID,
            boardID: fixture.board.boardID, groupID: fixture.board.groupID,
            authorMemberHandle: fixture.owner,
            authorCredentialHandle: fixture.credential.credentialHandle,
            logicalClock: UInt64(secondOffset),
            authorSequence: UInt64(preceding.count),
            previousAuthorEventDigest: priorDigest,
            createdAtUnixMilliseconds: fixture.milliseconds
                + Int64(secondOffset * 1_000),
            operation: .policyCheckpointV2(checkpoint)
        )
        let extracted = try await publish(
            event, fixture: fixture,
            at: fixture.now.addingTimeInterval(TimeInterval(secondOffset))
        )
        return (event, extracted)
    }

    private func publish(
        _ event: NoctBoardEvent,
        fixture: Fixture,
        at date: Date
    ) async throws -> NoctBoardVerifiedExtractedEventV2 {
        let eventBytes = try NoctBoardCodec.encode(event)
        let signed = NoctBoardSignedEventRecord(
            eventBytes: eventBytes,
            authorSignature: try fixture.credential.signingKey.sign(
                NoctBoardClient.eventSignaturePayload(eventBytes)
            )
        )
        let bytes = try NoctweaveCoder.encode(signed, sortedKeys: true)
        let outer = GroupConversationEventV2(
            id: event.id, clientTransactionID: event.clientTransactionID,
            groupID: event.groupID,
            authorMemberHandle: event.authorMemberHandle,
            authorCredentialHandle: event.authorCredentialHandle,
            createdAt: date, kind: .application,
            content: EncodedContent(
                type: NoctBoardClient.contentType, parameters: [:],
                payload: bytes, fallbackText: nil, disposition: .silent
            )
        )
        _ = try await fixture.runtime.prepareApplicationEvent(outer, at: date)
        try await fixture.runtime.markApplicationPublished(eventID: event.id)
        return NoctBoardVerifiedExtractedEventV2(
            event: event, signedRecordBytes: bytes,
            directOuterEventID: event.id, historyOuterEventID: nil
        )
    }
}

private actor BoardPolicyTestStore: @preconcurrency GroupRuntimeRecordPersistence {
    private var record: GroupRuntimeRecord?

    init(record: GroupRuntimeRecord) { self.record = record }

    func load() -> GroupRuntimeRecord? { record }
    func save(_ record: GroupRuntimeRecord) throws { self.record = record }
}
