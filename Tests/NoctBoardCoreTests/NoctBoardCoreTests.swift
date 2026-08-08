// SPDX-FileCopyrightText: 2026 Luiz Widmer
// SPDX-License-Identifier: AGPL-3.0-or-later

import Foundation
import NoctweaveCore
import XCTest
@testable import NoctBoardCore

final class NoctBoardCoreTests: XCTestCase {
    func testConfigurationRequiresOneBoardToEqualOneGroup() {
        let fixture = Fixture()
        let mismatched = NoctBoardConfiguration(
            boardID: fixture.boardID,
            groupID: UUID(),
            members: [fixture.coordinator]
        )

        XCTAssertFalse(mismatched.isStructurallyValid)
    }

    func testProjectionRefusesHistoryBeyondReplaySafeWindow() throws {
        let fixture = Fixture()
        let event = try fixture.event(
            author: fixture.coordinator,
            logicalClock: 0,
            authorSequence: 0,
            operation: .createThread(.init(title: "anchor"))
        )

        XCTAssertThrowsError(try NoctBoardProjector.project(
            events: Array(repeating: event, count: NoctBoardLimits.maximumBoardEvents + 1),
            configuration: fixture.configuration
        )) {
            XCTAssertEqual($0 as? NoctBoardProjectionError, .eventLimitExceeded)
        }
    }

    func testCodecIsCanonicalStrictAndBounded() throws {
        let fixture = Fixture()
        let event = try fixture.event(
            author: fixture.coordinator,
            logicalClock: 1,
            authorSequence: 0,
            operation: .createThread(.init(title: "Coordination"))
        )

        let encoded = try NoctBoardCodec.encode(event)
        XCTAssertTrue(NoctweaveCanonicalJSON.isCanonical(encoded))
        XCTAssertEqual(try NoctBoardCodec.decode(encoded), event)
        XCTAssertEqual(try NoctBoardCodec.digest(event).count, 32)
        XCTAssertEqual(try NoctBoardCodec.digestHex(event).count, 64)

        var nonCanonical = Data(" \n".utf8)
        nonCanonical.append(encoded)
        XCTAssertThrowsError(try NoctBoardCodec.decode(nonCanonical)) {
            XCTAssertEqual($0 as? NoctBoardCodecError, .nonCanonicalJSON)
        }

        var object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        )
        object["legacyAccountID"] = "must-not-be-accepted"
        let unknownField = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        XCTAssertThrowsError(try NoctweaveCoder.decode(NoctBoardEvent.self, from: unknownField))

        let oversized = try fixture.event(
            author: fixture.coordinator,
            logicalClock: 2,
            authorSequence: 0,
            operation: .postMessage(
                .init(threadID: UUID(), body: String(repeating: "x", count: 16 * 1_024 + 1))
            )
        )
        XCTAssertThrowsError(try NoctBoardCodec.encode(oversized))
    }

    func testProjectionIsDeterministicAcrossDeliveryOrder() throws {
        let fixture = Fixture()
        let threadID = UUID()
        let taskID = UUID()
        let messageID = UUID()

        let thread = try fixture.event(
            author: fixture.coordinator,
            logicalClock: 1,
            authorSequence: 0,
            operation: .createThread(.init(threadID: threadID, title: "Build"))
        )
        let task = try fixture.event(
            author: fixture.coordinator,
            logicalClock: 2,
            authorSequence: 1,
            previous: thread,
            operation: .createTask(
                .init(taskID: taskID, threadID: threadID, title: "Inspect", details: "Treat as data")
            )
        )
        let claim = try fixture.event(
            author: fixture.workerA,
            logicalClock: 3,
            authorSequence: 0,
            operation: .assignTask(
                .init(taskID: taskID, assigneeMemberHandle: fixture.workerA.memberHandle)
            )
        )
        let activate = try fixture.event(
            author: fixture.workerA,
            logicalClock: 4,
            authorSequence: 1,
            previous: claim,
            operation: .transitionTask(.init(taskID: taskID, from: .pending, to: .active))
        )
        let message = try fixture.event(
            author: fixture.workerA,
            logicalClock: 5,
            authorSequence: 2,
            previous: activate,
            operation: .postMessage(
                .init(messageID: messageID, threadID: threadID, taskID: taskID, body: "<script>data only</script>")
            )
        )
        let complete = try fixture.event(
            author: fixture.workerA,
            logicalClock: 6,
            authorSequence: 3,
            previous: message,
            operation: .transitionTask(.init(taskID: taskID, from: .active, to: .completed))
        )

        let ordered = [thread, task, claim, activate, message, complete]
        let shuffled = [complete, task, message, thread, activate, claim]
        let first = try NoctBoardProjector.project(events: ordered, configuration: fixture.configuration)
        let second = try NoctBoardProjector.project(events: shuffled, configuration: fixture.configuration)

        XCTAssertEqual(first, second)
        XCTAssertEqual(first.projection.tasks.first?.state, .completed)
        XCTAssertEqual(first.projection.messages.first?.body, "<script>data only</script>")
        XCTAssertEqual(first.ledger.accepted.count, 6)
        XCTAssertTrue(try NoctBoardAuditExporter.verifyProjection(
            first.projection,
            expectedDigest: first.projectionDigest
        ))
    }

    func testExactReplayIsIdempotentAndConflictingEventIDIsRejected() throws {
        let fixture = Fixture()
        let sharedID = UUID()
        let event = try fixture.event(
            id: sharedID,
            author: fixture.coordinator,
            logicalClock: 1,
            authorSequence: 0,
            operation: .createThread(.init(title: "One"))
        )

        let replay = try NoctBoardProjector.project(
            events: [event, event],
            configuration: fixture.configuration
        )
        XCTAssertEqual(replay.projection.threads.count, 1)
        XCTAssertEqual(replay.ledger.accepted.count, 1)
        XCTAssertEqual(replay.ledger.replayed.count, 1)

        let conflict = try fixture.event(
            id: sharedID,
            author: fixture.coordinator,
            logicalClock: 1,
            authorSequence: 0,
            operation: .createThread(.init(title: "Two"))
        )
        let left = try NoctBoardProjector.project(
            events: [event, conflict],
            configuration: fixture.configuration
        )
        let right = try NoctBoardProjector.project(
            events: [conflict, event],
            configuration: fixture.configuration
        )
        XCTAssertEqual(left, right)
        XCTAssertEqual(left.ledger.rejected.map(\.rejectionReason), [.eventIDConflict])
    }

    func testCrossBoardUnknownCredentialAndAuditorWritesAreRejected() throws {
        let fixture = Fixture()
        let threadID = UUID()
        let crossBoard = try fixture.event(
            author: fixture.coordinator,
            logicalClock: 0,
            authorSequence: 0,
            boardID: UUID(),
            operation: .createThread(.init(title: "foreign"))
        )
        let wrongCredential = try fixture.event(
            author: fixture.coordinator,
            credentialOverride: fixture.workerA.credentialHandle,
            logicalClock: 0,
            authorSequence: 0,
            operation: .createThread(.init(title: "spoofed"))
        )
        let thread = try fixture.event(
            author: fixture.coordinator,
            logicalClock: 1,
            authorSequence: 0,
            operation: .createThread(.init(threadID: threadID, title: "valid"))
        )
        let auditorWrite = try fixture.event(
            author: fixture.auditor,
            logicalClock: 2,
            authorSequence: 0,
            operation: .postMessage(.init(threadID: threadID, body: "cannot write"))
        )

        let result = try NoctBoardProjector.project(
            events: [thread, crossBoard, wrongCredential, auditorWrite],
            configuration: fixture.configuration
        )
        XCTAssertEqual(result.projection.threads.count, 1)
        XCTAssertEqual(Set(result.ledger.rejected.compactMap(\.rejectionReason)), [
            .boardBindingMismatch,
            .credentialBindingMismatch,
            .unauthorized,
        ])
    }

    func testHostileLogicalClockJumpIsRejectedWithoutPoisoningLaterWork() throws {
        let fixture = Fixture()
        let threadID = UUID()
        let first = try fixture.event(
            author: fixture.coordinator,
            logicalClock: 0,
            authorSequence: 0,
            operation: .createThread(.init(threadID: threadID, title: "anchor"))
        )
        let poison = NoctBoardEvent(
            boardID: fixture.boardID,
            groupID: fixture.groupID,
            authorMemberHandle: fixture.workerA.memberHandle,
            authorCredentialHandle: fixture.workerA.credentialHandle,
            logicalClock: NoctBoardLimits.maximumLogicalInteger,
            authorSequence: 0,
            previousAuthorEventDigest: nil,
            createdAtUnixMilliseconds: 1_800_000_000_500,
            operation: .postMessage(.init(threadID: UUID(), body: "poison"))
        )
        let later = try fixture.event(
            author: fixture.coordinator,
            logicalClock: 1,
            authorSequence: 1,
            previous: first,
            operation: .createThread(.init(title: "still writable"))
        )

        let result = try NoctBoardProjector.project(
            events: [poison, later, first],
            configuration: fixture.configuration
        )

        XCTAssertEqual(result.ledger.accepted.count, 2)
        XCTAssertEqual(result.ledger.rejected.map(\.rejectionReason), [.logicalClockGap])
        XCTAssertEqual(result.ledger.rejected.map(\.authorChainConsumed), [false])
        XCTAssertTrue(result.ledger.accepted.allSatisfy(\.authorChainConsumed))
        XCTAssertEqual(result.projection.threads.count, 2)
        let audit = try NoctBoardAuditExporter.jsonLines(for: result)
        XCTAssertNotNil(audit.range(of: Data("logicalClockGap".utf8)))

        let workerRecovery = try fixture.event(
            author: fixture.workerA,
            logicalClock: 2,
            authorSequence: 0,
            operation: .postMessage(.init(threadID: threadID, body: "recovered"))
        )
        let final = try NoctBoardProjector.project(
            events: [poison, workerRecovery, later, first],
            configuration: fixture.configuration
        )
        XCTAssertEqual(
            final.ledger.entries.last { $0.eventID == poison.id }?.rejectionReason,
            .authorSequenceConflict
        )
        let finalAudit = try NoctBoardAuditExporter.jsonLines(for: final)
        XCTAssertNotNil(finalAudit.range(of: Data(poison.id.uuidString.utf8)))
        XCTAssertNotNil(finalAudit.range(of: Data("authorSequenceConflict".utf8)))
    }

    func testAuthorChainGapsAndDigestMismatchesAreAudited() throws {
        let fixture = Fixture()
        let gap = try fixture.event(
            author: fixture.workerA,
            logicalClock: 1,
            authorSequence: 1,
            previousDigestOverride: Data(repeating: 0xAA, count: 32),
            operation: .postMessage(.init(threadID: UUID(), body: "gap"))
        )
        let first = try fixture.event(
            author: fixture.coordinator,
            logicalClock: 2,
            authorSequence: 0,
            operation: .createThread(.init(title: "first"))
        )
        let mismatch = try fixture.event(
            author: fixture.coordinator,
            logicalClock: 3,
            authorSequence: 1,
            previousDigestOverride: Data(repeating: 0xBB, count: 32),
            operation: .closeThread(.init(threadID: UUID()))
        )

        let result = try NoctBoardProjector.project(
            events: [mismatch, gap, first],
            configuration: fixture.configuration
        )
        XCTAssertEqual(result.ledger.rejected.compactMap(\.rejectionReason), [
            .authorSequenceGap,
            .authorChainMismatch,
        ])
        XCTAssertEqual(result.ledger.entries.last?.authorSequence, 1)
        XCTAssertEqual(result.ledger.entries.last?.previousAuthorEventDigest, String(repeating: "bb", count: 32))
    }

    func testWorkerCanAtomicallyClaimButCompetingClaimIsRejected() throws {
        let fixture = Fixture()
        let threadID = UUID()
        let taskID = UUID()
        let thread = try fixture.event(
            author: fixture.coordinator,
            logicalClock: 1,
            authorSequence: 0,
            operation: .createThread(.init(threadID: threadID, title: "Claims"))
        )
        let task = try fixture.event(
            author: fixture.coordinator,
            logicalClock: 2,
            authorSequence: 1,
            previous: thread,
            operation: .createTask(.init(taskID: taskID, threadID: threadID, title: "Only one"))
        )
        let firstClaim = try fixture.event(
            author: fixture.workerA,
            logicalClock: 3,
            authorSequence: 0,
            operation: .assignTask(
                .init(taskID: taskID, assigneeMemberHandle: fixture.workerA.memberHandle)
            )
        )
        let competingClaim = try fixture.event(
            author: fixture.workerB,
            logicalClock: 4,
            authorSequence: 0,
            operation: .assignTask(
                .init(taskID: taskID, assigneeMemberHandle: fixture.workerB.memberHandle)
            )
        )

        let result = try NoctBoardProjector.project(
            events: [competingClaim, task, firstClaim, thread],
            configuration: fixture.configuration
        )
        XCTAssertEqual(result.projection.tasks.first?.assigneeMemberHandle, fixture.workerA.memberHandle)
        XCTAssertEqual(result.ledger.rejected.map(\.rejectionReason), [.taskAlreadyAssigned])
    }

    func testTaskTransitionsEnforceAssigneeExpectedStateAndCoordinatorAuthority() throws {
        let fixture = Fixture()
        let threadID = UUID()
        let taskID = UUID()
        let thread = try fixture.event(
            author: fixture.coordinator,
            logicalClock: 1,
            authorSequence: 0,
            operation: .createThread(.init(threadID: threadID, title: "Transitions"))
        )
        let task = try fixture.event(
            author: fixture.coordinator,
            logicalClock: 2,
            authorSequence: 1,
            previous: thread,
            operation: .createTask(
                .init(
                    taskID: taskID,
                    threadID: threadID,
                    title: "Bound worker",
                    assigneeMemberHandle: fixture.workerA.memberHandle
                )
            )
        )
        let wrongWorker = try fixture.event(
            author: fixture.workerB,
            logicalClock: 3,
            authorSequence: 0,
            operation: .transitionTask(.init(taskID: taskID, from: .pending, to: .active))
        )
        let activate = try fixture.event(
            author: fixture.workerA,
            logicalClock: 4,
            authorSequence: 0,
            operation: .transitionTask(.init(taskID: taskID, from: .pending, to: .active))
        )
        let stale = try fixture.event(
            author: fixture.workerA,
            logicalClock: 5,
            authorSequence: 1,
            previous: activate,
            operation: .transitionTask(.init(taskID: taskID, from: .pending, to: .active))
        )
        let cancel = try fixture.event(
            author: fixture.coordinator,
            logicalClock: 6,
            authorSequence: 2,
            previous: task,
            operation: .transitionTask(.init(taskID: taskID, from: .active, to: .cancelled))
        )

        let result = try NoctBoardProjector.project(
            events: [stale, cancel, wrongWorker, task, activate, thread],
            configuration: fixture.configuration
        )
        XCTAssertEqual(result.projection.tasks.first?.state, .cancelled)
        XCTAssertEqual(result.ledger.rejected.compactMap(\.rejectionReason), [
            .unauthorized,
            .staleTaskState,
        ])
    }

    func testThreadCannotCloseUntilEveryTaskIsTerminal() throws {
        let fixture = Fixture()
        let threadID = UUID()
        let taskID = UUID()
        let thread = try fixture.event(
            author: fixture.coordinator,
            logicalClock: 1,
            authorSequence: 0,
            operation: .createThread(.init(threadID: threadID, title: "Close safely"))
        )
        let task = try fixture.event(
            author: fixture.coordinator,
            logicalClock: 2,
            authorSequence: 1,
            previous: thread,
            operation: .createTask(.init(taskID: taskID, threadID: threadID, title: "Finish me"))
        )
        let prematureClose = try fixture.event(
            author: fixture.coordinator,
            logicalClock: 3,
            authorSequence: 2,
            previous: task,
            operation: .closeThread(.init(threadID: threadID))
        )

        let rejected = try NoctBoardProjector.project(
            events: [prematureClose, task, thread],
            configuration: fixture.configuration
        )
        XCTAssertFalse(try XCTUnwrap(rejected.projection.threads.first).isClosed)
        XCTAssertEqual(rejected.ledger.rejected.map(\.rejectionReason), [.threadHasOpenTasks])

        let cancel = try fixture.event(
            author: fixture.coordinator,
            logicalClock: 3,
            authorSequence: 2,
            previous: task,
            operation: .transitionTask(.init(taskID: taskID, from: .pending, to: .cancelled))
        )
        let safeClose = try fixture.event(
            author: fixture.coordinator,
            logicalClock: 4,
            authorSequence: 3,
            previous: cancel,
            operation: .closeThread(.init(threadID: threadID))
        )
        let accepted = try NoctBoardProjector.project(
            events: [safeClose, task, thread, cancel],
            configuration: fixture.configuration
        )
        XCTAssertTrue(try XCTUnwrap(accepted.projection.threads.first).isClosed)
        XCTAssertEqual(accepted.ledger.rejected.count, 0)
    }

    func testWorkerWithOpenAssignmentCannotBecomeNonWorker() throws {
        let fixture = Fixture()
        let threadID = UUID()
        let taskID = UUID()
        let thread = try fixture.event(
            author: fixture.coordinator,
            logicalClock: 1,
            authorSequence: 0,
            operation: .createThread(.init(threadID: threadID, title: "Role safety"))
        )
        let task = try fixture.event(
            author: fixture.coordinator,
            logicalClock: 2,
            authorSequence: 1,
            previous: thread,
            operation: .createTask(.init(
                taskID: taskID,
                threadID: threadID,
                title: "Assigned work",
                assigneeMemberHandle: fixture.workerA.memberHandle
            ))
        )
        let roleChange = try fixture.event(
            author: fixture.coordinator,
            logicalClock: 3,
            authorSequence: 2,
            previous: task,
            operation: .setRole(.init(
                memberHandle: fixture.workerA.memberHandle,
                role: .auditor
            ))
        )

        let result = try NoctBoardProjector.project(
            events: [roleChange, task, thread],
            configuration: fixture.configuration
        )
        XCTAssertEqual(result.ledger.rejected.map(\.rejectionReason), [.memberHasOpenTasks])
        XCTAssertEqual(
            result.projection.members.first {
                $0.memberHandle == fixture.workerA.memberHandle
            }?.role,
            .worker
        )
    }

    func testRoleChangesAreAuditedAndLastCoordinatorCannotBeDemoted() throws {
        let fixture = Fixture()
        let promote = try fixture.event(
            author: fixture.coordinator,
            logicalClock: 1,
            authorSequence: 0,
            operation: .setRole(.init(memberHandle: fixture.auditor.memberHandle, role: .coordinator))
        )
        let demoteOriginal = try fixture.event(
            author: fixture.coordinator,
            logicalClock: 2,
            authorSequence: 1,
            previous: promote,
            operation: .setRole(.init(memberHandle: fixture.coordinator.memberHandle, role: .auditor))
        )
        let demoteLast = try fixture.event(
            author: fixture.auditor,
            logicalClock: 3,
            authorSequence: 0,
            operation: .setRole(.init(memberHandle: fixture.auditor.memberHandle, role: .worker))
        )

        let result = try NoctBoardProjector.project(
            events: [demoteLast, promote, demoteOriginal],
            configuration: fixture.configuration
        )
        XCTAssertEqual(result.ledger.accepted.count, 2)
        XCTAssertEqual(result.ledger.rejected.map(\.rejectionReason), [.lastCoordinator])
        XCTAssertEqual(
            result.projection.members.first { $0.memberHandle == fixture.auditor.memberHandle }?.role,
            .coordinator
        )
    }

    func testAuditJSONLIsDeterministicAndRedactsPayloadText() throws {
        let fixture = Fixture()
        let secretMarker = "MESSAGE-BODY-MUST-NOT-ENTER-AUDIT"
        let threadID = UUID()
        let thread = try fixture.event(
            author: fixture.coordinator,
            logicalClock: 1,
            authorSequence: 0,
            operation: .createThread(.init(threadID: threadID, title: "Sensitive title"))
        )
        let message = try fixture.event(
            author: fixture.workerA,
            logicalClock: 2,
            authorSequence: 0,
            operation: .postMessage(.init(threadID: threadID, body: secretMarker))
        )
        let result = try NoctBoardProjector.project(
            events: [message, thread],
            configuration: fixture.configuration
        )

        let quarantine = NoctBoardAuditContainerRejection(
            groupEventID: UUID(),
            reason: "envelopeBindingMismatch"
        )
        let attestation = NoctBoardAuditHistoryAttestation(
            groupEventID: UUID(),
            reassertedEventID: thread.id,
            assertedByMemberHandle: fixture.coordinator.memberHandle,
            assertedByCredentialHandle: fixture.coordinator.credentialHandle
        )
        let first = try NoctBoardAuditExporter.jsonLines(
            for: result,
            containerRejections: [quarantine],
            historyAttestations: [attestation]
        )
        let second = try NoctBoardAuditExporter.jsonl(
            for: result,
            containerRejections: [quarantine],
            historyAttestations: [attestation]
        )
        XCTAssertEqual(first, second)
        let string = try XCTUnwrap(String(data: first, encoding: .utf8))
        XCTAssertTrue(string.hasSuffix("\n"))
        XCTAssertFalse(string.contains(secretMarker))
        XCTAssertFalse(string.contains("Sensitive title"))
        XCTAssertTrue(string.contains("containerRejection"))
        XCTAssertTrue(string.contains("envelopeBindingMismatch"))
        XCTAssertTrue(string.contains("historyAttestation"))
        XCTAssertTrue(string.contains("\"containerRejectedCount\":1"))
        XCTAssertTrue(string.contains("\"historyAttestationCount\":1"))
        XCTAssertEqual(string.split(separator: "\n").count, result.ledger.entries.count + 4)
    }
}

private struct Fixture {
    let boardID = UUID()
    var groupID: UUID { boardID }
    let coordinator = NoctBoardMemberAuthorization(
        memberHandle: .generate(),
        credentialHandle: .generate(),
        role: .coordinator
    )
    let workerA = NoctBoardMemberAuthorization(
        memberHandle: .generate(),
        credentialHandle: .generate(),
        role: .worker
    )
    let workerB = NoctBoardMemberAuthorization(
        memberHandle: .generate(),
        credentialHandle: .generate(),
        role: .worker
    )
    let auditor = NoctBoardMemberAuthorization(
        memberHandle: .generate(),
        credentialHandle: .generate(),
        role: .auditor
    )

    var configuration: NoctBoardConfiguration {
        NoctBoardConfiguration(
            boardID: boardID,
            groupID: groupID,
            members: [coordinator, workerA, workerB, auditor]
        )
    }

    func event(
        id: UUID = UUID(),
        author: NoctBoardMemberAuthorization,
        credentialOverride: GroupScopedCredentialHandleV2? = nil,
        logicalClock: UInt64,
        authorSequence: UInt64,
        previous: NoctBoardEvent? = nil,
        previousDigestOverride: Data? = nil,
        boardID boardOverride: UUID? = nil,
        groupID groupOverride: UUID? = nil,
        operation: NoctBoardOperation
    ) throws -> NoctBoardEvent {
        let previousDigest: Data?
        if let previousDigestOverride {
            previousDigest = previousDigestOverride
        } else if let previous {
            previousDigest = try NoctBoardCodec.digest(previous)
        } else {
            previousDigest = nil
        }
        return NoctBoardEvent(
            id: id,
            clientTransactionID: UUID(),
            boardID: boardOverride ?? boardID,
            groupID: groupOverride ?? groupID,
            authorMemberHandle: author.memberHandle,
            authorCredentialHandle: credentialOverride ?? author.credentialHandle,
            logicalClock: logicalClock,
            authorSequence: authorSequence,
            previousAuthorEventDigest: previousDigest,
            createdAtUnixMilliseconds: 1_800_000_000_000 + Int64(logicalClock),
            operation: operation
        )
    }
}
