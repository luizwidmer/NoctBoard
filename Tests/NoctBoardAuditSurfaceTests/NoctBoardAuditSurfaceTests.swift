// SPDX-FileCopyrightText: 2026 Luiz Widmer
// SPDX-License-Identifier: AGPL-3.0-or-later

import Foundation
import NoctBoardCore
import NoctweaveCore
import XCTest
@testable import NoctBoardTransport
@testable import NoctBoardUI

final class NoctBoardAuditSurfaceTests: XCTestCase {
    func testImporterAcceptsExactAuditWithContainerAndHistoryEvidence() throws {
        let fixture = try makeFixture()
        let data = try NoctBoardAuditExporter.jsonLines(
            for: fixture.result,
            containerRejections: [
                .init(groupEventID: UUID(), reason: "invalidAuthorSignature"),
            ],
            historyAttestations: [
                .init(
                    groupEventID: UUID(),
                    reassertedEventID: fixture.event.id,
                    assertedByMemberHandle: fixture.member.memberHandle,
                    assertedByCredentialHandle: fixture.member.credentialHandle
                ),
            ]
        )

        let inspected = NoctBoardImportedAudit.inspect(
            data: data,
            sourceURL: URL(fileURLWithPath: "/tmp/noctboard-audit-surface.jsonl")
        )
        XCTAssertTrue(inspected.isStructurallyConsistent, inspected.errors.joined(separator: "\n"))
        XCTAssertEqual(inspected.acceptedCount, 1)
        XCTAssertEqual(inspected.containerRejectedCount, 1)
        XCTAssertEqual(inspected.historyAttestationCount, 1)
    }

    func testImporterRejectsPlaintextOrExtraHeaderFields() throws {
        let fixture = try makeFixture()
        let valid = try NoctBoardAuditExporter.jsonLines(for: fixture.result)
        var lines = valid.split(separator: UInt8(0x0A)).map { Data($0) }
        var header = try XCTUnwrap(
            JSONSerialization.jsonObject(with: lines[0]) as? [String: Any]
        )
        header["body"] = "must never be accepted"
        lines[0] = try JSONSerialization.data(withJSONObject: header, options: [.sortedKeys])
        let tampered = lines.reduce(into: Data()) { output, line in
            output.append(line)
            output.append(0x0A)
        }

        let inspected = NoctBoardImportedAudit.inspect(
            data: tampered,
            sourceURL: URL(fileURLWithPath: "/tmp/noctboard-audit-tampered.jsonl")
        )
        XCTAssertFalse(inspected.isStructurallyConsistent)
        XCTAssertTrue(inspected.errors.contains { $0.contains("projection plaintext") })
        XCTAssertTrue(inspected.errors.contains { $0.contains("outside its v1 shape") })
    }

    func testImporterRejectsDanglingHistoryAttestationAndUnknownContainerReason() throws {
        let fixture = try makeFixture()
        let data = try NoctBoardAuditExporter.jsonLines(
            for: fixture.result,
            containerRejections: [.init(groupEventID: UUID(), reason: "futureReason")],
            historyAttestations: [
                .init(
                    groupEventID: UUID(),
                    reassertedEventID: UUID(),
                    assertedByMemberHandle: fixture.member.memberHandle,
                    assertedByCredentialHandle: fixture.member.credentialHandle
                ),
            ]
        )

        let inspected = NoctBoardImportedAudit.inspect(
            data: data,
            sourceURL: URL(fileURLWithPath: "/tmp/noctboard-audit-invalid-evidence.jsonl")
        )
        XCTAssertFalse(inspected.isStructurallyConsistent)
        XCTAssertTrue(inspected.errors.contains { $0.contains("unsupported reason") })
        XCTAssertTrue(inspected.errors.contains { $0.contains("absent from the ledger") })
    }

    func testImporterRejectsArbitraryOperationTypeAndNoncanonicalRecords() throws {
        let fixture = try makeFixture()
        let valid = try NoctBoardAuditExporter.jsonLines(for: fixture.result)
        var lines = valid.split(separator: UInt8(0x0A)).map { Data($0) }
        var eventRecord = try XCTUnwrap(
            JSONSerialization.jsonObject(with: lines[1]) as? [String: Any]
        )
        var entry = try XCTUnwrap(eventRecord["entry"] as? [String: Any])
        entry["operationType"] = "secret board text disguised as a type"
        eventRecord["entry"] = entry
        lines[1] = try JSONSerialization.data(
            withJSONObject: eventRecord,
            options: [.sortedKeys, .withoutEscapingSlashes]
        )
        let forgedType = lines.reduce(into: Data()) { output, line in
            output.append(line)
            output.append(0x0A)
        }
        let typeInspection = NoctBoardImportedAudit.inspect(
            data: forgedType,
            sourceURL: URL(fileURLWithPath: "/tmp/noctboard-audit-forged-type.jsonl")
        )
        XCTAssertFalse(typeInspection.isStructurallyConsistent)
        XCTAssertTrue(typeInspection.errors.contains { $0.contains("unsupported operation type") })

        var noncanonicalLines = valid.split(separator: UInt8(0x0A)).map { Data($0) }
        noncanonicalLines[1].insert(0x20, at: 0)
        let noncanonical = noncanonicalLines.reduce(into: Data()) { output, line in
            output.append(line)
            output.append(0x0A)
        }
        let canonicalInspection = NoctBoardImportedAudit.inspect(
            data: noncanonical,
            sourceURL: URL(fileURLWithPath: "/tmp/noctboard-audit-noncanonical.jsonl")
        )
        XCTAssertFalse(canonicalInspection.isStructurallyConsistent)
        XCTAssertTrue(canonicalInspection.errors.contains { $0.contains("not canonical JSON") })
    }

    @MainActor
    func testAuditConsoleLabelsInjectedClientSnapshotAsLiveAndKeepsProvenance() throws {
        let fixture = try makeFixture()
        let board = try NoctBoardReference(id: fixture.result.projection.boardID)
        let history = NoctBoardHistoryBootstrapProvenance(
            groupEventID: UUID(),
            reassertedEventID: fixture.event.id,
            assertedByMemberHandle: fixture.member.memberHandle,
            assertedByCredentialHandle: fixture.member.credentialHandle
        )
        let snapshot = NoctBoardClientSnapshot(
            board: board,
            groupEpoch: 2,
            localMemberHandle: fixture.member.memberHandle,
            localCredentialHandle: fixture.member.credentialHandle,
            events: [fixture.event],
            historyBootstrapProvenance: [history],
            containerRejections: [
                .init(groupEventID: UUID(), reason: .invalidAuthorSignature),
            ],
            result: fixture.result
        )

        let model = NoctBoardAuditConsoleModel()
        model.apply(snapshot)
        XCTAssertEqual(
            model.source,
            .liveLocal(
                boardID: board.boardID,
                groupEpoch: 2,
                eventCount: 1,
                containerRejectionCount: 1
            )
        )
        XCTAssertEqual(model.historyBootstrapProvenance, [history])
        XCTAssertEqual(model.containerRejections.count, 1)
    }

    private func makeFixture() throws -> (
        result: NoctBoardProjectionResult,
        event: NoctBoardEvent,
        member: NoctBoardMemberAuthorization
    ) {
        let boardID = UUID()
        let member = NoctBoardMemberAuthorization(
            memberHandle: .generate(),
            credentialHandle: .generate(),
            role: .coordinator
        )
        let event = NoctBoardEvent(
            boardID: boardID,
            groupID: boardID,
            authorMemberHandle: member.memberHandle,
            authorCredentialHandle: member.credentialHandle,
            logicalClock: 0,
            authorSequence: 0,
            previousAuthorEventDigest: nil,
            createdAtUnixMilliseconds: 1_800_000_000_000,
            operation: .createThread(.init(title: "Sensitive title"))
        )
        let result = try NoctBoardProjector.project(
            events: [event],
            configuration: NoctBoardConfiguration(
                boardID: boardID,
                groupID: boardID,
                members: [member]
            )
        )
        return (result, event, member)
    }
}
