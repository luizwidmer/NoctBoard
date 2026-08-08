// SPDX-FileCopyrightText: 2026 Luiz Widmer
// SPDX-License-Identifier: AGPL-3.0-or-later

import CryptoKit
import Foundation
import NoctweaveCore

private struct NoctBoardAuditHeader: Codable {
    let recordType: String
    let schema: String
    let boardID: UUID
    let groupID: UUID
}

private struct NoctBoardAuditEventRecord: Codable {
    let recordType: String
    let entry: NoctBoardLedgerEntry
}

public struct NoctBoardAuditContainerRejection: Codable, Equatable, Sendable {
    public let groupEventID: UUID
    public let reason: String

    public init(groupEventID: UUID, reason: String) {
        self.groupEventID = groupEventID
        self.reason = reason
    }
}

private struct NoctBoardAuditContainerRejectionRecord: Codable {
    let recordType: String
    let entry: NoctBoardAuditContainerRejection
}

/// Declares that a late-joining endpoint learned an exact canonical event from
/// a new-epoch wrapper authenticated by the immutable genesis owner. It does
/// not claim that the late joiner verified the event's original outer group
/// envelope or original-author signature.
public struct NoctBoardAuditHistoryAttestation: Codable, Equatable, @unchecked Sendable {
    public let groupEventID: UUID
    public let reassertedEventID: UUID
    public let assertedByMemberHandle: GroupScopedMemberHandleV2
    public let assertedByCredentialHandle: GroupScopedCredentialHandleV2

    public init(
        groupEventID: UUID,
        reassertedEventID: UUID,
        assertedByMemberHandle: GroupScopedMemberHandleV2,
        assertedByCredentialHandle: GroupScopedCredentialHandleV2
    ) {
        self.groupEventID = groupEventID
        self.reassertedEventID = reassertedEventID
        self.assertedByMemberHandle = assertedByMemberHandle
        self.assertedByCredentialHandle = assertedByCredentialHandle
    }
}

private struct NoctBoardAuditHistoryAttestationRecord: Codable {
    let recordType: String
    let entry: NoctBoardAuditHistoryAttestation
}

private struct NoctBoardAuditSummary: Codable {
    let recordType: String
    let acceptedCount: Int
    let replayedCount: Int
    let rejectedCount: Int
    let containerRejectedCount: Int
    let historyAttestationCount: Int
    let projectionDigest: String
}

/// Produces a text-redacted decision trail plus a digest of the human-readable
/// projection. Message bodies remain in the local projection and are never
/// copied into the ledger export. Handles, decisions, metadata, and unkeyed
/// digests remain sensitive and can support offline confirmation of guessed
/// low-entropy board text.
public enum NoctBoardAuditExporter {
    public static let schema = "org.noctboard/audit:1.0"

    public static func projectionDigest(for projection: NoctBoardProjection) throws -> String {
        let canonical = try NoctweaveCoder.encode(projection, sortedKeys: true)
        return Data(SHA256.hash(data: canonical))
            .map { String(format: "%02x", $0) }
            .joined()
    }

    public static func verifyProjection(
        _ projection: NoctBoardProjection,
        expectedDigest: String
    ) throws -> Bool {
        guard expectedDigest.count == 64,
              expectedDigest.utf8.allSatisfy({
                  (0x30 ... 0x39).contains($0) || (0x61 ... 0x66).contains($0)
              }) else {
            return false
        }
        return try projectionDigest(for: projection) == expectedDigest
    }

    /// Canonical JSON Lines with a trailing newline. Its bytes are stable for a
    /// given result and contain no message/task/thread text.
    public static func jsonLines(
        for result: NoctBoardProjectionResult,
        containerRejections: [NoctBoardAuditContainerRejection] = [],
        historyAttestations: [NoctBoardAuditHistoryAttestation] = []
    ) throws -> Data {
        var output = Data()
        try append(
            NoctBoardAuditHeader(
                recordType: "header",
                schema: schema,
                boardID: result.projection.boardID,
                groupID: result.projection.groupID
            ),
            to: &output
        )
        for entry in result.ledger.entries {
            try append(
                NoctBoardAuditEventRecord(recordType: "event", entry: entry),
                to: &output
            )
        }
        for rejection in containerRejections.sorted(by: containerRejectionOrder) {
            try append(
                NoctBoardAuditContainerRejectionRecord(
                    recordType: "containerRejection",
                    entry: rejection
                ),
                to: &output
            )
        }
        for attestation in historyAttestations.sorted(by: historyAttestationOrder) {
            try append(
                NoctBoardAuditHistoryAttestationRecord(
                    recordType: "historyAttestation",
                    entry: attestation
                ),
                to: &output
            )
        }
        try append(
            NoctBoardAuditSummary(
                recordType: "summary",
                acceptedCount: result.ledger.accepted.count,
                replayedCount: result.ledger.replayed.count,
                rejectedCount: result.ledger.rejected.count,
                containerRejectedCount: containerRejections.count,
                historyAttestationCount: historyAttestations.count,
                projectionDigest: result.projectionDigest
            ),
            to: &output
        )
        return output
    }

    public static func jsonl(
        for result: NoctBoardProjectionResult,
        containerRejections: [NoctBoardAuditContainerRejection] = [],
        historyAttestations: [NoctBoardAuditHistoryAttestation] = []
    ) throws -> Data {
        try jsonLines(
            for: result,
            containerRejections: containerRejections,
            historyAttestations: historyAttestations
        )
    }

    private static func append<T: Encodable>(_ value: T, to output: inout Data) throws {
        output.append(try NoctweaveCoder.encode(value, sortedKeys: true))
        output.append(0x0A)
    }

    private static func containerRejectionOrder(
        _ left: NoctBoardAuditContainerRejection,
        _ right: NoctBoardAuditContainerRejection
    ) -> Bool {
        let leftID = left.groupEventID.uuidString.lowercased()
        let rightID = right.groupEventID.uuidString.lowercased()
        return leftID == rightID ? left.reason < right.reason : leftID < rightID
    }

    private static func historyAttestationOrder(
        _ left: NoctBoardAuditHistoryAttestation,
        _ right: NoctBoardAuditHistoryAttestation
    ) -> Bool {
        let leftEventID = left.reassertedEventID.uuidString.lowercased()
        let rightEventID = right.reassertedEventID.uuidString.lowercased()
        if leftEventID != rightEventID { return leftEventID < rightEventID }
        return left.groupEventID.uuidString.lowercased()
            < right.groupEventID.uuidString.lowercased()
    }
}
