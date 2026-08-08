// SPDX-FileCopyrightText: 2026 Luiz Widmer
// SPDX-License-Identifier: AGPL-3.0-or-later

import Darwin
import Foundation
import NoctBoardCore
import NoctweaveCore

public enum NoctBoardAuditImportError: LocalizedError {
    case cannotOpen(Int32)
    case notBoundedRegularFile
    case readFailed

    public var errorDescription: String? {
        switch self {
        case .cannotOpen(let code): "Cannot securely open the audit file (errno \(code))."
        case .notBoundedRegularFile: "Audit must be a no-follow regular file of at most 16 MiB."
        case .readFailed: "The bounded audit-file read failed."
        }
    }
}

public struct NoctBoardImportedAudit: @unchecked Sendable {
    public static let maximumBytes = 16 * 1_024 * 1_024
    public static let maximumRecords = (NoctBoardLimits.maximumBoardEvents * 2) + 2
    public static let maximumLineBytes = 64 * 1_024

    public let sourceURL: URL
    public let schema: String?
    public let boardID: UUID?
    public let groupID: UUID?
    public let entries: [NoctBoardLedgerEntry]
    public let containerRejections: [NoctBoardAuditContainerRejection]
    public let historyAttestations: [NoctBoardAuditHistoryAttestation]
    public let projectionDigest: String?
    public let acceptedCount: Int
    public let replayedCount: Int
    public let rejectedCount: Int
    public let containerRejectedCount: Int
    public let historyAttestationCount: Int
    public let isStructurallyConsistent: Bool
    public let errors: [String]

    public static func load(from sourceURL: URL) throws -> NoctBoardImportedAudit {
        let descriptor = sourceURL.withUnsafeFileSystemRepresentation { path -> Int32 in
            guard let path else { return -1 }
            return Darwin.open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        }
        guard descriptor >= 0 else { throw NoctBoardAuditImportError.cannotOpen(errno) }
        defer { Darwin.close(descriptor) }

        var status = stat()
        guard Darwin.fstat(descriptor, &status) == 0,
              (status.st_mode & S_IFMT) == S_IFREG,
              status.st_size >= 0,
              status.st_size <= maximumBytes else {
            throw NoctBoardAuditImportError.notBoundedRegularFile
        }

        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: false)
        var data = Data()
        data.reserveCapacity(min(Int(status.st_size), maximumBytes))
        do {
            while data.count <= maximumBytes {
                let allowance = min(64 * 1_024, maximumBytes + 1 - data.count)
                guard allowance > 0,
                      let chunk = try handle.read(upToCount: allowance),
                      !chunk.isEmpty else {
                    break
                }
                data.append(chunk)
            }
        } catch {
            throw NoctBoardAuditImportError.readFailed
        }
        guard data.count <= maximumBytes else {
            throw NoctBoardAuditImportError.notBoundedRegularFile
        }
        return inspect(data: data, sourceURL: sourceURL)
    }

    public static func inspect(data: Data, sourceURL: URL) -> NoctBoardImportedAudit {
        guard data.count <= maximumBytes else {
            return invalid(sourceURL, "Audit exceeds the 16-MiB inspection limit.")
        }
        let lines = data.split(separator: 0x0A, omittingEmptySubsequences: true)
        guard lines.count <= maximumRecords,
              lines.allSatisfy({ $0.count <= maximumLineBytes }) else {
            return invalid(
                sourceURL,
                "Audit exceeds the 6,002-record or 64-KiB-per-record inspection limit."
            )
        }
        let decoder = JSONDecoder()
        var errors: [String] = []
        var header: Header?
        var summary: Summary?
        var entries: [NoctBoardLedgerEntry] = []
        var containerRejections: [NoctBoardAuditContainerRejection] = []
        var historyAttestations: [NoctBoardAuditHistoryAttestation] = []
        var sawContainerRejection = false
        var sawHistoryAttestation = false

        for (offset, bytes) in lines.enumerated() {
            let line = Data(bytes)
            do {
                if !NoctweaveCanonicalJSON.isCanonical(line) {
                    errors.append("Audit record at line \(offset + 1) is not canonical JSON.")
                }
                guard let object = try JSONSerialization.jsonObject(with: line)
                    as? [String: Any] else {
                    errors.append("Audit record at line \(offset + 1) is not an object.")
                    continue
                }
                if containsProjectionPlaintext(object) {
                    errors.append("Audit record at line \(offset + 1) contains projection plaintext.")
                }
                let discriminator = try decoder.decode(Discriminator.self, from: line)
                if !hasExactShape(object, recordType: discriminator.recordType) {
                    errors.append("Audit record at line \(offset + 1) has fields outside its v1 shape.")
                }
                switch discriminator.recordType {
                case "header":
                    if offset != 0 || header != nil { errors.append("Header is not the first unique record.") }
                    header = try decoder.decode(Header.self, from: line)
                case "event":
                    if sawContainerRejection || sawHistoryAttestation {
                        errors.append("Event appears after evidence records at line \(offset + 1).")
                    }
                    let record = try decoder.decode(EventRecord.self, from: line)
                    if record.entry.order != entries.count {
                        errors.append("Ledger order is not contiguous at line \(offset + 1).")
                    }
                    entries.append(record.entry)
                case "containerRejection":
                    if sawHistoryAttestation {
                        errors.append("Container rejection appears after history attestations at line \(offset + 1).")
                    }
                    sawContainerRejection = true
                    let record = try decoder.decode(ContainerRejectionRecord.self, from: line)
                    containerRejections.append(record.entry)
                case "historyAttestation":
                    sawHistoryAttestation = true
                    let record = try decoder.decode(HistoryAttestationRecord.self, from: line)
                    historyAttestations.append(record.entry)
                case "summary":
                    if offset != lines.count - 1 || summary != nil {
                        errors.append("Summary is not the final unique record.")
                    }
                    summary = try decoder.decode(Summary.self, from: line)
                default:
                    errors.append("Unknown record type at line \(offset + 1).")
                }
            } catch {
                errors.append("Invalid audit record at line \(offset + 1).")
            }
        }

        if lines.count < 2 { errors.append("Audit must contain at least a header and summary.") }
        if header?.schema != NoctBoardAuditExporter.schema { errors.append("Unsupported audit schema.") }
        if header == nil { errors.append("Audit header is missing.") }
        if summary == nil { errors.append("Audit summary is missing.") }
        if header?.boardID != header?.groupID { errors.append("V1 board and group IDs do not match.") }

        let accepted = entries.filter { $0.outcome == .accepted }.count
        let replayed = entries.filter { $0.outcome == .replayed }.count
        let rejected = entries.filter { $0.outcome == .rejected }.count
        if summary?.acceptedCount != accepted { errors.append("Accepted count does not match ledger records.") }
        if summary?.replayedCount != replayed { errors.append("Replayed count does not match ledger records.") }
        if summary?.rejectedCount != rejected { errors.append("Rejected count does not match ledger records.") }
        if summary?.containerRejectedCount != containerRejections.count {
            errors.append("Container-rejected count does not match records.")
        }
        if summary?.historyAttestationCount != historyAttestations.count {
            errors.append("History-attestation count does not match records.")
        }
        let containerReasons = Set([
            "unexpectedContent", "malformedPayload", "envelopeBindingMismatch",
            "unauthorizedHistoryBootstrap", "invalidAuthorSignature",
        ])
        if containerRejections.contains(where: { !containerReasons.contains($0.reason) }) {
            errors.append("Container rejection has an unsupported reason.")
        }
        if Set(containerRejections.map(\.groupEventID)).count != containerRejections.count {
            errors.append("Container rejection group-event IDs are not unique.")
        }
        if Set(historyAttestations.map(\.groupEventID)).count != historyAttestations.count {
            errors.append("History-attestation group-event IDs are not unique.")
        }
        let ledgerEventIDs = Set(entries.map(\.eventID))
        if historyAttestations.contains(where: {
            !ledgerEventIDs.contains($0.reassertedEventID)
        }) {
            errors.append("History attestation refers to an event absent from the ledger.")
        }
        for entry in entries {
            if !allowedOperationTypes.contains(entry.operationType) {
                errors.append("Ledger record has an unsupported operation type.")
            }
            switch entry.outcome {
            case .accepted:
                if entry.rejectionReason != nil || !entry.authorChainConsumed {
                    errors.append("Accepted ledger record has inconsistent verdict metadata.")
                }
            case .replayed:
                if entry.rejectionReason != nil || entry.authorChainConsumed {
                    errors.append("Replayed ledger record has inconsistent verdict metadata.")
                }
            case .rejected:
                if entry.rejectionReason == nil {
                    errors.append("Rejected ledger record omits its rejection reason.")
                }
            }
        }
        if !isDigest(summary?.projectionDigest) { errors.append("Projection digest is malformed.") }
        for (index, entry) in entries.enumerated() where !isDigest(entry.eventDigest) {
            errors.append("Event digest is malformed at ledger order \(index).")
        }

        return NoctBoardImportedAudit(
            sourceURL: sourceURL,
            schema: header?.schema,
            boardID: header?.boardID,
            groupID: header?.groupID,
            entries: entries,
            containerRejections: containerRejections,
            historyAttestations: historyAttestations,
            projectionDigest: summary?.projectionDigest,
            acceptedCount: accepted,
            replayedCount: replayed,
            rejectedCount: rejected,
            containerRejectedCount: containerRejections.count,
            historyAttestationCount: historyAttestations.count,
            isStructurallyConsistent: errors.isEmpty,
            errors: errors
        )
    }

    private static func invalid(_ sourceURL: URL, _ error: String) -> NoctBoardImportedAudit {
        NoctBoardImportedAudit(
            sourceURL: sourceURL,
            schema: nil,
            boardID: nil,
            groupID: nil,
            entries: [],
            containerRejections: [],
            historyAttestations: [],
            projectionDigest: nil,
            acceptedCount: 0,
            replayedCount: 0,
            rejectedCount: 0,
            containerRejectedCount: 0,
            historyAttestationCount: 0,
            isStructurallyConsistent: false,
            errors: [error]
        )
    }

    private static func isDigest(_ value: String?) -> Bool {
        guard let value, value.utf8.count == 64 else { return false }
        return value.utf8.allSatisfy {
            (0x30 ... 0x39).contains($0) || (0x61 ... 0x66).contains($0)
        }
    }

    private static let allowedOperationTypes = Set([
        "thread.create", "thread.close", "task.create", "task.assign",
        "task.transition", "message.post", "member.set-role",
    ])

    private static func containsProjectionPlaintext(_ object: [String: Any]) -> Bool {
        let forbidden = Set(["body", "title", "details", "payload", "messages", "tasks", "threads"])
        for (key, value) in object {
            if forbidden.contains(key) { return true }
            if let nested = value as? [String: Any], containsProjectionPlaintext(nested) {
                return true
            }
            if let nested = value as? [[String: Any]],
               nested.contains(where: containsProjectionPlaintext) {
                return true
            }
        }
        return false
    }

    private static func hasExactShape(
        _ object: [String: Any],
        recordType: String
    ) -> Bool {
        func exact(_ expected: Set<String>, _ value: [String: Any]) -> Bool {
            Set(value.keys) == expected
        }
        func exact(
            required: Set<String>,
            optional: Set<String>,
            _ value: [String: Any]
        ) -> Bool {
            let actual = Set(value.keys)
            return required.isSubset(of: actual)
                && actual.isSubset(of: required.union(optional))
        }
        switch recordType {
        case "header":
            return exact(["recordType", "schema", "boardID", "groupID"], object)
        case "event":
            guard exact(["recordType", "entry"], object),
                  let entry = object["entry"] as? [String: Any] else { return false }
            return exact(required: [
                "order", "eventID", "clientTransactionID", "logicalClock",
                "authorSequence", "createdAtUnixMilliseconds", "authorMemberHandle",
                "authorCredentialHandle", "authorChainConsumed", "operationType",
                "eventDigest", "outcome",
            ], optional: ["previousAuthorEventDigest", "rejectionReason"], entry)
        case "containerRejection":
            guard exact(["recordType", "entry"], object),
                  let entry = object["entry"] as? [String: Any] else { return false }
            return exact(["groupEventID", "reason"], entry)
        case "historyAttestation":
            guard exact(["recordType", "entry"], object),
                  let entry = object["entry"] as? [String: Any] else { return false }
            return exact([
                "groupEventID", "reassertedEventID", "assertedByMemberHandle",
                "assertedByCredentialHandle",
            ], entry)
        case "summary":
            return exact([
                "recordType", "acceptedCount", "replayedCount", "rejectedCount",
                "containerRejectedCount", "historyAttestationCount", "projectionDigest",
            ], object)
        default:
            return false
        }
    }

    private struct Discriminator: Decodable { let recordType: String }
    private struct Header: Decodable {
        let recordType: String
        let schema: String
        let boardID: UUID
        let groupID: UUID
    }
    private struct EventRecord: Decodable {
        let recordType: String
        let entry: NoctBoardLedgerEntry
    }
    private struct ContainerRejectionRecord: Decodable {
        let recordType: String
        let entry: NoctBoardAuditContainerRejection
    }
    private struct HistoryAttestationRecord: Decodable {
        let recordType: String
        let entry: NoctBoardAuditHistoryAttestation
    }
    private struct Summary: Decodable {
        let recordType: String
        let acceptedCount: Int
        let replayedCount: Int
        let rejectedCount: Int
        let containerRejectedCount: Int
        let historyAttestationCount: Int
        let projectionDigest: String
    }
}
