// SPDX-FileCopyrightText: 2026 Luiz Widmer
// SPDX-License-Identifier: AGPL-3.0-or-later

import CryptoKit
import Foundation
import NoctBoardCore
@preconcurrency import NoctweaveCore
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

enum NoctBoardAdmissionVerificationStatus: String, Codable, Sendable {
    case pending
    case verified
}

enum NoctBoardOwnerAdmissionPhase: String, Codable, Sendable {
    case prepared
    case epochCommitted
    case complete
}

struct NoctBoardOwnerHistoryRecord: Codable, Equatable, Sendable {
    let eventID: UUID
    let signedEventRecordBytes: Data
}

struct NoctBoardOwnerAdmissionJournal: Codable, Equatable, @unchecked Sendable {
    let revision: UInt64
    let board: NoctBoardReference
    let admissionID: UUID
    let request: NoctBoardAdmissionRequest
    let requestDigest: Data
    let idempotencyKey: Data
    let anchor: GroupJoinAnchorV2
    let existingMemberRouteAnnouncements: [SignedGroupRouteSetAnnouncementV2]
    let historyRecords: [NoctBoardOwnerHistoryRecord]
    let historyManifest: [NoctBoardAdmissionHistoryManifestEntry]
    let baseGroupEventCount: Int
    let createdAt: Date
    let expiresAt: Date
    let packageBytes: Data?
    let packageDigest: Data?
    let pendingOperationIDs: [UUID]
    let phase: NoctBoardOwnerAdmissionPhase

    var isStructurallyValid: Bool {
        revision < UInt64.max
            && board.boardID == board.groupID
            && admissionID == request.admissionID
            && request.board == board
            && requestDigest.count == 32
            && idempotencyKey.count == 32
            && request.admission.groupId == board.groupID
            && request.initialRouteSet.groupID == board.groupID
            && anchor.baseState.groupId == board.groupID
            && anchor.destinationMemberHandle == request.admission.memberHandle
            && anchor.destinationCredentialHandle == request.admission.credentialHandle
            && anchor.expiresAt == expiresAt
            && createdAt.timeIntervalSince1970.isFinite
            && expiresAt.timeIntervalSince1970.isFinite
            && expiresAt > createdAt
            && (phase == .complete || historyRecords.count == historyManifest.count)
            && (phase == .complete || !historyRecords.isEmpty)
            && historyRecords.count <= NoctBoardClient.maximumAdmissionHistoryEvents
            && Set(historyRecords.map(\.eventID)).count == historyRecords.count
            && historyRecords.allSatisfy {
                !$0.signedEventRecordBytes.isEmpty
                    && $0.signedEventRecordBytes.count
                        <= NoctBoardSignedEventRecord.maximumEncodedBytes
            }
            && Set(historyManifest).count == historyManifest.count
            && historyManifest.allSatisfy(\.isStructurallyValid)
            && baseGroupEventCount >= historyRecords.count
            && baseGroupEventCount <= NoctBoardLimits.maximumBoardEvents
            && existingMemberRouteAnnouncements.count <= 128
            && Set(existingMemberRouteAnnouncements.map {
                $0.routeSet.ownerCredentialHandle
            }).count == existingMemberRouteAnnouncements.count
            && pendingOperationIDs.count <= 1 + historyManifest.count
            && Set(pendingOperationIDs).count == pendingOperationIDs.count
            && decodedPackage.map {
                $0.board == board
                    && $0.admissionID == admissionID
                    && $0.anchor == anchor
                    && $0.historyManifest == historyManifest
                    && $0.expiresAt == expiresAt
            } ?? (packageBytes == nil)
            && packageBytes.map {
                !$0.isEmpty
                    && $0.count <= NoctBoardAdmissionCodec.maximumArtifactBytes
            }
                ?? (phase == .prepared)
            && packageDigest.map { $0.count == 32 } ?? (phase == .prepared)
            && (phase != .prepared || (packageBytes == nil && packageDigest == nil))
            && (phase != .complete
                || (historyRecords.isEmpty && existingMemberRouteAnnouncements.isEmpty))
            && (phase != .complete || (packageBytes != nil && packageDigest != nil))
    }

    var decodedPackage: NoctBoardAdmissionPackage? {
        guard let packageBytes else { return nil }
        return try? NoctBoardAdmissionCodec.decodePackage(packageBytes)
    }

    func replacing(
        packageBytes: Data? = nil,
        packageDigest: Data? = nil,
        pendingOperationIDs: [UUID]? = nil,
        phase: NoctBoardOwnerAdmissionPhase? = nil
    ) -> NoctBoardOwnerAdmissionJournal {
        NoctBoardOwnerAdmissionJournal(
            revision: revision,
            board: board,
            admissionID: admissionID,
            request: request,
            requestDigest: requestDigest,
            idempotencyKey: idempotencyKey,
            anchor: anchor,
            existingMemberRouteAnnouncements: existingMemberRouteAnnouncements,
            historyRecords: historyRecords,
            historyManifest: historyManifest,
            baseGroupEventCount: baseGroupEventCount,
            createdAt: createdAt,
            expiresAt: expiresAt,
            packageBytes: packageBytes ?? self.packageBytes,
            packageDigest: packageDigest ?? self.packageDigest,
            pendingOperationIDs: pendingOperationIDs ?? self.pendingOperationIDs,
            phase: phase ?? self.phase
        )
    }

    func compactedComplete(
        packageBytes: Data,
        packageDigest: Data
    ) -> NoctBoardOwnerAdmissionJournal {
        NoctBoardOwnerAdmissionJournal(
            revision: revision,
            board: board,
            admissionID: admissionID,
            request: request,
            requestDigest: requestDigest,
            idempotencyKey: idempotencyKey,
            anchor: anchor,
            existingMemberRouteAnnouncements: [],
            historyRecords: [],
            historyManifest: historyManifest,
            baseGroupEventCount: baseGroupEventCount,
            createdAt: createdAt,
            expiresAt: expiresAt,
            packageBytes: packageBytes,
            packageDigest: packageDigest,
            pendingOperationIDs: [],
            phase: .complete
        )
    }

    fileprivate func withRevision(_ revision: UInt64) -> NoctBoardOwnerAdmissionJournal {
        NoctBoardOwnerAdmissionJournal(
            revision: revision,
            board: board,
            admissionID: admissionID,
            request: request,
            requestDigest: requestDigest,
            idempotencyKey: idempotencyKey,
            anchor: anchor,
            existingMemberRouteAnnouncements: existingMemberRouteAnnouncements,
            historyRecords: historyRecords,
            historyManifest: historyManifest,
            baseGroupEventCount: baseGroupEventCount,
            createdAt: createdAt,
            expiresAt: expiresAt,
            packageBytes: packageBytes,
            packageDigest: packageDigest,
            pendingOperationIDs: pendingOperationIDs,
            phase: phase
        )
    }
}

struct NoctBoardJoinAdmissionReceipt: Codable, Equatable, @unchecked Sendable {
    let board: NoctBoardReference
    let admissionID: UUID
    let originJoinAnchorID: UUID
    let destinationMemberHandle: GroupScopedMemberHandleV2
    let destinationCredentialHandle: GroupScopedCredentialHandleV2
    let destinationAdmissionDigest: Data
    let requestDigest: Data
    let packageDigest: Data
    let historyManifest: [NoctBoardAdmissionHistoryManifestEntry]
    let expiresAt: Date
    let status: NoctBoardAdmissionVerificationStatus

    var isStructurallyValid: Bool {
        board.boardID == board.groupID
            && requestDigest.count == 32
            && packageDigest.count == 32
            && destinationAdmissionDigest.count == 32
            && !historyManifest.isEmpty
            && historyManifest.count <= NoctBoardClient.maximumAdmissionHistoryEvents
            && Set(historyManifest).count == historyManifest.count
            && historyManifest.allSatisfy(\.isStructurallyValid)
            && expiresAt.timeIntervalSince1970.isFinite
    }

    func verified() -> NoctBoardJoinAdmissionReceipt {
        NoctBoardJoinAdmissionReceipt(
            board: board,
            admissionID: admissionID,
            originJoinAnchorID: originJoinAnchorID,
            destinationMemberHandle: destinationMemberHandle,
            destinationCredentialHandle: destinationCredentialHandle,
            destinationAdmissionDigest: destinationAdmissionDigest,
            requestDigest: requestDigest,
            packageDigest: packageDigest,
            historyManifest: historyManifest,
            expiresAt: expiresAt,
            status: .verified
        )
    }
}

enum NoctBoardAdmissionStateStoreError: Error, Equatable {
    case invalidState
    case conflictingAdmission
    case storageUnavailable
}

final class NoctBoardOwnerOperationLease: @unchecked Sendable {
    private let stateLock = NSLock()
    private var descriptor: Int32?

    fileprivate init(descriptor: Int32?) {
        self.descriptor = descriptor
    }

    func release() {
        stateLock.lock()
        let current = descriptor
        descriptor = nil
        stateLock.unlock()
        guard let current else { return }
        _ = flock(current, LOCK_UN)
        _ = close(current)
    }

    deinit { release() }
}

actor NoctBoardAdmissionStateStore {
    static let maximumPlaintextBytes = 64 * 1_024 * 1_024
    private static let maximumStoredBytes = 96 * 1_024 * 1_024
    /// A canonical Data field expands to base64 in the journal JSON. Reserve
    /// the complete public package bound plus one MiB of exact-object overhead
    /// before Core is allowed to persist an epoch intent.
    static let maximumPackageReservationBytes =
        ((NoctBoardAdmissionCodec.maximumArtifactBytes + 2) / 3) * 4
            + (1 * 1_024 * 1_024)
    private static let service = "org.noctboard.securestorage"
    private static let aadDomain = Data("org.noctboard.admission-state.aad.v1\0".utf8)

    private enum Protection {
        case encrypted(account: String, aad: Data)
        case insecurePlaintextForTesting
        case memoryOnly
    }

    private struct Document: Codable, Equatable {
        static let schema = "org.noctboard/admission-state:1.0"

        let schema: String
        var generation: UInt64
        var ownerJournals: [NoctBoardOwnerAdmissionJournal]
        var joinReceipts: [NoctBoardJoinAdmissionReceipt]

        private enum CodingKeys: String, CodingKey, CaseIterable {
            case schema
            case generation
            case ownerJournals
            case joinReceipts
        }

        init(
            generation: UInt64 = 0,
            ownerJournals: [NoctBoardOwnerAdmissionJournal] = [],
            joinReceipts: [NoctBoardJoinAdmissionReceipt] = []
        ) {
            schema = Self.schema
            self.generation = generation
            self.ownerJournals = ownerJournals
            self.joinReceipts = joinReceipts
        }

        init(from decoder: Decoder) throws {
            let strict = try decoder.container(keyedBy: AdmissionCodingKey.self)
            guard Set(strict.allKeys.map(\.stringValue))
                    == Set(CodingKeys.allCases.map(\.rawValue)) else {
                throw DecodingError.dataCorrupted(
                    .init(
                        codingPath: decoder.codingPath,
                        debugDescription: "Admission state fields must match v1 exactly"
                    )
                )
            }
            let values = try decoder.container(keyedBy: CodingKeys.self)
            schema = try values.decode(String.self, forKey: .schema)
            generation = try values.decode(UInt64.self, forKey: .generation)
            ownerJournals = try values.decode(
                [NoctBoardOwnerAdmissionJournal].self,
                forKey: .ownerJournals
            )
            joinReceipts = try values.decode(
                [NoctBoardJoinAdmissionReceipt].self,
                forKey: .joinReceipts
            )
            guard isStructurallyValid else {
                throw DecodingError.dataCorrupted(
                    .init(codingPath: decoder.codingPath, debugDescription: "Invalid admission state")
                )
            }
        }

        func encode(to encoder: Encoder) throws {
            guard isStructurallyValid else {
                throw EncodingError.invalidValue(
                    self,
                    .init(codingPath: encoder.codingPath, debugDescription: "Invalid admission state")
                )
            }
            var values = encoder.container(keyedBy: CodingKeys.self)
            try values.encode(schema, forKey: .schema)
            try values.encode(generation, forKey: .generation)
            try values.encode(ownerJournals, forKey: .ownerJournals)
            try values.encode(joinReceipts, forKey: .joinReceipts)
        }

        var isStructurallyValid: Bool {
            schema == Self.schema
                && ownerJournals.count <= 256
                && joinReceipts.count <= 256
                && Set(ownerJournals.map { "\($0.board.boardID):\($0.admissionID)" }).count
                    == ownerJournals.count
                && Set(joinReceipts.map { "\($0.board.boardID):\($0.admissionID)" }).count
                    == joinReceipts.count
                && ownerJournals.allSatisfy(\.isStructurallyValid)
                && joinReceipts.allSatisfy(\.isStructurallyValid)
        }
    }

    private struct EncryptedEnvelope: Codable {
        static let version = 1
        let version: Int
        let sealed: Data

        private enum CodingKeys: String, CodingKey, CaseIterable {
            case version
            case sealed
        }

        init(sealed: Data) {
            version = Self.version
            self.sealed = sealed
        }

        init(from decoder: Decoder) throws {
            let strict = try decoder.container(keyedBy: AdmissionCodingKey.self)
            guard Set(strict.allKeys.map(\.stringValue))
                    == Set(CodingKeys.allCases.map(\.rawValue)) else {
                throw DecodingError.dataCorrupted(
                    .init(codingPath: decoder.codingPath, debugDescription: "Invalid envelope fields")
                )
            }
            let values = try decoder.container(keyedBy: CodingKeys.self)
            version = try values.decode(Int.self, forKey: .version)
            sealed = try values.decode(Data.self, forKey: .sealed)
            guard version == Self.version,
                  !sealed.isEmpty,
                  sealed.count <= NoctBoardAdmissionStateStore.maximumStoredBytes else {
                throw DecodingError.dataCorrupted(
                    .init(codingPath: decoder.codingPath, debugDescription: "Invalid envelope")
                )
            }
        }
    }

    private let fileURL: URL?
    private let protection: Protection
    private var cached: Document?

    init(
        stateFileURL: URL,
        protection: ClientStateStoreProtection,
        storageScopeIdentifier: String
    ) {
        let privateDirectory = stateFileURL.standardizedFileURL
            .resolvingSymlinksInPath()
            .appendingPathExtension("noctboard-private")
        fileURL = privateDirectory.appendingPathComponent("admission-state.json")
        if protection == .encrypted {
            let scopeDigest = Data(SHA256.hash(
                data: Data(storageScopeIdentifier.utf8)
            ))
            self.protection = .encrypted(
                account: "admission-state-v1-" + scopeDigest.map {
                    String(format: "%02x", $0)
                }.joined(),
                aad: Self.aadDomain + scopeDigest
            )
        } else {
            self.protection = .insecurePlaintextForTesting
        }
    }

    init(memoryOnlyForTesting: Void = ()) {
        fileURL = nil
        protection = .memoryOnly
        cached = Document()
    }

    func acquireOwnerOperationLease() throws -> NoctBoardOwnerOperationLease {
        if case .memoryOnly = protection {
            return NoctBoardOwnerOperationLease(descriptor: nil)
        }
        guard let fileURL else {
            throw NoctBoardAdmissionStateStoreError.storageUnavailable
        }
        try ensurePrivateDirectory(fileURL.deletingLastPathComponent())
        let lockURL = fileURL.appendingPathExtension("owner-operation.lock")
        let descriptor: Int32 = lockURL.withUnsafeFileSystemRepresentation { path in
            guard let path else { return Int32(-1) }
            return open(path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0o600)
        }
        guard descriptor >= 0,
              fchmod(descriptor, 0o600) == 0,
              flock(descriptor, LOCK_EX | LOCK_NB) == 0 else {
            if descriptor >= 0 { _ = close(descriptor) }
            throw NoctBoardAdmissionStateStoreError.storageUnavailable
        }
        return NoctBoardOwnerOperationLease(descriptor: descriptor)
    }

    func ownerJournal(
        board: NoctBoardReference,
        admissionID: UUID
    ) throws -> NoctBoardOwnerAdmissionJournal? {
        try withStoreLock(exclusive: false) {
            try loadDocumentUnlocked().ownerJournals.first {
                $0.board == board && $0.admissionID == admissionID
            }
        }
    }

    func abortPreparedOwnerJournal(
        board: NoctBoardReference,
        admissionID: UUID,
        revision: UInt64,
        requestDigest: Data
    ) throws {
        try withStoreLock(exclusive: true) {
            var current = try loadDocumentUnlocked()
            guard let index = current.ownerJournals.firstIndex(where: {
                $0.board == board && $0.admissionID == admissionID
            }) else {
                return
            }
            let existing = current.ownerJournals[index]
            guard existing.phase == .prepared,
                  existing.revision == revision,
                  existing.requestDigest == requestDigest,
                  existing.packageBytes == nil else {
                throw NoctBoardAdmissionStateStoreError.conflictingAdmission
            }
            current.ownerJournals.remove(at: index)
            try saveDocumentUnlocked(current)
        }
    }

    func saveOwnerJournal(
        _ journal: NoctBoardOwnerAdmissionJournal
    ) throws -> NoctBoardOwnerAdmissionJournal {
        guard journal.isStructurallyValid else {
            throw NoctBoardAdmissionStateStoreError.invalidState
        }
        return try withStoreLock(exclusive: true) {
            var current = try loadDocumentUnlocked()
            if let index = current.ownerJournals.firstIndex(where: {
                $0.board == journal.board && $0.admissionID == journal.admissionID
            }) {
                let existing = current.ownerJournals[index]
                let isExactCompletionCompaction = existing.phase == .epochCommitted
                    && journal.phase == .complete
                    && journal.existingMemberRouteAnnouncements.isEmpty
                    && journal.historyRecords.isEmpty
                guard existing.revision == journal.revision,
                      existing.request == journal.request,
                      existing.requestDigest == journal.requestDigest,
                      existing.idempotencyKey == journal.idempotencyKey,
                      existing.anchor == journal.anchor,
                      (existing.existingMemberRouteAnnouncements
                        == journal.existingMemberRouteAnnouncements
                        || isExactCompletionCompaction),
                      (existing.historyRecords == journal.historyRecords
                        || isExactCompletionCompaction),
                      existing.historyManifest == journal.historyManifest,
                      existing.baseGroupEventCount == journal.baseGroupEventCount,
                      existing.createdAt == journal.createdAt,
                      existing.expiresAt == journal.expiresAt,
                      Self.phaseRank(journal.phase) >= Self.phaseRank(existing.phase),
                      existing.packageBytes.map({ $0 == journal.packageBytes }) ?? true,
                      existing.packageDigest.map({ $0 == journal.packageDigest }) ?? true else {
                    throw NoctBoardAdmissionStateStoreError.conflictingAdmission
                }
                let saved = journal.withRevision(journal.revision + 1)
                current.ownerJournals[index] = saved
                try saveDocumentUnlocked(current)
                return saved
            } else {
                guard journal.revision == 0 else {
                    throw NoctBoardAdmissionStateStoreError.conflictingAdmission
                }
                guard !current.ownerJournals.contains(where: {
                    $0.board == journal.board && $0.phase != .complete
                }) else {
                    throw NoctBoardAdmissionStateStoreError.conflictingAdmission
                }
                let saved = journal.withRevision(1)
                current.ownerJournals.append(saved)
                try requireReservedCapacity(current)
                try saveDocumentUnlocked(current)
                return saved
            }
        }
    }

    private static func phaseRank(_ phase: NoctBoardOwnerAdmissionPhase) -> Int {
        switch phase {
        case .prepared: 0
        case .epochCommitted: 1
        case .complete: 2
        }
    }

    private func requireReservedCapacity(_ document: Document) throws {
        let encoded = try NoctweaveCoder.encode(document, sortedKeys: true)
        let outstandingReservations = document.ownerJournals.filter {
            $0.phase == .prepared && $0.packageBytes == nil
        }.count
        guard Self.reservedCapacityFits(
            encodedDocumentBytes: encoded.count,
            outstandingPackageCount: outstandingReservations
        ) else {
            throw NoctBoardAdmissionStateStoreError.storageUnavailable
        }
    }

    static func reservedCapacityFits(
        encodedDocumentBytes: Int,
        outstandingPackageCount: Int
    ) -> Bool {
        guard encodedDocumentBytes >= 0,
              outstandingPackageCount >= 0,
              encodedDocumentBytes <= maximumPlaintextBytes else {
            return false
        }
        let (reservedBytes, overflow) = outstandingPackageCount.multipliedReportingOverflow(
            by: maximumPackageReservationBytes
        )
        return !overflow
            && reservedBytes <= maximumPlaintextBytes - encodedDocumentBytes
    }

    func joinReceipt(
        board: NoctBoardReference
    ) throws -> NoctBoardJoinAdmissionReceipt? {
        try withStoreLock(exclusive: false) {
            try loadDocumentUnlocked().joinReceipts.last { $0.board == board }
        }
    }

    func beginJoinReceipt(_ receipt: NoctBoardJoinAdmissionReceipt) throws {
        guard receipt.status == .pending, receipt.isStructurallyValid else {
            throw NoctBoardAdmissionStateStoreError.invalidState
        }
        try withStoreLock(exclusive: true) {
            var current = try loadDocumentUnlocked()
            if let index = current.joinReceipts.firstIndex(where: {
                $0.board == receipt.board && $0.admissionID == receipt.admissionID
            }) {
                let existing = current.joinReceipts[index]
            guard existing.board == receipt.board,
                  existing.originJoinAnchorID == receipt.originJoinAnchorID,
                  existing.destinationMemberHandle == receipt.destinationMemberHandle,
                      existing.destinationCredentialHandle
                        == receipt.destinationCredentialHandle,
                      existing.requestDigest == receipt.requestDigest,
                      existing.packageDigest == receipt.packageDigest,
                      existing.historyManifest == receipt.historyManifest,
                      existing.expiresAt == receipt.expiresAt else {
                    throw NoctBoardAdmissionStateStoreError.conflictingAdmission
                }
                return
            }
            guard !current.joinReceipts.contains(where: { $0.board == receipt.board }) else {
                throw NoctBoardAdmissionStateStoreError.conflictingAdmission
            }
            current.joinReceipts.append(receipt)
            try saveDocumentUnlocked(current)
        }
    }

    func markJoinReceiptVerified(
        board: NoctBoardReference,
        admissionID: UUID,
        requestDigest: Data,
        packageDigest: Data
    ) throws {
        try withStoreLock(exclusive: true) {
            var current = try loadDocumentUnlocked()
            guard let index = current.joinReceipts.firstIndex(where: {
                $0.board == board && $0.admissionID == admissionID
            }) else {
                throw NoctBoardAdmissionStateStoreError.invalidState
            }
            let receipt = current.joinReceipts[index]
            guard receipt.requestDigest == requestDigest,
                  receipt.packageDigest == packageDigest else {
                throw NoctBoardAdmissionStateStoreError.conflictingAdmission
            }
            current.joinReceipts[index] = receipt.verified()
            try saveDocumentUnlocked(current)
        }
    }

    private func withStoreLock<T>(
        exclusive: Bool,
        _ body: () throws -> T
    ) throws -> T {
        if case .memoryOnly = protection {
            return try body()
        }
        guard let fileURL else {
            throw NoctBoardAdmissionStateStoreError.storageUnavailable
        }
        try ensurePrivateDirectory(fileURL.deletingLastPathComponent())
        let lockURL = fileURL.appendingPathExtension("lock")
        let descriptor: Int32 = lockURL.withUnsafeFileSystemRepresentation { path in
            guard let path else { return Int32(-1) }
            return open(path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0o600)
        }
        guard descriptor >= 0 else {
            throw NoctBoardAdmissionStateStoreError.storageUnavailable
        }
        defer { _ = close(descriptor) }
        guard flock(descriptor, exclusive ? LOCK_EX : LOCK_SH) == 0 else {
            throw NoctBoardAdmissionStateStoreError.storageUnavailable
        }
        defer { _ = flock(descriptor, LOCK_UN) }
        guard fchmod(descriptor, 0o600) == 0 else {
            throw NoctBoardAdmissionStateStoreError.storageUnavailable
        }
        return try body()
    }

    private func loadDocumentUnlocked() throws -> Document {
        if case .memoryOnly = protection {
            return cached ?? Document()
        }
        guard let fileURL else {
            throw NoctBoardAdmissionStateStoreError.storageUnavailable
        }
        guard let stored = try readSecureFile(fileURL) else {
            return Document()
        }
        guard stored.count <= Self.maximumStoredBytes,
              NoctweaveCanonicalJSON.isCanonical(stored) else {
            throw NoctBoardAdmissionStateStoreError.invalidState
        }
        let plaintext: Data
        switch protection {
        case .encrypted(let account, let aad):
            let envelope = try NoctweaveCoder.decode(EncryptedEnvelope.self, from: stored)
            let key = try SecureStorageKeyProvider.shared.loadOrCreateKey(
                service: Self.service,
                account: account
            )
            guard let sealed = try? AES.GCM.SealedBox(combined: envelope.sealed),
                  let opened = try? AES.GCM.open(sealed, using: key, authenticating: aad) else {
                throw NoctBoardAdmissionStateStoreError.invalidState
            }
            plaintext = opened
        case .insecurePlaintextForTesting, .memoryOnly:
            plaintext = stored
        }
        guard plaintext.count <= Self.maximumPlaintextBytes,
              NoctweaveCanonicalJSON.isCanonical(plaintext) else {
            throw NoctBoardAdmissionStateStoreError.invalidState
        }
        let decoded = try NoctweaveCoder.decode(Document.self, from: plaintext)
        return decoded
    }

    private func saveDocumentUnlocked(_ document: Document) throws {
        guard document.isStructurallyValid, document.generation < UInt64.max else {
            throw NoctBoardAdmissionStateStoreError.invalidState
        }
        try requireReservedCapacity(document)
        var next = document
        next.generation += 1
        if case .memoryOnly = protection {
            cached = next
            return
        }
        guard let fileURL else {
            throw NoctBoardAdmissionStateStoreError.storageUnavailable
        }
        let plaintext = try NoctweaveCoder.encode(next, sortedKeys: true)
        guard plaintext.count <= Self.maximumPlaintextBytes else {
            throw NoctBoardAdmissionStateStoreError.invalidState
        }
        let stored: Data
        switch protection {
        case .encrypted(let account, let aad):
            let key = try SecureStorageKeyProvider.shared.loadOrCreateKey(
                service: Self.service,
                account: account
            )
            let sealed = try AES.GCM.seal(plaintext, using: key, authenticating: aad)
            guard let combined = sealed.combined else {
                throw NoctBoardAdmissionStateStoreError.storageUnavailable
            }
            stored = try NoctweaveCoder.encode(
                EncryptedEnvelope(sealed: combined),
                sortedKeys: true
            )
        case .insecurePlaintextForTesting:
            stored = plaintext
        case .memoryOnly:
            cached = document
            return
        }
        guard stored.count <= Self.maximumStoredBytes else {
            throw NoctBoardAdmissionStateStoreError.invalidState
        }
        try writeSecureFile(stored, to: fileURL)
    }

    private func ensurePrivateDirectory(_ directory: URL) throws {
        var status = stat()
        let exists = directory.withUnsafeFileSystemRepresentation { path in
            guard let path else { return false }
            return lstat(path, &status) == 0
        }
        if !exists {
            guard errno == ENOENT else {
                throw NoctBoardAdmissionStateStoreError.storageUnavailable
            }
            try FileManager.default.createDirectory(
                at: directory,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
            let created = directory.withUnsafeFileSystemRepresentation { path in
                guard let path else { return false }
                return lstat(path, &status) == 0
            }
            guard created else {
                throw NoctBoardAdmissionStateStoreError.storageUnavailable
            }
        }
        guard (status.st_mode & S_IFMT) == S_IFDIR,
              status.st_uid == geteuid() else {
            throw NoctBoardAdmissionStateStoreError.storageUnavailable
        }
        let tightened = directory.withUnsafeFileSystemRepresentation { path in
            guard let path else { return false }
            return chmod(path, 0o700) == 0
        }
        guard tightened else {
            throw NoctBoardAdmissionStateStoreError.storageUnavailable
        }
    }

    private func readSecureFile(_ url: URL) throws -> Data? {
        let descriptor: Int32 = url.withUnsafeFileSystemRepresentation { path in
            guard let path else { return Int32(-1) }
            return open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        }
        if descriptor < 0, errno == ENOENT { return nil }
        guard descriptor >= 0 else {
            throw NoctBoardAdmissionStateStoreError.storageUnavailable
        }
        var status = stat()
        guard fstat(descriptor, &status) == 0,
              (status.st_mode & S_IFMT) == S_IFREG,
              status.st_uid == geteuid(),
              (status.st_mode & 0o077) == 0,
              status.st_size >= 0,
              status.st_size <= Self.maximumStoredBytes else {
            _ = close(descriptor)
            throw NoctBoardAdmissionStateStoreError.storageUnavailable
        }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        guard let data = try handle.readToEnd(),
              data.count == Int(status.st_size) else {
            throw NoctBoardAdmissionStateStoreError.storageUnavailable
        }
        return data
    }

    private func writeSecureFile(_ data: Data, to url: URL) throws {
        let directory = url.deletingLastPathComponent()
        try ensurePrivateDirectory(directory)
        let temporary = directory.appendingPathComponent(
            ".admission-state-\(UUID().uuidString).tmp"
        )
        let descriptor: Int32 = temporary.withUnsafeFileSystemRepresentation { path in
            guard let path else { return Int32(-1) }
            return open(
                path,
                O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                0o600
            )
        }
        guard descriptor >= 0 else {
            throw NoctBoardAdmissionStateStoreError.storageUnavailable
        }
        var shouldRemoveTemporary = true
        defer {
            _ = close(descriptor)
            if shouldRemoveTemporary {
                temporary.withUnsafeFileSystemRepresentation { path in
                    if let path { _ = unlink(path) }
                }
            }
        }
        let wroteAll = data.withUnsafeBytes { rawBuffer -> Bool in
            guard let base = rawBuffer.baseAddress else { return data.isEmpty }
            var offset = 0
            while offset < rawBuffer.count {
                let result = write(descriptor, base.advanced(by: offset), rawBuffer.count - offset)
                if result <= 0 { return false }
                offset += result
            }
            return true
        }
        guard wroteAll, fsync(descriptor) == 0, fchmod(descriptor, 0o600) == 0 else {
            throw NoctBoardAdmissionStateStoreError.storageUnavailable
        }
        let renamed = temporary.withUnsafeFileSystemRepresentation { source in
            url.withUnsafeFileSystemRepresentation { destination in
                guard let source, let destination else { return false }
                return rename(source, destination) == 0
            }
        }
        guard renamed else {
            throw NoctBoardAdmissionStateStoreError.storageUnavailable
        }
        shouldRemoveTemporary = false
        let directoryDescriptor: Int32 = directory.withUnsafeFileSystemRepresentation { path in
            guard let path else { return Int32(-1) }
            return open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        }
        guard directoryDescriptor >= 0 else {
            throw NoctBoardAdmissionStateStoreError.storageUnavailable
        }
        defer { _ = close(directoryDescriptor) }
        guard fsync(directoryDescriptor) == 0 else {
            throw NoctBoardAdmissionStateStoreError.storageUnavailable
        }
    }
}

private struct AdmissionCodingKey: CodingKey {
    let stringValue: String
    let intValue: Int?

    init?(stringValue: String) {
        self.stringValue = stringValue
        intValue = nil
    }

    init?(intValue: Int) {
        stringValue = String(intValue)
        self.intValue = intValue
    }
}
