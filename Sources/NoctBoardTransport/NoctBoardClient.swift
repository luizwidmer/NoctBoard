// SPDX-FileCopyrightText: 2026 Luiz Widmer
// SPDX-License-Identifier: AGPL-3.0-or-later

import CryptoKit
import Foundation
@preconcurrency import NoctBoardCore
@preconcurrency import NoctweaveCore

private struct NoctBoardReferenceCodingKey: CodingKey {
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

public enum NoctBoardReferenceError: Error, Equatable, Sendable {
    case boardAndGroupMustMatch
    case invalidIdentifier
}

public struct NoctBoardReference: Codable, Equatable, Hashable, Sendable {
    public let boardID: UUID
    public let groupID: UUID

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case boardID
        case groupID
    }

    public init(id: UUID) throws {
        guard id != Self.zeroIdentifier else {
            throw NoctBoardReferenceError.invalidIdentifier
        }
        boardID = id
        groupID = id
    }

    public init(boardID: UUID, groupID: UUID) throws {
        guard boardID != Self.zeroIdentifier, groupID != Self.zeroIdentifier else {
            throw NoctBoardReferenceError.invalidIdentifier
        }
        guard boardID == groupID else {
            throw NoctBoardReferenceError.boardAndGroupMustMatch
        }
        self.boardID = boardID
        self.groupID = groupID
    }

    public init(from decoder: Decoder) throws {
        let strict = try decoder.container(keyedBy: NoctBoardReferenceCodingKey.self)
        guard Set(strict.allKeys.map(\.stringValue))
                == Set(CodingKeys.allCases.map(\.rawValue)) else {
            throw DecodingError.dataCorrupted(
                .init(
                    codingPath: decoder.codingPath,
                    debugDescription: "NoctBoard reference fields must match v1 exactly"
                )
            )
        }
        let values = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            boardID: values.decode(UUID.self, forKey: .boardID),
            groupID: values.decode(UUID.self, forKey: .groupID)
        )
    }

    public func encode(to encoder: Encoder) throws {
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(boardID, forKey: .boardID)
        try values.encode(groupID, forKey: .groupID)
    }

    private static let zeroIdentifier = UUID(
        uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    )
}

/// Exact canonical event bytes reasserted by the immutable genesis owner after
/// a member joins. The outer Noctweave group envelope supplies current-epoch
/// authentication; this record never claims to reproduce the original outer
/// envelope proof from an earlier epoch.
struct NoctBoardHistoryRecord: Codable, Equatable, Sendable {
    static let schema = "org.noctboard/history:1.0"

    let schema: String
    let boardID: UUID
    let groupID: UUID
    let signedEventRecordBytes: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case schema
        case boardID
        case groupID
        case signedEventRecordBytes
    }

    init(boardID: UUID, groupID: UUID, signedEventRecordBytes: Data) {
        schema = Self.schema
        self.boardID = boardID
        self.groupID = groupID
        self.signedEventRecordBytes = signedEventRecordBytes
    }

    init(from decoder: Decoder) throws {
        let strict = try decoder.container(keyedBy: NoctBoardReferenceCodingKey.self)
        guard Set(strict.allKeys.map(\.stringValue))
                == Set(CodingKeys.allCases.map(\.rawValue)) else {
            throw DecodingError.dataCorrupted(
                .init(
                    codingPath: decoder.codingPath,
                    debugDescription: "NoctBoard history fields must match v1 exactly"
                )
            )
        }
        let values = try decoder.container(keyedBy: CodingKeys.self)
        schema = try values.decode(String.self, forKey: .schema)
        boardID = try values.decode(UUID.self, forKey: .boardID)
        groupID = try values.decode(UUID.self, forKey: .groupID)
        signedEventRecordBytes = try values.decode(
            Data.self,
            forKey: .signedEventRecordBytes
        )
        guard schema == Self.schema,
              signedEventRecordBytes.count <= NoctBoardSignedEventRecord.maximumEncodedBytes else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: decoder.codingPath, debugDescription: "Invalid history record")
            )
        }
    }
}

/// Application-level attribution that survives owner-mediated late-join
/// re-encryption. The signature is ML-DSA under the event author's exact
/// group-scoped credential; it is neither an account nor a cross-group key.
struct NoctBoardSignedEventRecord: Codable, Equatable, Sendable {
    static let schema = "org.noctboard/signed-event:1.0"
    static let maximumEncodedBytes = 64 * 1_024

    let schema: String
    let eventBytes: Data
    let authorSignature: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case schema
        case eventBytes
        case authorSignature
    }

    init(eventBytes: Data, authorSignature: Data) {
        schema = Self.schema
        self.eventBytes = eventBytes
        self.authorSignature = authorSignature
    }

    init(from decoder: Decoder) throws {
        let strict = try decoder.container(keyedBy: NoctBoardReferenceCodingKey.self)
        guard Set(strict.allKeys.map(\.stringValue))
                == Set(CodingKeys.allCases.map(\.rawValue)) else {
            throw DecodingError.dataCorrupted(
                .init(
                    codingPath: decoder.codingPath,
                    debugDescription: "Signed NoctBoard event fields must match v1 exactly"
                )
            )
        }
        let values = try decoder.container(keyedBy: CodingKeys.self)
        schema = try values.decode(String.self, forKey: .schema)
        eventBytes = try values.decode(Data.self, forKey: .eventBytes)
        authorSignature = try values.decode(Data.self, forKey: .authorSignature)
        guard schema == Self.schema,
              eventBytes.count <= NoctBoardLimits.maximumEventBytes,
              !authorSignature.isEmpty,
              authorSignature.count <= 16 * 1_024 else {
            throw DecodingError.dataCorrupted(
                .init(
                    codingPath: decoder.codingPath,
                    debugDescription: "Invalid signed NoctBoard event"
                )
            )
        }
    }
}

/// Local-open configuration. Encrypted state and a stable rollback-anchor scope
/// are the production defaults. Plaintext protection is intentionally named by
/// Noctweave as a testing-only mode and must be selected explicitly.
public struct NoctBoardClientOpenConfiguration: @unchecked Sendable {
    public let stateFileURL: URL
    public let storageScopeIdentifier: String?
    public let displayName: String
    public let relay: RelayEndpoint
    public let relayAccessPassword: String?
    public let stateProtection: ClientStateStoreProtection

    public init(
        stateFileURL: URL,
        storageScopeIdentifier: String? = nil,
        displayName: String,
        relay: RelayEndpoint,
        relayAccessPassword: String? = nil,
        stateProtection: ClientStateStoreProtection = .encrypted
    ) {
        self.stateFileURL = stateFileURL
        if let storageScopeIdentifier {
            self.storageScopeIdentifier = storageScopeIdentifier
        } else {
            let pathDigest = Data(SHA256.hash(
                data: Data(stateFileURL.standardizedFileURL.path.utf8)
            )).map { String(format: "%02x", $0) }.joined()
            self.storageScopeIdentifier = "org.noctboard.state.\(pathDigest)"
        }
        self.displayName = displayName
        self.relay = relay
        self.relayAccessPassword = relayAccessPassword
        self.stateProtection = stateProtection
    }
}

public enum NoctBoardTransportError: Error, Equatable {
    case invalidOpenConfiguration
    case insecureRelayAuthentication
    case boardAlreadyBound
    case boardNotBound
    case boardBindingMismatch
    case boardNotPresentInLocalState
    case invalidBoardName
    case invalidGroupState
    case invalidBoardContainer
    case admissionHistoryWindowExceeded
    case admissionPackageExpired
    case admissionHistoryIncomplete
    case admissionValidityInsufficient
    case admissionPlanStale
    case admissionVerificationPending
    case boardAuditWindowExceeded
    case membershipRemovalRequiresAuditSegmentation
    case credentialRotationRequiresAuditSegmentation
    case groupRoleChangeRequiresAuditSegmentation
    case groupPermissionChangeRequiresAuditSegmentation
    case groupCapabilityChangeRequiresAuditSegmentation
    case logicalClockExhausted
    case authorSequenceExhausted
    case localAuthorizationRejected(NoctBoardRejectionReason?)
    case publicationIncomplete(NoctBoardPublicationDisposition)
    case synchronizationPageLimitReached
    case relayUnhealthy
}

public enum NoctBoardPublicationDisposition: String, Codable, Equatable, Sendable {
    case complete
    case pendingRetry
    case authorizationRecoveryRequired
    case relayRejected
    case invalidRelayResponse

    init(_ value: HeadlessGroupTransportDispositionV2) {
        switch value {
        case .complete: self = .complete
        case .pendingRetry: self = .pendingRetry
        case .authorizationRecoveryRequired: self = .authorizationRecoveryRequired
        case .relayRejected: self = .relayRejected
        case .invalidRelayResponse: self = .invalidRelayResponse
        }
    }
}

public enum NoctBoardContainerRejectionReason: String, Codable, Equatable, Sendable {
    case unexpectedContent
    case malformedPayload
    case envelopeBindingMismatch
    case unauthorizedHistoryBootstrap
    case invalidAuthorSignature
}

public struct NoctBoardContainerRejection: Codable, Equatable, Identifiable, Sendable {
    public var id: UUID { groupEventID }
    public let groupEventID: UUID
    public let reason: NoctBoardContainerRejectionReason

    public init(groupEventID: UUID, reason: NoctBoardContainerRejectionReason) {
        self.groupEventID = groupEventID
        self.reason = reason
    }
}

public struct NoctBoardHistoryBootstrapProvenance: Codable, Equatable, Identifiable,
    @unchecked Sendable {
    public var id: UUID { groupEventID }
    public let groupEventID: UUID
    public let reassertedEventID: UUID
    public let assertedByMemberHandle: GroupScopedMemberHandleV2
    public let assertedByCredentialHandle: GroupScopedCredentialHandleV2
}

/// One exact signed application record the genesis owner committed to
/// re-encrypting for a newly admitted member. The wrapper identifier is
/// deterministic for the admission, while the digest binds the original
/// author's canonical signed-record bytes.
public struct NoctBoardAdmissionHistoryManifestEntry: Codable, Equatable, Hashable,
    Sendable {
    public let historyGroupEventID: UUID
    public let eventID: UUID
    public let signedEventRecordDigest: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case historyGroupEventID
        case eventID
        case signedEventRecordDigest
    }

    init(
        historyGroupEventID: UUID,
        eventID: UUID,
        signedEventRecordDigest: Data
    ) {
        self.historyGroupEventID = historyGroupEventID
        self.eventID = eventID
        self.signedEventRecordDigest = signedEventRecordDigest
    }

    public init(from decoder: Decoder) throws {
        let strict = try decoder.container(keyedBy: NoctBoardReferenceCodingKey.self)
        guard Set(strict.allKeys.map(\.stringValue))
                == Set(CodingKeys.allCases.map(\.rawValue)) else {
            throw DecodingError.dataCorrupted(
                .init(
                    codingPath: decoder.codingPath,
                    debugDescription: "Admission history manifest fields must match v1 exactly"
                )
            )
        }
        let values = try decoder.container(keyedBy: CodingKeys.self)
        historyGroupEventID = try values.decode(UUID.self, forKey: .historyGroupEventID)
        eventID = try values.decode(UUID.self, forKey: .eventID)
        signedEventRecordDigest = try values.decode(
            Data.self,
            forKey: .signedEventRecordDigest
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorrupted(
                .init(
                    codingPath: decoder.codingPath,
                    debugDescription: "Invalid admission history manifest entry"
                )
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                .init(
                    codingPath: encoder.codingPath,
                    debugDescription: "Invalid admission history manifest entry"
                )
            )
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(historyGroupEventID, forKey: .historyGroupEventID)
        try values.encode(eventID, forKey: .eventID)
        try values.encode(signedEventRecordDigest, forKey: .signedEventRecordDigest)
    }

    var isStructurallyValid: Bool {
        historyGroupEventID != Self.zeroIdentifier
            && eventID != Self.zeroIdentifier
            && signedEventRecordDigest.count == SHA256.Digest.byteCount
    }

    private static let zeroIdentifier = UUID(
        uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    )
}

public struct NoctBoardClientSnapshot: Equatable, @unchecked Sendable {
    public let board: NoctBoardReference
    public let groupEpoch: UInt64
    public let localMemberHandle: GroupScopedMemberHandleV2
    public let localCredentialHandle: GroupScopedCredentialHandleV2
    public let events: [NoctBoardEvent]
    public let historyBootstrapProvenance: [NoctBoardHistoryBootstrapProvenance]
    public let containerRejections: [NoctBoardContainerRejection]
    public let result: NoctBoardProjectionResult

    public var projection: NoctBoardProjection { result.projection }
    public var ledger: NoctBoardLedger { result.ledger }
    public var projectionDigest: String { result.projectionDigest }
}

public struct NoctBoardPublishResult: Equatable, Sendable {
    public let event: NoctBoardEvent
    public let operationID: UUID?
    public let complete: Bool
    public let disposition: NoctBoardPublicationDisposition
    public let projectionDigest: String
}

public struct NoctBoardCreationResult: Equatable, @unchecked Sendable {
    public let board: NoctBoardReference
    public let ownerMemberHandle: GroupScopedMemberHandleV2
    public let ownerCredentialHandle: GroupScopedCredentialHandleV2
    public let initialThreadID: UUID
    public let initialPublication: NoctBoardPublishResult
}

public struct NoctBoardSynchronizationResult: Equatable, @unchecked Sendable {
    public let receivedGroupEventCount: Int
    public let receivedBoardEventIDs: [UUID]
    public let snapshot: NoctBoardClientSnapshot
}

public struct NoctBoardPublicationResumeResult: Codable, Equatable, Sendable {
    public let operationID: UUID
    public let eventID: UUID
    public let attemptedPublicationCount: Int
    public let acceptedPublicationCount: Int
    public let pendingPublicationCount: Int
    public let complete: Bool
    public let disposition: NoctBoardPublicationDisposition
}

public struct NoctBoardMaintenanceResult: Codable, Equatable, Sendable {
    public let observedAt: Date
    public let resumedTransportCount: Int
    public let rotatedReceiveRoute: Bool
    public let routeAnnouncementComplete: Bool?
    public let requiresFollowUp: Bool
}

public struct NoctBoardRelayHealth: Codable, Equatable, @unchecked Sendable {
    public let healthy: Bool
    public let checkedAt: Date
    public let endpoint: RelayEndpoint

    public init(healthy: Bool, checkedAt: Date, endpoint: RelayEndpoint) {
        self.healthy = healthy
        self.checkedAt = checkedAt
        self.endpoint = endpoint
    }
}

/// Group-only material a prospective member prepares locally. The caller must
/// move it through an independently authenticated encrypted invitation channel.
public struct NoctBoardAdmissionRequest: Codable, Equatable, @unchecked Sendable {
    public let board: NoctBoardReference
    public let admissionID: UUID
    public let invitationBindingDigest: Data
    public let admission: GroupCredentialAdmissionV2
    public let initialRouteSet: SignedGroupOpaqueRouteSetV2

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case board
        case admissionID
        case invitationBindingDigest
        case admission
        case initialRouteSet
    }

    public init(
        board: NoctBoardReference,
        admissionID: UUID,
        invitationBindingDigest: Data,
        admission: GroupCredentialAdmissionV2,
        initialRouteSet: SignedGroupOpaqueRouteSetV2
    ) {
        self.board = board
        self.admissionID = admissionID
        self.invitationBindingDigest = invitationBindingDigest
        self.admission = admission
        self.initialRouteSet = initialRouteSet
    }

    public init(from decoder: Decoder) throws {
        let strict = try decoder.container(keyedBy: NoctBoardReferenceCodingKey.self)
        guard Set(strict.allKeys.map(\.stringValue))
                == Set(CodingKeys.allCases.map(\.rawValue)) else {
            throw DecodingError.dataCorrupted(
                .init(
                    codingPath: decoder.codingPath,
                    debugDescription: "Admission request fields must match v1 exactly"
                )
            )
        }
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            board: try values.decode(NoctBoardReference.self, forKey: .board),
            admissionID: try values.decode(UUID.self, forKey: .admissionID),
            invitationBindingDigest: try values.decode(
                Data.self,
                forKey: .invitationBindingDigest
            ),
            admission: try values.decode(
                GroupCredentialAdmissionV2.self,
                forKey: .admission
            ),
            initialRouteSet: try values.decode(
                SignedGroupOpaqueRouteSetV2.self,
                forKey: .initialRouteSet
            )
        )
        do {
            try validateArtifact()
        } catch {
            throw DecodingError.dataCorrupted(
                .init(codingPath: decoder.codingPath, debugDescription: "Invalid admission request")
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        do {
            try validateArtifact()
        } catch {
            throw EncodingError.invalidValue(
                self,
                .init(codingPath: encoder.codingPath, debugDescription: "Invalid admission request")
            )
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(board, forKey: .board)
        try values.encode(admissionID, forKey: .admissionID)
        try values.encode(invitationBindingDigest, forKey: .invitationBindingDigest)
        try values.encode(admission, forKey: .admission)
        try values.encode(initialRouteSet, forKey: .initialRouteSet)
    }

    func validateArtifact() throws {
        guard admissionID != Self.zeroIdentifier,
              invitationBindingDigest.count == 32,
              admission.groupId == board.groupID,
              initialRouteSet.groupID == board.groupID,
              initialRouteSet.ownerCredentialHandle == admission.credentialHandle,
              initialRouteSet.ownerAdmissionDigest == admission.digest,
              admission.contentTypes.contains(where: {
                  $0.supports(NoctBoardClient.contentType)
              }),
              admission.contentTypes.contains(where: {
                  $0.supports(NoctBoardClient.historyContentType)
              }) else {
            throw NoctBoardTransportError.invalidGroupState
        }
        _ = try admission.verified(
            forGroupId: board.groupID,
            memberHandle: admission.memberHandle,
            selection: admission.selection,
            now: admission.issuedAt
        )
        _ = try initialRouteSet.verifyThrowing(
            ownerSigningPublicKey: admission.groupSigningPublicKey
        )
    }

    private static let zeroIdentifier = UUID(
        uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    )
}

/// Exact group artifacts returned by the owner. This is invitation-channel
/// material, not a reusable account or cross-board credential.
public struct NoctBoardAdmissionPackage: Codable, Equatable, @unchecked Sendable {
    public let board: NoctBoardReference
    public let admissionID: UUID
    public let anchor: GroupJoinAnchorV2
    public let transition: GroupEpochTransitionEnvelopeV2
    public let welcome: SignedGroupWelcomeV2
    public let existingMemberRouteAnnouncements: [SignedGroupRouteSetAnnouncementV2]
    public let historyManifest: [NoctBoardAdmissionHistoryManifestEntry]
    public let expiresAt: Date

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case board
        case admissionID
        case anchor
        case transition
        case welcome
        case existingMemberRouteAnnouncements
        case historyManifest
        case expiresAt
    }

    public init(
        board: NoctBoardReference,
        admissionID: UUID,
        anchor: GroupJoinAnchorV2,
        transition: GroupEpochTransitionEnvelopeV2,
        welcome: SignedGroupWelcomeV2,
        existingMemberRouteAnnouncements: [SignedGroupRouteSetAnnouncementV2],
        historyManifest: [NoctBoardAdmissionHistoryManifestEntry],
        expiresAt: Date
    ) {
        self.board = board
        self.admissionID = admissionID
        self.anchor = anchor
        self.transition = transition
        self.welcome = welcome
        self.existingMemberRouteAnnouncements = existingMemberRouteAnnouncements
        self.historyManifest = historyManifest
        self.expiresAt = expiresAt
    }

    public init(from decoder: Decoder) throws {
        let strict = try decoder.container(keyedBy: NoctBoardReferenceCodingKey.self)
        guard Set(strict.allKeys.map(\.stringValue))
                == Set(CodingKeys.allCases.map(\.rawValue)) else {
            throw DecodingError.dataCorrupted(
                .init(
                    codingPath: decoder.codingPath,
                    debugDescription: "Admission package fields must match v1 exactly"
                )
            )
        }
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            board: try values.decode(NoctBoardReference.self, forKey: .board),
            admissionID: try values.decode(UUID.self, forKey: .admissionID),
            anchor: try values.decode(GroupJoinAnchorV2.self, forKey: .anchor),
            transition: try values.decode(
                GroupEpochTransitionEnvelopeV2.self,
                forKey: .transition
            ),
            welcome: try values.decode(SignedGroupWelcomeV2.self, forKey: .welcome),
            existingMemberRouteAnnouncements: try values.decode(
                [SignedGroupRouteSetAnnouncementV2].self,
                forKey: .existingMemberRouteAnnouncements
            ),
            historyManifest: try values.decode(
                [NoctBoardAdmissionHistoryManifestEntry].self,
                forKey: .historyManifest
            ),
            expiresAt: try values.decode(Date.self, forKey: .expiresAt)
        )
        do {
            try validateArtifact()
        } catch {
            throw DecodingError.dataCorrupted(
                .init(codingPath: decoder.codingPath, debugDescription: "Invalid admission package")
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        do {
            try validateArtifact()
        } catch {
            throw EncodingError.invalidValue(
                self,
                .init(codingPath: encoder.codingPath, debugDescription: "Invalid admission package")
            )
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(board, forKey: .board)
        try values.encode(admissionID, forKey: .admissionID)
        try values.encode(anchor, forKey: .anchor)
        try values.encode(transition, forKey: .transition)
        try values.encode(welcome, forKey: .welcome)
        try values.encode(
            existingMemberRouteAnnouncements,
            forKey: .existingMemberRouteAnnouncements
        )
        try values.encode(historyManifest, forKey: .historyManifest)
        try values.encode(expiresAt, forKey: .expiresAt)
    }

    func validateArtifact() throws {
        let manifestSorted = historyManifest.sorted {
            $0.historyGroupEventID.uuidString < $1.historyGroupEventID.uuidString
        }
        let projection = transition.commit.admissionProjection
        let announcementHandles = existingMemberRouteAnnouncements.map {
            $0.routeSet.ownerCredentialHandle
        }
        let expectedHandles = anchor.baseState.activeCredentials.map(\.credentialHandle)
            .sorted { $0.rawValue < $1.rawValue }
        guard admissionID != Self.zeroIdentifier,
              expiresAt.timeIntervalSince1970.isFinite,
              anchor.baseState.groupId == board.groupID,
              transition.commit.groupId == board.groupID,
              transition.nextState.groupId == board.groupID,
              welcome.groupId == board.groupID,
              transition.commit.operation == .addMember,
              projection != nil,
              projection?.groupId == board.groupID,
              projection?.contentTypes.contains(where: {
                  $0.supports(NoctBoardClient.contentType)
              }) == true,
              projection?.contentTypes.contains(where: {
                  $0.supports(NoctBoardClient.historyContentType)
              }) == true,
              transition.commit.baseEpoch == anchor.baseState.epoch,
              anchor.destinationMemberHandle
                == transition.commit.admissionProjection?.memberHandle,
              anchor.destinationCredentialHandle
                == transition.commit.admissionProjection?.credentialHandle,
              welcome.destinationCredentialHandle == anchor.destinationCredentialHandle,
              welcome.destinationAdmissionDigest == anchor.destinationAdmissionDigest,
              expiresAt == anchor.expiresAt,
              expiresAt <= welcome.expiresAt,
              !historyManifest.isEmpty,
              historyManifest.count <= NoctBoardClient.maximumAdmissionHistoryEvents,
              historyManifest == manifestSorted,
              Set(historyManifest.map(\.historyGroupEventID)).count
                == historyManifest.count,
              Set(historyManifest.map(\.eventID)).count == historyManifest.count,
              Set(historyManifest.map(\.signedEventRecordDigest)).count
                == historyManifest.count,
              historyManifest.allSatisfy({ entry in
                  entry.isStructurallyValid
                      && entry.historyGroupEventID == NoctBoardClient.deterministicUUID(
                          domain: "org.noctboard.history.event.v1",
                          admissionID: admissionID,
                          eventID: entry.eventID,
                          eventDigest: entry.signedEventRecordDigest
                      )
              }),
              existingMemberRouteAnnouncements.count <= 128,
              announcementHandles == expectedHandles,
              Set(announcementHandles).count == announcementHandles.count,
              existingMemberRouteAnnouncements.allSatisfy({
                  $0.groupID == board.groupID
                      && $0.stateEpoch <= anchor.baseState.epoch
                      && expiresAt <= $0.routeSet.expiresAt
              }) else {
            throw NoctBoardTransportError.invalidGroupState
        }
        _ = try transition.commit.verifiedTransition(
            from: anchor.baseState,
            observedAt: transition.commit.createdAt
        )
        _ = try transition.nextState.verified(
            previousState: anchor.baseState,
            commit: transition.commit,
            observedAt: transition.commit.createdAt
        )
        _ = try welcome.verified(against: transition.nextState, now: welcome.createdAt)
        for announcement in existingMemberRouteAnnouncements {
            _ = try announcement.verified(
                against: anchor.baseState,
                observedAt: transition.commit.createdAt
            )
        }
    }

    private static let zeroIdentifier = UUID(
        uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    )
}

public enum NoctBoardAdmissionCodecError: Error, Equatable, Sendable {
    case invalidArtifact
    case artifactTooLarge
}

enum NoctBoardAdmissionTestInterruption: Equatable, Sendable {
    case afterOwnerPlanJournaled
    case afterCoreEpochPrepared
    case afterEpochPackageJournaled
}

/// Strict NCJ-1 admission artifacts for the independently authenticated
/// invitation channel. Raw JSONDecoder is intentionally not part of this API:
/// duplicate keys, whitespace variants, and dropped unknown fields fail.
public enum NoctBoardAdmissionCodec {
    public static let maximumArtifactBytes = 16 * 1_024 * 1_024

    public static func encodeRequest(_ request: NoctBoardAdmissionRequest) throws -> Data {
        try canonicalEncode(request)
    }

    public static func encodePackage(_ package: NoctBoardAdmissionPackage) throws -> Data {
        try canonicalEncode(package)
    }

    public static func decodeRequest(_ data: Data) throws -> NoctBoardAdmissionRequest {
        try canonicalDecode(NoctBoardAdmissionRequest.self, data: data)
    }

    public static func decodePackage(_ data: Data) throws -> NoctBoardAdmissionPackage {
        try canonicalDecode(NoctBoardAdmissionPackage.self, data: data)
    }

    private static func canonicalEncode<T: Codable>(_ value: T) throws -> Data {
        let data = try NoctweaveCanonicalJSON.encode(value)
        guard !data.isEmpty, data.count <= maximumArtifactBytes else {
            throw NoctBoardAdmissionCodecError.artifactTooLarge
        }
        return data
    }

    private static func canonicalDecode<T: Codable>(
        _ type: T.Type,
        data: Data
    ) throws -> T {
        guard !data.isEmpty, data.count <= maximumArtifactBytes else {
            throw NoctBoardAdmissionCodecError.artifactTooLarge
        }
        guard NoctweaveCanonicalJSON.isCanonical(data) else {
            throw NoctBoardAdmissionCodecError.invalidArtifact
        }
        let value: T
        do {
            value = try NoctweaveCoder.decode(type, from: data)
        } catch {
            throw NoctBoardAdmissionCodecError.invalidArtifact
        }
        guard try NoctweaveCanonicalJSON.encode(value) == data else {
            throw NoctBoardAdmissionCodecError.invalidArtifact
        }
        return value
    }
}

public actor NoctBoardClient {
    public static var contentType: ContentTypeId {
        ContentTypeId(
            authority: "org.noctboard",
            name: "event",
            major: 1,
            minor: 0
        )
    }
    public static var contentCapability: ContentTypeCapabilityV2 {
        ContentTypeCapabilityV2(contentType)
    }
    public static var historyContentType: ContentTypeId {
        ContentTypeId(
            authority: "org.noctboard",
            name: "history",
            major: 1,
            minor: 0
        )
    }
    public static var historyContentCapability: ContentTypeCapabilityV2 {
        ContentTypeCapabilityV2(historyContentType)
    }
    public static let maximumSynchronizationPages = 32
    public static let maximumAdmissionHistoryEvents = 128
    public static let minimumAdmissionHandoffValidity: TimeInterval = 15 * 60
    public static let receiveRouteRotationLeadTime: TimeInterval = 60 * 60
    /// Large fixed packets keep post-quantum membership transitions bounded to
    /// a small number of relay operations. Every packet remains padded to the
    /// same board profile; application events themselves stay capped at 32 KiB.
    public static var routePolicy: OpaqueRoutePolicyV2 {
        OpaqueRoutePolicyV2(
            paddingBucket: .bytes65536,
            retentionBucket: .sixHours,
            quotaBucket: .packets1024
        )
    }

    private let messagingClient: HeadlessMessagingClient
    private let admissionStateStore: NoctBoardAdmissionStateStore
    private let relay: RelayEndpoint
    private let relayAccessPassword: String?
    private var boundBoard: NoctBoardReference?
    private var admissionTestInterruption: NoctBoardAdmissionTestInterruption?

    init(
        messagingClient: HeadlessMessagingClient,
        relay: RelayEndpoint,
        relayAccessPassword: String?,
        board: NoctBoardReference?,
        admissionStateStore: NoctBoardAdmissionStateStore = NoctBoardAdmissionStateStore()
    ) {
        self.messagingClient = messagingClient
        self.admissionStateStore = admissionStateStore
        self.relay = relay
        self.relayAccessPassword = relayAccessPassword
        self.boundBoard = board
        self.admissionTestInterruption = nil
    }

    func setAdmissionTestInterruption(
        _ interruption: NoctBoardAdmissionTestInterruption?
    ) {
        admissionTestInterruption = interruption
    }

    public static func open(
        configuration: NoctBoardClientOpenConfiguration,
        board: NoctBoardReference? = nil
    ) async throws -> NoctBoardClient {
        try validateRelayAuthentication(
            endpoint: configuration.relay,
            accessPassword: configuration.relayAccessPassword
        )
        let displayName = configuration.displayName
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let scope = configuration.storageScopeIdentifier?
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard !displayName.isEmpty,
              displayName.utf8.count <= 512,
              configuration.relay.isStructurallyValid,
              configuration.relayAccessPassword?.utf8.count ?? 0
                <= RelayClient.maxAuthenticationBytes,
              configuration.stateProtection != .encrypted || scope?.isEmpty == false else {
            throw NoctBoardTransportError.invalidOpenConfiguration
        }

        let store = ClientStateStore(
            fileURL: configuration.stateFileURL,
            protection: configuration.stateProtection,
            storageScopeIdentifier: scope
        )
        let client = try await HeadlessMessagingClient.open(
            stateStore: store,
            displayName: displayName
        )
        try await client.upsertRelayPreference(
            endpoint: configuration.relay,
            name: "Noct Board relay",
            accessPassword: configuration.relayAccessPassword
        )
        let result = NoctBoardClient(
            messagingClient: client,
            relay: configuration.relay,
            relayAccessPassword: configuration.relayAccessPassword,
            board: board,
            admissionStateStore: NoctBoardAdmissionStateStore(
                stateFileURL: configuration.stateFileURL,
                protection: configuration.stateProtection,
                storageScopeIdentifier: scope!
            )
        )
        if let board {
            try await result.requireLocalGroup(board)
            try await result.requireBoardAccessVerified(board)
        }
        return result
    }

    static func validateRelayAuthentication(
        endpoint: RelayEndpoint,
        accessPassword: String?
    ) throws {
        guard accessPassword?.isEmpty != false || endpoint.useTLS else {
            throw NoctBoardTransportError.insecureRelayAuthentication
        }
    }

    public func boardReference() -> NoctBoardReference? { boundBoard }

    /// Binds this product instance to exactly one already-admitted Noctweave
    /// group. NoctBoard v1 requires the board ID to equal the group ID.
    public func bindBoard(_ board: NoctBoardReference) async throws {
        if let boundBoard {
            guard boundBoard == board else {
                throw NoctBoardTransportError.boardAlreadyBound
            }
            try await requireBoardAccessVerified(board)
            return
        }
        try await requireLocalGroup(board)
        try await requireBoardAccessVerified(board)
        boundBoard = board
    }

    public func createBoard(
        name: String,
        boardID: UUID = UUID(),
        initialThreadID: UUID = UUID(),
        initialEventID: UUID = UUID(),
        initialClientTransactionID: UUID = UUID(),
        createdAt: Date = Date()
    ) async throws -> NoctBoardCreationResult {
        guard boundBoard == nil else { throw NoctBoardTransportError.boardAlreadyBound }
        let initialThread = NoctBoardCreateThread(threadID: initialThreadID, title: name)
        guard initialThread.isStructurallyValid else {
            throw NoctBoardTransportError.invalidBoardName
        }

        let canonicalDate = Self.canonicalDate(createdAt)
        let board = try NoctBoardReference(id: boardID)
        let metadataDigest = Self.boardMetadataDigest(boardID: boardID)
        let created = try await messagingClient.createGroup(
            groupID: board.groupID,
            relay: relay,
            metadataDigest: metadataDigest,
            policy: Self.routePolicy,
            contentTypes: Self.groupContentCapabilities,
            createdAt: canonicalDate
        )
        boundBoard = board

        do {
            let initialPublication = try await publish(
                .createThread(initialThread),
                eventID: initialEventID,
                clientTransactionID: initialClientTransactionID,
                createdAt: canonicalDate
            )
            return NoctBoardCreationResult(
                board: board,
                ownerMemberHandle: created.ownerMemberHandle,
                ownerCredentialHandle: created.ownerCredentialHandle,
                initialThreadID: initialThreadID,
                initialPublication: initialPublication
            )
        } catch {
            // The group and any prepared exact operation remain durably stored.
            // Preserve the binding so the caller can inspect or resume it.
            throw error
        }
    }

    /// Completes a board creation from caller-persisted identifiers. If the
    /// group was durably created before a relay/process failure, this binds the
    /// existing local group and retries the exact initial application event.
    /// If no such local group exists, it creates it with the same identifiers.
    public func recoverBoardCreation(
        name: String,
        boardID: UUID,
        initialThreadID: UUID,
        initialEventID: UUID,
        initialClientTransactionID: UUID,
        createdAt: Date = Date()
    ) async throws -> NoctBoardCreationResult {
        let initialThread = NoctBoardCreateThread(threadID: initialThreadID, title: name)
        guard initialThread.isStructurallyValid else {
            throw NoctBoardTransportError.invalidBoardName
        }
        let board = try NoctBoardReference(id: boardID)

        if let boundBoard {
            guard boundBoard == board else {
                throw NoctBoardTransportError.boardAlreadyBound
            }
        } else {
            do {
                try await requireLocalGroup(board)
                boundBoard = board
            } catch NoctBoardTransportError.boardNotPresentInLocalState {
                return try await createBoard(
                    name: name,
                    boardID: boardID,
                    initialThreadID: initialThreadID,
                    initialEventID: initialEventID,
                    initialClientTransactionID: initialClientTransactionID,
                    createdAt: createdAt
                )
            }
        }

        let initialPublication = try await publish(
            .createThread(initialThread),
            eventID: initialEventID,
            clientTransactionID: initialClientTransactionID,
            createdAt: createdAt
        )
        let runtime = try await messagingClient.openGroupRuntime(groupID: board.groupID)
        let localCredential = await runtime.snapshot().localCredential
        return NoctBoardCreationResult(
            board: board,
            ownerMemberHandle: localCredential.memberHandle,
            ownerCredentialHandle: localCredential.credentialHandle,
            initialThreadID: initialThreadID,
            initialPublication: initialPublication
        )
    }

    /// Builds a strict event from the durable local group log, rejects a known
    /// unauthorized transition locally, then durably prepares exact encrypted
    /// Noctweave bytes before attempting relay publication.
    public func publish(
        _ operation: NoctBoardOperation,
        eventID: UUID = UUID(),
        clientTransactionID: UUID = UUID(),
        createdAt: Date = Date()
    ) async throws -> NoctBoardPublishResult {
        guard operation.isStructurallyValid else {
            throw NoctBoardTransportError.invalidBoardContainer
        }
        let board = try requiredBoard()
        try await requireBoardAccessVerified(board)
        let mutationLease = try await acquireBoardMutationLease()
        defer { mutationLease.release() }
        let runtime = try await messagingClient.openGroupRuntime(groupID: board.groupID)
        let groupState = await runtime.snapshot()
        let localCredential = groupState.localCredential
        let configuration = try Self.boardConfiguration(
            board: board,
            signedState: groupState.signedState
        )
        try Self.enforceAuditWindow(groupEventCount: groupState.events.count)
        let extracted = Self.extractBoardEvents(
            groupState.events,
            board: board,
            signedState: groupState.signedState
        )
        let projection = try NoctBoardProjector.project(
            events: extracted.events,
            configuration: configuration
        )

        if let existing = extracted.events.first(where: {
            $0.id == eventID || $0.clientTransactionID == clientTransactionID
        }) {
            guard existing.id == eventID,
                  existing.clientTransactionID == clientTransactionID,
                  existing.authorMemberHandle == localCredential.memberHandle,
                  existing.authorCredentialHandle == localCredential.credentialHandle,
                  existing.operation == operation else {
                throw NoctBoardTransportError.localAuthorizationRejected(.eventIDConflict)
            }
            let existingDigest = try NoctBoardCodec.digestHex(existing)
            let verdict = projection.ledger.entries.last(where: {
                $0.eventID == existing.id
                    && $0.clientTransactionID == existing.clientTransactionID
                    && $0.eventDigest == existingDigest
            })
            guard verdict?.outcome == .accepted || verdict?.outcome == .replayed else {
                throw NoctBoardTransportError.localAuthorizationRejected(
                    verdict?.rejectionReason
                )
            }
            if let pending = groupState.outboundTransportOperations.first(where: {
                $0.kind == .application && $0.logicalID == existing.id
            }), !pending.isComplete {
                let resumed = try await messagingClient.resumeGroupTransport(
                    groupID: board.groupID,
                    operationID: pending.id,
                    at: Self.canonicalDate(createdAt)
                )
                return NoctBoardPublishResult(
                    event: existing,
                    operationID: pending.id,
                    complete: resumed.complete,
                    disposition: NoctBoardPublicationDisposition(resumed.disposition),
                    projectionDigest: projection.projectionDigest
                )
            }
            return NoctBoardPublishResult(
                event: existing,
                operationID: nil,
                complete: true,
                disposition: .complete,
                projectionDigest: projection.projectionDigest
            )
        }

        try Self.enforceAuditWindow(
            groupEventCount: groupState.events.count,
            reservingNewEvents: 1
        )
        let consumed = projection.ledger.entries.filter(\.authorChainConsumed)
        guard let maximumClock = consumed.map(\.logicalClock).max() else {
            return try await publish(
                operation,
                eventID: eventID,
                clientTransactionID: clientTransactionID,
                createdAt: createdAt,
                board: board,
                groupState: groupState,
                existingEvents: extracted.events,
                logicalClock: 0,
                authorSequence: 0,
                previousAuthorEventDigest: nil,
                localCredential: localCredential
            )
        }
        guard maximumClock < NoctBoardLimits.maximumLogicalInteger else {
            throw NoctBoardTransportError.logicalClockExhausted
        }

        let nextSequence: UInt64
        let previousDigest: Data?
        if let previous = consumed.last(where: {
            $0.authorMemberHandle == localCredential.memberHandle
                && $0.authorCredentialHandle == localCredential.credentialHandle
        }) {
            guard previous.authorSequence < NoctBoardLimits.maximumLogicalInteger,
                  let digest = Self.data(hex: previous.eventDigest) else {
                throw NoctBoardTransportError.authorSequenceExhausted
            }
            nextSequence = previous.authorSequence + 1
            previousDigest = digest
        } else {
            nextSequence = 0
            previousDigest = nil
        }
        return try await publish(
            operation,
            eventID: eventID,
            clientTransactionID: clientTransactionID,
            createdAt: createdAt,
            board: board,
            groupState: groupState,
            existingEvents: extracted.events,
            logicalClock: maximumClock + 1,
            authorSequence: nextSequence,
            previousAuthorEventDigest: previousDigest,
            localCredential: localCredential
        )
    }

    public func synchronize() async throws -> NoctBoardSynchronizationResult {
        let board = try requiredBoard()
        try await requireBoardAccessVerified(board)
        let mutationLease = try await acquireBoardMutationLease()
        defer { mutationLease.release() }
        let rotation = try await rotateReceiveRouteIfNeeded(
            board: board,
            at: Self.canonicalDate(Date())
        )
        var receivedEventIDs: [UUID] = []
        var receivedEventCount = 0
        var pageCount = 0
        var hasMore = true
        while hasMore, pageCount < Self.maximumSynchronizationPages {
            let page = try await messagingClient.noctBoardSyncTransfer(
                groupID: board.groupID
            )
            receivedEventIDs.append(contentsOf: page.receivedEventIDs)
            receivedEventCount += page.receivedEventCount
            hasMore = page.hasMore
            pageCount += 1
        }
        guard !hasMore else {
            throw NoctBoardTransportError.synchronizationPageLimitReached
        }
        // Epoch processing can stage an exact route re-announcement. Resume it
        // before returning so peers can continue fanout after membership
        // changes without requiring product callers to understand journals.
        let maintenance = try await messagingClient.maintainGroup(groupID: board.groupID)
        let routeAnnouncementComplete = rotation.map { rotation in
            guard !rotation.announcementComplete,
                  let operationID = rotation.announcementOperationID else {
                return rotation.announcementComplete
            }
            return maintenance.transportResults.last(where: {
                $0.operationID == operationID
            })?.complete ?? false
        }
        guard !maintenance.requiresFollowUp, routeAnnouncementComplete != false else {
            throw NoctBoardTransportError.publicationIncomplete(.pendingRetry)
        }
        let current = try await snapshot()
        let receivedIDs = Set(receivedEventIDs)
        let receivedHistoryEventIDs = Set(current.historyBootstrapProvenance.compactMap {
            receivedIDs.contains($0.groupEventID) ? $0.reassertedEventID : nil
        })
        return NoctBoardSynchronizationResult(
            receivedGroupEventCount: receivedEventCount,
            receivedBoardEventIDs: current.events
                .filter {
                    receivedIDs.contains($0.id) || receivedHistoryEventIDs.contains($0.id)
                }
                .map(\.id),
            snapshot: current
        )
    }

    public func snapshot() async throws -> NoctBoardClientSnapshot {
        let board = try requiredBoard()
        try await requireBoardAccessVerified(board)
        let runtime = try await messagingClient.openGroupRuntime(groupID: board.groupID)
        let groupState = await runtime.snapshot()
        let configuration = try Self.boardConfiguration(
            board: board,
            signedState: groupState.signedState
        )
        try Self.enforceAuditWindow(groupEventCount: groupState.events.count)
        let extracted = Self.extractBoardEvents(
            groupState.events,
            board: board,
            signedState: groupState.signedState
        )
        let result = try NoctBoardProjector.project(
            events: extracted.events,
            configuration: configuration
        )
        return NoctBoardClientSnapshot(
            board: board,
            groupEpoch: groupState.signedState.epoch,
            localMemberHandle: groupState.localCredential.memberHandle,
            localCredentialHandle: groupState.localCredential.credentialHandle,
            events: extracted.events,
            historyBootstrapProvenance: extracted.historyBootstrapProvenance,
            containerRejections: extracted.rejections,
            result: result
        )
    }

    public func auditJSONL() async throws -> Data {
        let current = try await snapshot()
        return try NoctBoardAuditExporter.jsonLines(
            for: current.result,
            containerRejections: current.containerRejections.map {
                NoctBoardAuditContainerRejection(
                    groupEventID: $0.groupEventID,
                    reason: $0.reason.rawValue
                )
            },
            historyAttestations: current.historyBootstrapProvenance.map {
                NoctBoardAuditHistoryAttestation(
                    groupEventID: $0.groupEventID,
                    reassertedEventID: $0.reassertedEventID,
                    assertedByMemberHandle: $0.assertedByMemberHandle,
                    assertedByCredentialHandle: $0.assertedByCredentialHandle
                )
            }
        )
    }

    public func relayHealth(at date: Date = Date()) async throws -> NoctBoardRelayHealth {
        let request = RelayRequest.health()
        let response = try await RelayClient(
            endpoint: relay,
            authToken: relayAccessPassword
        ).send(request)
        guard response.isResponse(to: request),
              response.status == .success,
              response.successBody == .empty else {
            throw NoctBoardTransportError.relayUnhealthy
        }
        return NoctBoardRelayHealth(
            healthy: true,
            checkedAt: Self.canonicalDate(date),
            endpoint: relay
        )
    }

    public func prepareAdmission(
        to board: NoctBoardReference,
        invitationBindingDigest: Data,
        expiresAt: Date,
        createdAt: Date = Date()
    ) async throws -> NoctBoardAdmissionRequest {
        guard boundBoard == nil || boundBoard == board,
              invitationBindingDigest.count == 32 else {
            throw NoctBoardTransportError.boardBindingMismatch
        }
        let canonicalCreatedAt = Self.canonicalDate(createdAt)
        let canonicalExpiresAt = Self.canonicalDate(expiresAt)
        let clientState = await messagingClient.snapshot()
        guard !clientState.activePersona.groupRuntimes.contains(where: {
            $0.groupId == board.groupID
        }) else {
            throw NoctBoardTransportError.invalidGroupState
        }
        let matchingGroup = clientState.activePersona.pendingGroupAdmissions.filter {
            $0.groupID == board.groupID
        }
        let admissionID: UUID
        let admission: GroupCredentialAdmissionV2
        if let existing = matchingGroup.first {
            guard matchingGroup.count == 1,
                  Self.pendingAdmissionMatchesPreparationPlan(
                      existing,
                      board: board,
                      invitationBindingDigest: invitationBindingDigest,
                      expiresAt: canonicalExpiresAt,
                      relay: relay
                  ) else {
                throw NoctBoardTransportError.invalidGroupState
            }
            admissionID = existing.id
            admission = existing.admission
        } else {
            let prepared = try await messagingClient.prepareGroupAdmission(
                groupID: board.groupID,
                invitationBindingDigest: invitationBindingDigest,
                relay: relay,
                policy: Self.routePolicy,
                contentTypes: Self.groupContentCapabilities,
                expiresAt: canonicalExpiresAt,
                createdAt: canonicalCreatedAt
            )
            admissionID = prepared.admissionID
            admission = prepared.admission
        }
        let route = try await messagingClient.resumeGroupAdmissionRoute(
            admissionID: admissionID,
            at: canonicalCreatedAt
        )
        return NoctBoardAdmissionRequest(
            board: board,
            admissionID: admissionID,
            invitationBindingDigest: invitationBindingDigest,
            admission: admission,
            initialRouteSet: route.routeSet
        )
    }

    public func admit(
        _ request: NoctBoardAdmissionRequest,
        createdAt: Date = Date()
    ) async throws -> NoctBoardAdmissionPackage {
        let board = try requiredBoard()
        try await requireBoardAccessVerified(board)
        try request.validateArtifact()
        guard request.board == board,
              request.admission.groupId == board.groupID,
              request.initialRouteSet.groupID == board.groupID else {
            throw NoctBoardTransportError.boardBindingMismatch
        }
        let requestDigest = try Self.admissionArtifactDigest(
            domain: "org.noctboard.admission-request.v1",
            request
        )
        if let existing = try await ownerAdmissionJournal(
            board: board,
            admissionID: request.admissionID
        ) {
            guard existing.requestDigest == requestDigest,
                  existing.request == request else {
                throw NoctBoardTransportError.invalidGroupState
            }
            return try await resumeOwnerAdmission(existing)
        }
        let canonicalCreatedAt = Self.canonicalDate(createdAt)
        let runtimeBeforeAdmission = try await messagingClient.openGroupRuntime(
            groupID: board.groupID
        )
        let stateBeforeAdmission = await runtimeBeforeAdmission.snapshot()
        _ = try Self.boardConfiguration(
            board: board,
            signedState: stateBeforeAdmission.signedState
        )
        try Self.enforceAuditWindow(groupEventCount: stateBeforeAdmission.events.count)
        let history = Self.extractBoardEvents(
            stateBeforeAdmission.events,
            board: board,
            signedState: stateBeforeAdmission.signedState
        ).reassertableEvents
        guard !history.isEmpty else {
            throw NoctBoardTransportError.admissionHistoryIncomplete
        }
        guard history.count <= Self.maximumAdmissionHistoryEvents else {
            throw NoctBoardTransportError.admissionHistoryWindowExceeded
        }
        try Self.enforceAuditWindow(
            groupEventCount: stateBeforeAdmission.events.count,
            reservingNewEvents: history.count
        )
        let historyManifest = Self.admissionHistoryManifest(
            history,
            admissionID: request.admissionID
        )
        let idempotencyKey = Self.idempotencyKey(
            domain: "org.noctboard.admission.v1",
            id: request.admissionID
        )
        guard let admissionDigest = request.admission.digest else {
            throw NoctBoardTransportError.invalidGroupState
        }
        let announcements = try Self.existingMemberRouteAnnouncements(
            state: stateBeforeAdmission,
            observedAt: canonicalCreatedAt
        )
        let handoffExpiry = Self.admissionHandoffExpiry(
            admissionExpiresAt: request.admission.expiresAt,
            initialRouteExpiresAt: request.initialRouteSet.expiresAt,
            existingRouteExpiresAt: announcements.map(\.routeSet.expiresAt)
        )
        guard handoffExpiry >= canonicalCreatedAt.addingTimeInterval(
            Self.minimumAdmissionHandoffValidity
        ) else {
            throw NoctBoardTransportError.admissionValidityInsufficient
        }
        let anchor = try GroupJoinAnchorV2(
            id: Self.deterministicUUID(
                domain: "org.noctboard.admission-anchor.v1",
                admissionID: request.admissionID,
                eventID: request.admission.id,
                eventDigest: requestDigest
            ),
            baseState: stateBeforeAdmission.signedState,
            destinationMemberHandle: request.admission.memberHandle,
            destinationCredentialHandle: request.admission.credentialHandle,
            destinationAdmissionDigest: admissionDigest,
            issuedAt: canonicalCreatedAt,
            expiresAt: handoffExpiry
        )
        var journal = NoctBoardOwnerAdmissionJournal(
            revision: 0,
            board: board,
            admissionID: request.admissionID,
            request: request,
            requestDigest: requestDigest,
            idempotencyKey: idempotencyKey,
            anchor: anchor,
            existingMemberRouteAnnouncements: announcements,
            historyRecords: history.map {
                NoctBoardOwnerHistoryRecord(
                    eventID: $0.event.id,
                    signedEventRecordBytes: $0.signedRecordBytes
                )
            },
            historyManifest: historyManifest,
            baseGroupEventCount: stateBeforeAdmission.events.count,
            createdAt: canonicalCreatedAt,
            expiresAt: handoffExpiry,
            packageBytes: nil,
            packageDigest: nil,
            pendingOperationIDs: [],
            phase: .prepared
        )
        journal = try await saveOwnerAdmissionJournal(journal)
        if admissionTestInterruption == .afterOwnerPlanJournaled {
            admissionTestInterruption = nil
            throw NoctBoardTransportError.publicationIncomplete(.pendingRetry)
        }
        return try await resumeOwnerAdmission(journal)
    }

    public func completeAdmission(
        request: NoctBoardAdmissionRequest,
        package: NoctBoardAdmissionPackage,
        observedAt: Date = Date()
    ) async throws {
        guard request.board == package.board,
              request.admissionID == package.admissionID,
              boundBoard == nil || boundBoard == package.board else {
            throw NoctBoardTransportError.boardBindingMismatch
        }
        let observedAt = Self.canonicalDate(observedAt)
        try Self.validateAdmissionPackage(request: request, package: package)
        let requestDigest = try Self.admissionArtifactDigest(
            domain: "org.noctboard.admission-request.v1",
            request
        )
        let packageDigest = try Self.admissionArtifactDigest(
            domain: "org.noctboard.admission-package.v1",
            package
        )
        guard let destinationAdmissionDigest = request.admission.digest else {
            throw NoctBoardTransportError.invalidGroupState
        }
        let receipt = NoctBoardJoinAdmissionReceipt(
            board: package.board,
            admissionID: package.admissionID,
            originJoinAnchorID: package.anchor.id,
            destinationMemberHandle: request.admission.memberHandle,
            destinationCredentialHandle: request.admission.credentialHandle,
            destinationAdmissionDigest: destinationAdmissionDigest,
            requestDigest: requestDigest,
            packageDigest: packageDigest,
            historyManifest: package.historyManifest,
            expiresAt: package.expiresAt,
            status: .pending
        )
        var clientState = await messagingClient.snapshot()
        var alreadyInstalled = clientState.activePersona.groupRuntimes.contains {
            $0.groupId == package.board.groupID
        }
        var pendingAdmission = clientState.activePersona.pendingGroupAdmissions.first {
            $0.id == request.admissionID
        }
        if !alreadyInstalled {
            guard let localPendingAdmission = pendingAdmission,
                  Self.pendingAdmissionMatchesRequest(
                      localPendingAdmission,
                      request: request
                  ) else {
                throw NoctBoardTransportError.invalidGroupState
            }
        }
        let existingReceipt: NoctBoardJoinAdmissionReceipt?
        do {
            existingReceipt = try await admissionStateStore.joinReceipt(
                board: package.board
            )
        } catch {
            throw NoctBoardTransportError.invalidGroupState
        }
        if let existingReceipt {
            guard existingReceipt.admissionID == receipt.admissionID,
                  existingReceipt.originJoinAnchorID == receipt.originJoinAnchorID,
                  existingReceipt.destinationMemberHandle
                    == receipt.destinationMemberHandle,
                  existingReceipt.destinationCredentialHandle
                    == receipt.destinationCredentialHandle,
                  existingReceipt.requestDigest == requestDigest,
                  existingReceipt.packageDigest == packageDigest,
                  existingReceipt.historyManifest == package.historyManifest,
                  existingReceipt.expiresAt == package.expiresAt else {
                throw NoctBoardTransportError.invalidGroupState
            }
            if existingReceipt.status == .verified {
                guard alreadyInstalled else {
                    throw NoctBoardTransportError.invalidGroupState
                }
                boundBoard = package.board
                try await requireBoardAccessVerified(package.board)
                return
            }
        } else {
            guard !alreadyInstalled else {
                // A receipt must have been committed before accepting Welcome.
                // Never reconstruct missing local authority from runtime state.
                throw NoctBoardTransportError.admissionVerificationPending
            }
            guard Self.admissionArtifactIsUsableForFreshInstall(
                observedAt: observedAt,
                expiresAt: package.expiresAt
            ) else {
                throw NoctBoardTransportError.admissionPackageExpired
            }
            guard let localPendingAdmission = pendingAdmission,
                  localPendingAdmission.anchor == nil,
                  localPendingAdmission.transition == nil,
                  localPendingAdmission.welcome == nil,
                  localPendingAdmission.peerRouteCache.entries.isEmpty else {
                // NoctBoard must durably commit its receipt before any
                // irreversible admission control artifact is accepted.
                throw NoctBoardTransportError.admissionVerificationPending
            }
            do {
                try await admissionStateStore.beginJoinReceipt(receipt)
            } catch {
                throw NoctBoardTransportError.invalidGroupState
            }
        }
        if !alreadyInstalled,
           !Self.admissionArtifactIsUsableForFreshInstall(
               observedAt: observedAt,
               expiresAt: package.expiresAt
           ) {
            guard let existingReceipt,
                  existingReceipt.status == .pending,
                  let resumablePendingAdmission = pendingAdmission,
                  resumablePendingAdmission.isReadyToJoin,
                  Self.pendingAdmissionProgressMatchesPackage(
                      resumablePendingAdmission,
                      package: package
                  ),
                  let completionObservedAt = resumablePendingAdmission.completionObservedAt,
                  completionObservedAt <= package.expiresAt else {
                throw NoctBoardTransportError.admissionPackageExpired
            }
            let completed = try await messagingClient.acceptGroupAdmissionWelcome(
                admissionID: request.admissionID,
                welcome: package.welcome,
                observedAt: resumablePendingAdmission.welcomeObservedAt
                    ?? completionObservedAt
            )
            guard completed.completed else {
                throw NoctBoardTransportError.invalidGroupState
            }
            clientState = await messagingClient.snapshot()
            alreadyInstalled = clientState.activePersona.groupRuntimes.contains {
                $0.groupId == package.board.groupID
            }
            pendingAdmission = clientState.activePersona.pendingGroupAdmissions.first {
                $0.id == request.admissionID
            }
            guard alreadyInstalled, pendingAdmission == nil else {
                throw NoctBoardTransportError.invalidGroupState
            }
        }
        if !alreadyInstalled {
            _ = try await messagingClient.pinGroupJoinAnchor(
                admissionID: request.admissionID,
                anchor: package.anchor,
                invitationBindingDigest: request.invitationBindingDigest,
                observedAt: observedAt
            )
            for announcement in package.existingMemberRouteAnnouncements {
                _ = try await messagingClient.acceptGroupAdmissionRouteAnnouncement(
                    admissionID: request.admissionID,
                    announcement: announcement,
                    observedAt: observedAt
                )
            }
            _ = try await messagingClient.acceptGroupAdmissionTransition(
                admissionID: request.admissionID,
                transition: package.transition,
                observedAt: observedAt
            )
            let completed = try await messagingClient.acceptGroupAdmissionWelcome(
                admissionID: request.admissionID,
                welcome: package.welcome,
                observedAt: observedAt
            )
            guard completed.completed else {
                throw NoctBoardTransportError.invalidGroupState
            }
        }
        let runtime = try await messagingClient.openGroupRuntime(
            groupID: package.board.groupID
        )
        let installed = await runtime.snapshot()
        guard installed.localCredential.memberHandle == request.admission.memberHandle,
              installed.localCredential.credentialHandle
                == request.admission.credentialHandle,
              installed.originJoinAnchorID == package.anchor.id else {
            throw NoctBoardTransportError.invalidGroupState
        }
        _ = try Self.boardConfiguration(
            board: package.board,
            signedState: installed.signedState
        )
        // The irreversible runtime is now installed, but the pending receipt
        // keeps every board API fail-closed until exact history verification.
        boundBoard = package.board
        let groupState = try await synchronizeAdmissionHistory(
            board: package.board,
            observedAt: observedAt
        )
        try Self.verifyAdmissionHistoryManifest(
            expected: package.historyManifest,
            received: Self.extractBoardEvents(
                groupState.events,
                board: package.board,
                signedState: groupState.signedState
            ).historyManifest
        )
        do {
            try await admissionStateStore.markJoinReceiptVerified(
                board: package.board,
                admissionID: package.admissionID,
                requestDigest: requestDigest,
                packageDigest: packageDigest
            )
        } catch {
            throw NoctBoardTransportError.invalidGroupState
        }
        boundBoard = package.board
        try await requireBoardAccessVerified(package.board)
    }

    public func maintain(
        at date: Date = Date(),
        forceReceiveRouteRotation: Bool = false
    ) async throws -> NoctBoardMaintenanceResult {
        let board = try requiredBoard()
        try await requireBoardAccessVerified(board)
        let mutationLease = try await acquireBoardMutationLease()
        defer { mutationLease.release() }
        let observedAt = Self.canonicalDate(date)
        let rotation = try await rotateReceiveRouteIfNeeded(
            board: board,
            at: observedAt,
            force: forceReceiveRouteRotation
        )
        let report = try await messagingClient.maintainGroup(
            groupID: board.groupID,
            at: observedAt
        )
        let announcementComplete = rotation.map { rotation in
            guard !rotation.announcementComplete,
                  let operationID = rotation.announcementOperationID else {
                return rotation.announcementComplete
            }
            return report.transportResults.last(where: {
                $0.operationID == operationID
            })?.complete ?? false
        }
        return NoctBoardMaintenanceResult(
            observedAt: report.observedAt,
            resumedTransportCount: report.transportResults.count,
            rotatedReceiveRoute: rotation != nil,
            routeAnnouncementComplete: announcementComplete,
            requiresFollowUp: report.requiresFollowUp || announcementComplete == false
        )
    }

    /// Resumes the exact bytes already persisted for one publish result. It
    /// never reconstructs an event, advances an author chain, or encrypts a
    /// replacement ciphertext.
    public func resumePublication(
        operationID: UUID,
        at date: Date = Date()
    ) async throws -> NoctBoardPublicationResumeResult {
        let board = try requiredBoard()
        try await requireBoardAccessVerified(board)
        let mutationLease = try await acquireBoardMutationLease()
        defer { mutationLease.release() }
        let result = try await messagingClient.resumeGroupTransport(
            groupID: board.groupID,
            operationID: operationID,
            at: Self.canonicalDate(date)
        )
        return NoctBoardPublicationResumeResult(
            operationID: result.operationID,
            eventID: result.logicalID,
            attemptedPublicationCount: result.attemptedPublicationCount,
            acceptedPublicationCount: result.acceptedPublicationCount,
            pendingPublicationCount: result.pendingPublicationCount,
            complete: result.complete,
            disposition: NoctBoardPublicationDisposition(result.disposition)
        )
    }

    private func publish(
        _ operation: NoctBoardOperation,
        eventID: UUID,
        clientTransactionID: UUID,
        createdAt: Date,
        board: NoctBoardReference,
        groupState: GroupRuntimeRecord,
        existingEvents: [NoctBoardEvent],
        logicalClock: UInt64,
        authorSequence: UInt64,
        previousAuthorEventDigest: Data?,
        localCredential: LocalGroupCredentialV2
    ) async throws -> NoctBoardPublishResult {
        let canonicalDate = Self.canonicalDate(createdAt)
        let milliseconds = Int64(canonicalDate.timeIntervalSince1970 * 1_000)
        let event = NoctBoardEvent(
            id: eventID,
            clientTransactionID: clientTransactionID,
            boardID: board.boardID,
            groupID: board.groupID,
            authorMemberHandle: localCredential.memberHandle,
            authorCredentialHandle: localCredential.credentialHandle,
            logicalClock: logicalClock,
            authorSequence: authorSequence,
            previousAuthorEventDigest: previousAuthorEventDigest,
            createdAtUnixMilliseconds: milliseconds,
            operation: operation
        )
        let configuration = try Self.boardConfiguration(
            board: board,
            signedState: groupState.signedState
        )
        let preflight = try NoctBoardProjector.project(
            events: existingEvents + [event],
            configuration: configuration
        )
        let candidateDigest = try NoctBoardCodec.digestHex(event)
        guard let verdict = preflight.ledger.entries.last(where: {
            $0.eventID == event.id
                && $0.clientTransactionID == event.clientTransactionID
                && $0.eventDigest == candidateDigest
        }), verdict.outcome == .accepted else {
            throw NoctBoardTransportError.localAuthorizationRejected(
                preflight.ledger.entries.last(where: {
                    $0.eventID == event.id
                        && $0.clientTransactionID == event.clientTransactionID
                        && $0.eventDigest == candidateDigest
                })?.rejectionReason
            )
        }

        let eventBytes = try NoctBoardCodec.encode(event)
        let signedRecord = NoctBoardSignedEventRecord(
            eventBytes: eventBytes,
            authorSignature: try localCredential.signingKey.sign(
                Self.eventSignaturePayload(eventBytes)
            )
        )
        let signedRecordBytes = try NoctweaveCoder.encode(signedRecord, sortedKeys: true)
        guard signedRecordBytes.count <= NoctBoardSignedEventRecord.maximumEncodedBytes else {
            throw NoctBoardTransportError.invalidBoardContainer
        }
        let content = EncodedContent(
            type: Self.contentType,
            parameters: [:],
            payload: signedRecordBytes,
            fallbackText: nil,
            disposition: .silent
        )
        guard content.isStructurallyValid else {
            throw NoctBoardTransportError.invalidBoardContainer
        }
        let groupEvent = GroupConversationEventV2(
            id: event.id,
            clientTransactionID: event.clientTransactionID,
            groupID: board.groupID,
            authorMemberHandle: event.authorMemberHandle,
            authorCredentialHandle: event.authorCredentialHandle,
            createdAt: canonicalDate,
            kind: .application,
            content: content,
            relation: nil
        )
        let prepared = try await messagingClient.prepareGroupApplication(
            groupEvent,
            at: canonicalDate
        )
        guard let operation = prepared.transportOperation else {
            return NoctBoardPublishResult(
                event: event,
                operationID: nil,
                complete: true,
                disposition: .complete,
                projectionDigest: preflight.projectionDigest
            )
        }
        let publication = try await messagingClient.resumeGroupTransport(
            groupID: board.groupID,
            operationID: operation.id,
            at: canonicalDate
        )
        return NoctBoardPublishResult(
            event: event,
            operationID: operation.id,
            complete: publication.complete,
            disposition: NoctBoardPublicationDisposition(publication.disposition),
            projectionDigest: preflight.projectionDigest
        )
    }

    private func ownerAdmissionJournal(
        board: NoctBoardReference,
        admissionID: UUID
    ) async throws -> NoctBoardOwnerAdmissionJournal? {
        do {
            return try await admissionStateStore.ownerJournal(
                board: board,
                admissionID: admissionID
            )
        } catch {
            throw NoctBoardTransportError.invalidGroupState
        }
    }

    private func saveOwnerAdmissionJournal(
        _ journal: NoctBoardOwnerAdmissionJournal
    ) async throws -> NoctBoardOwnerAdmissionJournal {
        do {
            return try await admissionStateStore.saveOwnerJournal(journal)
        } catch {
            throw NoctBoardTransportError.invalidGroupState
        }
    }

    private func acquireBoardMutationLease() async throws -> NoctBoardOwnerOperationLease {
        do {
            return try await admissionStateStore.acquireOwnerOperationLease()
        } catch {
            throw NoctBoardTransportError.publicationIncomplete(.pendingRetry)
        }
    }

    private func abortPreparedOwnerAdmissionJournal(
        _ journal: NoctBoardOwnerAdmissionJournal
    ) async throws {
        do {
            try await admissionStateStore.abortPreparedOwnerJournal(
                board: journal.board,
                admissionID: journal.admissionID,
                revision: journal.revision,
                requestDigest: journal.requestDigest
            )
        } catch {
            throw NoctBoardTransportError.invalidGroupState
        }
    }

    private func resumeOwnerAdmission(
        _ storedJournal: NoctBoardOwnerAdmissionJournal
    ) async throws -> NoctBoardAdmissionPackage {
        let operationLease = try await acquireBoardMutationLease()
        defer { operationLease.release() }
        guard let latestJournal = try await ownerAdmissionJournal(
            board: storedJournal.board,
            admissionID: storedJournal.admissionID
        ),
        latestJournal.request == storedJournal.request,
        latestJournal.requestDigest == storedJournal.requestDigest,
        latestJournal.idempotencyKey == storedJournal.idempotencyKey else {
            throw NoctBoardTransportError.invalidGroupState
        }
        var journal = latestJournal
        let board = journal.board
        if journal.phase == .complete {
            guard let package = journal.decodedPackage,
                  let packageBytes = journal.packageBytes,
                  let packageDigest = journal.packageDigest,
                  try NoctBoardAdmissionCodec.encodePackage(package) == packageBytes,
                  try Self.admissionArtifactDigest(
                      domain: "org.noctboard.admission-package.v1",
                      package
                  ) == packageDigest else {
                throw NoctBoardTransportError.invalidGroupState
            }
            try Self.validateAdmissionPackage(request: journal.request, package: package)
            return package
        }
        var runtime = try await messagingClient.openGroupRuntime(groupID: board.groupID)
        var state = await runtime.snapshot()
        var intent = state.epochIntents.first {
            $0.idempotencyKey == journal.idempotencyKey
        }
        var transportOperationID = state.outboundTransportOperations.first {
            $0.kind == .epoch && $0.logicalID == intent?.id
        }?.id
        var package = journal.decodedPackage

        if package == nil, intent == nil {
            let wallClockNow = Self.canonicalDate(Date())
            guard Self.preparedAdmissionHasMinimumValidity(
                observedAt: wallClockNow,
                expiresAt: journal.expiresAt
            ) else {
                try await abortPreparedOwnerAdmissionJournal(journal)
                throw NoctBoardTransportError.admissionValidityInsufficient
            }
            let currentAnnouncements = try? Self.existingMemberRouteAnnouncements(
                state: state,
                observedAt: journal.createdAt
            )
            let currentHistoryRecords = Self.extractBoardEvents(
                state.events,
                board: board,
                signedState: state.signedState
            ).reassertableEvents.map {
                NoctBoardOwnerHistoryRecord(
                    eventID: $0.event.id,
                    signedEventRecordBytes: $0.signedRecordBytes
                )
            }
            guard state.signedState == journal.anchor.baseState,
                  state.events.count == journal.baseGroupEventCount,
                  currentAnnouncements == journal.existingMemberRouteAnnouncements,
                  currentHistoryRecords == journal.historyRecords else {
                // Another admission or lower-level state change advanced the
                // board after this plan was journaled. Reject before Core
                // persists a new epoch/member intent, and release the exact
                // stale reservation so the caller can safely replan.
                try await abortPreparedOwnerAdmissionJournal(journal)
                throw NoctBoardTransportError.admissionPlanStale
            }
            let prepared = try await messagingClient.prepareGroupMemberAddition(
                groupID: board.groupID,
                admission: journal.request.admission,
                initialRouteSet: journal.request.initialRouteSet,
                role: .member,
                anchorExpiresAt: journal.expiresAt,
                idempotencyKey: journal.idempotencyKey,
                createdAt: journal.createdAt
            )
            guard prepared.existingMemberRouteAnnouncements
                    == journal.existingMemberRouteAnnouncements,
                  prepared.transition.commit.createdAt == journal.createdAt,
                  prepared.anchor.expiresAt == journal.expiresAt else {
                throw NoctBoardTransportError.invalidGroupState
            }
            package = NoctBoardAdmissionPackage(
                board: board,
                admissionID: journal.admissionID,
                anchor: journal.anchor,
                transition: prepared.transition,
                welcome: prepared.welcome,
                existingMemberRouteAnnouncements: journal.existingMemberRouteAnnouncements,
                historyManifest: journal.historyManifest,
                expiresAt: journal.expiresAt
            )
            transportOperationID = prepared.transportOperation?.id
            runtime = try await messagingClient.openGroupRuntime(groupID: board.groupID)
            state = await runtime.snapshot()
            intent = state.epochIntents.first {
                $0.idempotencyKey == journal.idempotencyKey
            }
            if admissionTestInterruption == .afterCoreEpochPrepared {
                admissionTestInterruption = nil
                throw NoctBoardTransportError.publicationIncomplete(.pendingRetry)
            }
        }

        if let intent {
            guard intent.idempotencyKey == journal.idempotencyKey,
                  intent.createdAt == journal.createdAt,
                  intent.groupId == board.groupID,
                  intent.nextSignedState.members.contains(where: {
                      $0.id == journal.request.admission.memberHandle
                  }),
                  intent.nextSignedState.memberCredentials.contains(where: {
                      $0.memberHandle == journal.request.admission.memberHandle
                          && $0.credentialHandle
                            == journal.request.admission.credentialHandle
                  }) else {
                throw NoctBoardTransportError.invalidGroupState
            }
        } else if let package {
            // A finalized intent may have been safely compacted. The durable
            // package remains recoverable only when the installed epoch is
            // exactly the package's authenticated next state.
            guard state.signedState == package.transition.nextState else {
                throw NoctBoardTransportError.invalidGroupState
            }
        } else {
            throw NoctBoardTransportError.invalidGroupState
        }

        if package == nil, let intent {
            let transition = GroupEpochTransitionEnvelopeV2(
                commit: intent.signedCommit,
                nextState: intent.nextSignedState,
                providerCommitBytes: intent.providerCommitBytes
            )
            guard transition.isStructurallyValid,
                  let welcome = intent.signedWelcomes.first(where: {
                      $0.destinationCredentialHandle
                        == journal.request.admission.credentialHandle
                  }) else {
                throw NoctBoardTransportError.invalidGroupState
            }
            package = NoctBoardAdmissionPackage(
                board: board,
                admissionID: journal.admissionID,
                anchor: journal.anchor,
                transition: transition,
                welcome: welcome,
                existingMemberRouteAnnouncements: journal.existingMemberRouteAnnouncements,
                historyManifest: journal.historyManifest,
                expiresAt: journal.expiresAt
            )
        }
        if let intent, transportOperationID == nil, intent.phase != .finalized {
            let routeSets = journal.existingMemberRouteAnnouncements.compactMap {
                $0.routeSet.ownerCredentialHandle
                        == intent.localCredentialAfterCommit.credentialHandle
                    ? nil
                    : $0.routeSet
            } + [journal.request.initialRouteSet]
            transportOperationID = try await runtime.noctBoardRecoverEpochTransport(
                intentID: intent.id,
                routeSets: NoctBoardRouteSetsTransfer(routeSets),
                at: journal.createdAt
            )
        }

        guard let package else {
            throw NoctBoardTransportError.invalidGroupState
        }
        try Self.validateAdmissionPackage(request: journal.request, package: package)
        let packageBytes = try NoctBoardAdmissionCodec.encodePackage(package)
        let packageDigest = try Self.admissionArtifactDigest(
            domain: "org.noctboard.admission-package.v1",
            package
        )
        var pendingIDs = journal.pendingOperationIDs
        if let transportOperationID, !pendingIDs.contains(transportOperationID) {
            pendingIDs.append(transportOperationID)
        }
        journal = journal.replacing(
            packageBytes: packageBytes,
            packageDigest: packageDigest,
            pendingOperationIDs: pendingIDs,
            phase: .epochCommitted
        )
        journal = try await saveOwnerAdmissionJournal(journal)

        if admissionTestInterruption == .afterEpochPackageJournaled {
            admissionTestInterruption = nil
            throw NoctBoardTransportError.publicationIncomplete(.pendingRetry)
        }

        if let transportOperationID {
            let resumed = try await messagingClient.resumeGroupTransport(
                groupID: board.groupID,
                operationID: transportOperationID,
                at: journal.createdAt
            )
            guard resumed.complete else {
                throw NoctBoardTransportError.publicationIncomplete(
                    NoctBoardPublicationDisposition(resumed.disposition)
                )
            }
            pendingIDs.removeAll { $0 == transportOperationID }
            journal = journal.replacing(pendingOperationIDs: pendingIDs)
            journal = try await saveOwnerAdmissionJournal(journal)
        }

        let history = try Self.reassertableEvents(
            from: journal.historyRecords,
            signedState: journal.anchor.baseState
        )
        journal = try await publishAdmissionHistory(
            history,
            admissionID: journal.admissionID,
            board: board,
            initialRouteSet: journal.request.initialRouteSet,
            at: journal.createdAt,
            ownerJournal: journal
        )
        journal = journal.compactedComplete(
            packageBytes: packageBytes,
            packageDigest: packageDigest
        )
        journal = try await saveOwnerAdmissionJournal(journal)
        guard journal.packageBytes == packageBytes,
              journal.packageDigest == packageDigest else {
            throw NoctBoardTransportError.invalidGroupState
        }
        return package
    }

    private func synchronizeAdmissionHistory(
        board: NoctBoardReference,
        observedAt: Date
    ) async throws -> GroupRuntimeRecord {
        var pageCount = 0
        var hasMore = true
        while hasMore, pageCount < Self.maximumSynchronizationPages {
            let page = try await messagingClient.noctBoardSyncTransfer(
                groupID: board.groupID
            )
            hasMore = page.hasMore
            pageCount += 1
        }
        guard !hasMore else {
            throw NoctBoardTransportError.synchronizationPageLimitReached
        }
        let maintenance = try await messagingClient.maintainGroup(
            groupID: board.groupID,
            at: observedAt
        )
        guard !maintenance.requiresFollowUp else {
            throw NoctBoardTransportError.publicationIncomplete(.pendingRetry)
        }
        let runtime = try await messagingClient.openGroupRuntime(groupID: board.groupID)
        return await runtime.snapshot()
    }

    private static func admissionArtifactDigest<T: Encodable>(
        domain: String,
        _ value: T
    ) throws -> Data {
        let encoded = try NoctweaveCoder.encode(value, sortedKeys: true)
        return Data(SHA256.hash(data: Data(domain.utf8) + Data([0]) + encoded))
    }

    static func admissionHandoffExpiry(
        admissionExpiresAt: Date,
        initialRouteExpiresAt: Date,
        existingRouteExpiresAt: [Date]
    ) -> Date {
        ([admissionExpiresAt, initialRouteExpiresAt] + existingRouteExpiresAt)
            .min() ?? min(admissionExpiresAt, initialRouteExpiresAt)
    }

    static func admissionArtifactIsUsableForFreshInstall(
        observedAt: Date,
        expiresAt: Date
    ) -> Bool {
        observedAt.timeIntervalSince1970.isFinite
            && expiresAt.timeIntervalSince1970.isFinite
            && observedAt < expiresAt
    }

    static func preparedAdmissionHasMinimumValidity(
        observedAt: Date,
        expiresAt: Date
    ) -> Bool {
        admissionArtifactIsUsableForFreshInstall(
            observedAt: observedAt,
            expiresAt: expiresAt
        ) && observedAt.addingTimeInterval(minimumAdmissionHandoffValidity) <= expiresAt
    }

    private static func pendingAdmissionMatchesPreparationPlan(
        _ pending: PendingGroupAdmissionV2,
        board: NoctBoardReference,
        invitationBindingDigest: Data,
        expiresAt: Date,
        relay: RelayEndpoint
    ) -> Bool {
        let expectedContentTypes = groupContentCapabilities.sorted {
            ($0.authority, $0.name) < ($1.authority, $1.name)
        }
        guard pending.groupID == board.groupID,
              pending.invitationBindingDigest == invitationBindingDigest,
              pending.admission.groupId == board.groupID,
              pending.admission.expiresAt == expiresAt,
              pending.admission.contentTypes == expectedContentTypes,
              pending.localCredential.memberHandle == pending.admission.memberHandle,
              pending.localCredential.credentialHandle
                == pending.admission.credentialHandle else {
            return false
        }
        if let route = pending.pendingRoute {
            return route.relay == relay
                && route.createRequest.lease.policy == routePolicy
        }
        guard let route = pending.activeRoute else { return false }
        return route.localRoute.relay == relay
            && route.localRoute.route.lease.policy == routePolicy
    }

    private static func pendingAdmissionMatchesRequest(
        _ pending: PendingGroupAdmissionV2,
        request: NoctBoardAdmissionRequest
    ) -> Bool {
        pending.id == request.admissionID
            && pending.groupID == request.board.groupID
            && pending.invitationBindingDigest == request.invitationBindingDigest
            && pending.admission == request.admission
            && pending.localCredential.memberHandle == request.admission.memberHandle
            && pending.localCredential.credentialHandle
                == request.admission.credentialHandle
            && pending.advertisedRouteSet == request.initialRouteSet
    }

    private static func pendingAdmissionProgressMatchesPackage(
        _ pending: PendingGroupAdmissionV2,
        package: NoctBoardAdmissionPackage
    ) -> Bool {
        let cachedAnnouncements = pending.peerRouteCache.entries.map(\.announcement)
            .sorted {
                $0.routeSet.ownerCredentialHandle.rawValue
                    < $1.routeSet.ownerCredentialHandle.rawValue
            }
        return pending.anchor == package.anchor
            && pending.transition == package.transition
            && pending.welcome == package.welcome
            && cachedAnnouncements == package.existingMemberRouteAnnouncements
    }

    private static func validateAdmissionPackage(
        request: NoctBoardAdmissionRequest,
        package: NoctBoardAdmissionPackage
    ) throws {
        try request.validateArtifact()
        try package.validateArtifact()
        let manifest = package.historyManifest
        let sortedManifest = manifest.sorted {
            $0.historyGroupEventID.uuidString < $1.historyGroupEventID.uuidString
        }
        let announcementHandles = package.existingMemberRouteAnnouncements.map {
            $0.routeSet.ownerCredentialHandle
        }
        let expectedAnnouncementHandles = package.anchor.baseState.activeCredentials
            .map(\.credentialHandle)
            .sorted { $0.rawValue < $1.rawValue }
        guard request.board == package.board,
              request.admissionID == package.admissionID,
              request.admission.groupId == package.board.groupID,
              request.initialRouteSet.groupID == package.board.groupID,
              package.anchor.baseState.groupId == package.board.groupID,
              package.transition.commit.groupId == package.board.groupID,
              package.transition.nextState.groupId == package.board.groupID,
              package.welcome.groupId == package.board.groupID,
              package.transition.commit.operation == .addMember,
              package.transition.commit.admissionProjection == request.admission,
              package.anchor.destinationMemberHandle == request.admission.memberHandle,
              package.anchor.destinationCredentialHandle
                == request.admission.credentialHandle,
              package.welcome.destinationCredentialHandle
                == request.admission.credentialHandle,
              package.welcome.destinationAdmissionDigest == request.admission.digest,
              package.expiresAt == package.anchor.expiresAt,
              package.expiresAt <= request.initialRouteSet.expiresAt,
              package.expiresAt <= request.admission.expiresAt,
              package.expiresAt <= package.welcome.expiresAt,
              !manifest.isEmpty,
              manifest.count <= maximumAdmissionHistoryEvents,
              manifest == sortedManifest,
              Set(manifest.map(\.historyGroupEventID)).count == manifest.count,
              Set(manifest.map(\.eventID)).count == manifest.count,
              Set(manifest.map(\.signedEventRecordDigest)).count == manifest.count,
              manifest.allSatisfy({ entry in
                  entry.isStructurallyValid
                      && entry.historyGroupEventID == deterministicUUID(
                          domain: "org.noctboard.history.event.v1",
                          admissionID: package.admissionID,
                          eventID: entry.eventID,
                          eventDigest: entry.signedEventRecordDigest
                      )
              }),
              package.existingMemberRouteAnnouncements.count <= 128,
              announcementHandles == expectedAnnouncementHandles,
              Set(announcementHandles).count == announcementHandles.count,
              package.existingMemberRouteAnnouncements.allSatisfy({
                  $0.groupID == package.board.groupID
                      && $0.stateEpoch <= package.anchor.baseState.epoch
                      && package.expiresAt <= $0.routeSet.expiresAt
              }) else {
            throw NoctBoardTransportError.invalidGroupState
        }
        _ = try package.transition.commit.verifiedTransition(
            from: package.anchor.baseState,
            observedAt: package.transition.commit.createdAt
        )
        _ = try package.transition.nextState.verified(
            previousState: package.anchor.baseState,
            commit: package.transition.commit,
            observedAt: package.transition.commit.createdAt
        )
        _ = try package.welcome.verified(
            against: package.transition.nextState,
            now: package.welcome.createdAt
        )
        for announcement in package.existingMemberRouteAnnouncements {
            _ = try announcement.verified(
                against: package.anchor.baseState,
                observedAt: package.transition.commit.createdAt
            )
        }
    }

    private static func reassertableEvents(
        from records: [NoctBoardOwnerHistoryRecord],
        signedState: SignedGroupStateV2
    ) throws -> [ReassertableEvent] {
        try records.map { stored in
            guard NoctweaveCanonicalJSON.isCanonical(stored.signedEventRecordBytes),
                  let record = try? NoctweaveCoder.decode(
                    NoctBoardSignedEventRecord.self,
                    from: stored.signedEventRecordBytes
                  ),
                  let event = try? NoctBoardCodec.decode(record.eventBytes),
                  event.id == stored.eventID,
                  let credential = signedState.memberCredentials.first(where: {
                      $0.memberHandle == event.authorMemberHandle
                          && $0.credentialHandle == event.authorCredentialHandle
                  }),
                  SigningKeyPair.verify(
                    signature: record.authorSignature,
                    data: eventSignaturePayload(record.eventBytes),
                    publicKeyData: credential.signingPublicKey
                  ) else {
                throw NoctBoardTransportError.invalidGroupState
            }
            return ReassertableEvent(
                event: event,
                signedRecordBytes: stored.signedEventRecordBytes
            )
        }
    }

    private static func existingMemberRouteAnnouncements(
        state: GroupRuntimeRecord,
        observedAt: Date
    ) throws -> [SignedGroupRouteSetAnnouncementV2] {
        var announcements: [SignedGroupRouteSetAnnouncementV2] = []
        for credential in state.signedState.activeCredentials {
            let announcement: SignedGroupRouteSetAnnouncementV2?
            if credential.credentialHandle == state.localCredential.credentialHandle {
                announcement = state.inboundTransport.advertisedRouteAnnouncement
            } else {
                announcement = state.peerRouteCache.entries.first {
                    $0.id == credential.credentialHandle
                }?.announcement
            }
            guard let announcement,
                  announcement.routeSet.ownerCredentialHandle
                    == credential.credentialHandle,
                  !announcement.routeSet.usableRoutes(at: observedAt).isEmpty else {
                throw NoctBoardTransportError.invalidGroupState
            }
            _ = try announcement.verified(
                against: state.signedState,
                observedAt: observedAt
            )
            announcements.append(announcement)
        }
        return announcements.sorted {
            $0.routeSet.ownerCredentialHandle.rawValue
                < $1.routeSet.ownerCredentialHandle.rawValue
        }
    }

    /// Re-encrypts exact canonical application history into the new epoch.
    /// Late joiners trust the immutable genesis owner's current authenticated
    /// reassertion; they cannot independently reconstruct the original outer
    /// group-envelope proof from an epoch they were not allowed to decrypt.
    private func publishAdmissionHistory(
        _ events: [ReassertableEvent],
        admissionID: UUID,
        board: NoctBoardReference,
        initialRouteSet: SignedGroupOpaqueRouteSetV2,
        at date: Date,
        ownerJournal storedJournal: NoctBoardOwnerAdmissionJournal
    ) async throws -> NoctBoardOwnerAdmissionJournal {
        guard events.count <= Self.maximumAdmissionHistoryEvents else {
            throw NoctBoardTransportError.admissionHistoryWindowExceeded
        }
        let runtime = try await messagingClient.openGroupRuntime(groupID: board.groupID)
        var state = await runtime.snapshot()
        var ownerJournal = storedJournal
        let owner = state.signedState.members.first {
            $0.addedEpoch == 1 && $0.role == .owner && $0.removedEpoch == nil
        }
        guard state.localCredential.memberHandle == owner?.id else {
            throw NoctBoardTransportError.invalidGroupState
        }

        for source in events {
            let event = source.event
            let eventDigest = Data(SHA256.hash(data: source.signedRecordBytes))
            let groupEventID = Self.deterministicUUID(
                domain: "org.noctboard.history.event.v1",
                admissionID: admissionID,
                eventID: event.id,
                eventDigest: eventDigest
            )
            let transactionID = Self.deterministicUUID(
                domain: "org.noctboard.history.transaction.v1",
                admissionID: admissionID,
                eventID: event.id,
                eventDigest: eventDigest
            )
            let record = NoctBoardHistoryRecord(
                boardID: board.boardID,
                groupID: board.groupID,
                signedEventRecordBytes: source.signedRecordBytes
            )
            let content = EncodedContent(
                type: Self.historyContentType,
                payload: try NoctweaveCoder.encode(record, sortedKeys: true),
                disposition: .silent
            )
            guard content.isStructurallyValid else {
                throw NoctBoardTransportError.invalidBoardContainer
            }
            let groupEvent = GroupConversationEventV2(
                id: groupEventID,
                clientTransactionID: transactionID,
                groupID: board.groupID,
                authorMemberHandle: state.localCredential.memberHandle,
                authorCredentialHandle: state.localCredential.credentialHandle,
                createdAt: date,
                kind: .application,
                content: content
            )
            var operationID: UUID?
            if let existing = state.events.first(where: { $0.id == groupEventID }) {
                guard existing == groupEvent else {
                    throw NoctBoardTransportError.invalidBoardContainer
                }
                operationID = state.outboundTransportOperations.first(where: {
                    $0.kind == .application
                        && $0.logicalID == groupEventID
                })?.id
                if operationID == nil,
                   state.pendingApplicationPublications.contains(where: {
                       $0.event.id == groupEventID
                   }) {
                    let additionalRouteSet = state.peerRouteCache.entries.contains(where: {
                        $0.id == initialRouteSet.ownerCredentialHandle
                    }) ? nil : NoctBoardRouteSetTransfer(initialRouteSet)
                    let prepared = try await messagingClient.noctBoardPrepareGroupApplication(
                        groupEvent,
                        additionalRouteSet: additionalRouteSet,
                        at: date
                    )
                    operationID = prepared.transportOperationID
                }
            } else {
                let additionalRouteSet = state.peerRouteCache.entries.contains(where: {
                    $0.id == initialRouteSet.ownerCredentialHandle
                }) ? nil : NoctBoardRouteSetTransfer(initialRouteSet)
                let prepared = try await messagingClient.noctBoardPrepareGroupApplication(
                    groupEvent,
                    additionalRouteSet: additionalRouteSet,
                    at: date
                )
                operationID = prepared.transportOperationID
            }
            if let operationID {
                var pendingIDs = ownerJournal.pendingOperationIDs
                if !pendingIDs.contains(operationID) {
                    pendingIDs.append(operationID)
                    ownerJournal = ownerJournal.replacing(
                        pendingOperationIDs: pendingIDs
                    )
                    ownerJournal = try await saveOwnerAdmissionJournal(ownerJournal)
                }
                let resumed = try await messagingClient.resumeGroupTransport(
                    groupID: board.groupID,
                    operationID: operationID,
                    at: date
                )
                guard resumed.complete else {
                    throw NoctBoardTransportError.publicationIncomplete(
                        NoctBoardPublicationDisposition(resumed.disposition)
                    )
                }
                pendingIDs.removeAll { $0 == operationID }
                ownerJournal = ownerJournal.replacing(
                    pendingOperationIDs: pendingIDs
                )
                ownerJournal = try await saveOwnerAdmissionJournal(ownerJournal)
            }
            state = await runtime.snapshot()
        }
        return ownerJournal
    }

    private func requiredBoard() throws -> NoctBoardReference {
        guard let boundBoard else { throw NoctBoardTransportError.boardNotBound }
        return boundBoard
    }

    private func requireBoardAccessVerified(_ board: NoctBoardReference) async throws {
        let runtime = try await messagingClient.openGroupRuntime(groupID: board.groupID)
        let state = await runtime.snapshot()
        if let localMember = state.signedState.members.first(where: {
            $0.id == state.localCredential.memberHandle && $0.removedEpoch == nil
        }), localMember.addedEpoch == 1, localMember.role == .owner {
            return
        }
        let receipt: NoctBoardJoinAdmissionReceipt?
        do {
            receipt = try await admissionStateStore.joinReceipt(board: board)
        } catch {
            throw NoctBoardTransportError.invalidGroupState
        }
        guard let receipt,
              receipt.status == .verified,
              receipt.originJoinAnchorID == state.originJoinAnchorID,
              receipt.destinationMemberHandle == state.localCredential.memberHandle,
              receipt.destinationCredentialHandle == state.localCredential.credentialHandle,
              state.signedState.memberCredentials.contains(where: {
                  $0.memberHandle == receipt.destinationMemberHandle
                      && $0.credentialHandle == receipt.destinationCredentialHandle
                      && $0.admissionDigest == receipt.destinationAdmissionDigest
                      && $0.removedEpoch == nil
              }) else {
            throw NoctBoardTransportError.admissionVerificationPending
        }
        do {
            _ = try Self.boardConfiguration(board: board, signedState: state.signedState)
            try Self.enforceAuditWindow(groupEventCount: state.events.count)
            let retained = Self.extractBoardEvents(
                state.events,
                board: board,
                signedState: state.signedState
            )
            try Self.verifyAdmissionHistoryManifest(
                expected: receipt.historyManifest,
                received: retained.historyManifest
            )
        } catch {
            throw NoctBoardTransportError.admissionVerificationPending
        }
    }

    private func requireLocalGroup(_ board: NoctBoardReference) async throws {
        let state = await messagingClient.snapshot()
        guard state.activePersona.groupRuntimes.contains(where: {
            $0.groupId == board.groupID
        }) else {
            throw NoctBoardTransportError.boardNotPresentInLocalState
        }
    }

    private func rotateReceiveRouteIfNeeded(
        board: NoctBoardReference,
        at date: Date,
        force: Bool = false
    ) async throws -> NoctBoardRouteRotationTransfer? {
        let status = try await messagingClient.noctBoardRouteMaintenanceStatus(
            groupID: board.groupID
        )
        guard force || Self.shouldRotateReceiveRoute(
            hasPendingRoute: status.hasPendingRoute,
            activeRouteExpiresAt: status.activeRouteExpiresAt,
            at: date
        ) else {
            return nil
        }
        return try await messagingClient.noctBoardRotateReceiveRoute(
            groupID: board.groupID,
            relay: relay,
            policy: Self.routePolicy,
            at: date
        )
    }

    static func shouldRotateReceiveRoute(
        hasPendingRoute: Bool,
        activeRouteExpiresAt: Date?,
        at date: Date
    ) -> Bool {
        hasPendingRoute
            || activeRouteExpiresAt == nil
            || activeRouteExpiresAt! <= date.addingTimeInterval(receiveRouteRotationLeadTime)
    }

    private static var groupContentCapabilities: [ContentTypeCapabilityV2] {
        ProtocolCapabilityManifest.defaultContentTypes
            + [contentCapability, historyContentCapability]
    }

    private struct ExtractedEvents {
        let events: [NoctBoardEvent]
        let reassertableEvents: [ReassertableEvent]
        let historyManifest: [NoctBoardAdmissionHistoryManifestEntry]
        let historyBootstrapProvenance: [NoctBoardHistoryBootstrapProvenance]
        let rejections: [NoctBoardContainerRejection]
    }

    private struct ReassertableEvent {
        let event: NoctBoardEvent
        let signedRecordBytes: Data
    }

    private static func extractBoardEvents(
        _ groupEvents: [GroupConversationEventV2],
        board: NoctBoardReference,
        signedState: SignedGroupStateV2
    ) -> ExtractedEvents {
        var events: [NoctBoardEvent] = []
        var reassertableEvents: [ReassertableEvent] = []
        var seenEventDigests = Set<Data>()
        var historyManifest: [NoctBoardAdmissionHistoryManifestEntry] = []
        var historyBootstrapProvenance: [NoctBoardHistoryBootstrapProvenance] = []
        var rejections: [NoctBoardContainerRejection] = []
        let genesisOwner = signedState.members.first {
            $0.addedEpoch == 1 && $0.role == .owner && $0.removedEpoch == nil
        }
        let genesisCredential = genesisOwner.flatMap { owner in
            signedState.memberCredentials.first {
                $0.memberHandle == owner.id && $0.removedEpoch == nil
            }
        }

        func decodeSignedEvent(
            _ bytes: Data,
            containerID: UUID
        ) -> (event: NoctBoardEvent, recordBytes: Data)? {
            guard bytes.count <= NoctBoardSignedEventRecord.maximumEncodedBytes,
                  NoctweaveCanonicalJSON.isCanonical(bytes),
                  let record = try? NoctweaveCoder.decode(
                    NoctBoardSignedEventRecord.self,
                    from: bytes
                  ),
                  let event = try? NoctBoardCodec.decode(record.eventBytes) else {
                rejections.append(NoctBoardContainerRejection(
                    groupEventID: containerID,
                    reason: .malformedPayload
                ))
                return nil
            }
            guard let credential = signedState.memberCredentials.first(where: {
                $0.memberHandle == event.authorMemberHandle
                    && $0.credentialHandle == event.authorCredentialHandle
            }), SigningKeyPair.verify(
                signature: record.authorSignature,
                data: Self.eventSignaturePayload(record.eventBytes),
                publicKeyData: credential.signingPublicKey
            ) else {
                rejections.append(NoctBoardContainerRejection(
                    groupEventID: containerID,
                    reason: .invalidAuthorSignature
                ))
                return nil
            }
            return (event, bytes)
        }

        func appendExact(
            _ event: NoctBoardEvent,
            signedRecordBytes: Data,
            containerID: UUID
        ) {
            guard let digest = try? NoctBoardCodec.digest(event) else {
                rejections.append(NoctBoardContainerRejection(
                    groupEventID: containerID,
                    reason: .malformedPayload
                ))
                return
            }
            if seenEventDigests.insert(digest).inserted {
                events.append(event)
                reassertableEvents.append(ReassertableEvent(
                    event: event,
                    signedRecordBytes: signedRecordBytes
                ))
            }
        }

        for groupEvent in groupEvents {
            guard groupEvent.groupID == board.groupID,
                  groupEvent.kind == .application,
                  groupEvent.relation == nil,
                  groupEvent.content.parameters.isEmpty,
                  groupEvent.content.fallbackText == nil,
                  groupEvent.content.disposition == .silent else {
                rejections.append(NoctBoardContainerRejection(
                    groupEventID: groupEvent.id,
                    reason: .malformedPayload
                ))
                continue
            }

            if groupEvent.content.type == historyContentType {
                guard groupEvent.authorMemberHandle == genesisOwner?.id,
                      groupEvent.authorCredentialHandle
                        == genesisCredential?.credentialHandle else {
                    rejections.append(NoctBoardContainerRejection(
                        groupEventID: groupEvent.id,
                        reason: .unauthorizedHistoryBootstrap
                    ))
                    continue
                }
                guard NoctweaveCanonicalJSON.isCanonical(groupEvent.content.payload),
                      let record = try? NoctweaveCoder.decode(
                        NoctBoardHistoryRecord.self,
                        from: groupEvent.content.payload
                      ) else {
                    rejections.append(NoctBoardContainerRejection(
                        groupEventID: groupEvent.id,
                        reason: .malformedPayload
                    ))
                    continue
                }
                guard record.boardID == board.boardID,
                      record.groupID == board.groupID else {
                    rejections.append(NoctBoardContainerRejection(
                        groupEventID: groupEvent.id,
                        reason: .envelopeBindingMismatch
                    ))
                    continue
                }
                guard let signed = decodeSignedEvent(
                    record.signedEventRecordBytes,
                    containerID: groupEvent.id
                ) else { continue }
                let event = signed.event
                guard event.boardID == board.boardID,
                      event.groupID == board.groupID else {
                    rejections.append(NoctBoardContainerRejection(
                        groupEventID: groupEvent.id,
                        reason: .envelopeBindingMismatch
                    ))
                    continue
                }
                historyBootstrapProvenance.append(
                    NoctBoardHistoryBootstrapProvenance(
                        groupEventID: groupEvent.id,
                        reassertedEventID: event.id,
                        assertedByMemberHandle: groupEvent.authorMemberHandle,
                        assertedByCredentialHandle: groupEvent.authorCredentialHandle
                    )
                )
                historyManifest.append(NoctBoardAdmissionHistoryManifestEntry(
                    historyGroupEventID: groupEvent.id,
                    eventID: event.id,
                    signedEventRecordDigest: Data(SHA256.hash(
                        data: signed.recordBytes
                    ))
                ))
                appendExact(
                    event,
                    signedRecordBytes: signed.recordBytes,
                    containerID: groupEvent.id
                )
                continue
            }

            guard groupEvent.content.type == contentType else {
                rejections.append(NoctBoardContainerRejection(
                    groupEventID: groupEvent.id,
                    reason: .unexpectedContent
                ))
                continue
            }
            guard let signed = decodeSignedEvent(
                groupEvent.content.payload,
                containerID: groupEvent.id
            ) else { continue }
            let event = signed.event
            let groupMilliseconds = Int64(
                canonicalDate(groupEvent.createdAt).timeIntervalSince1970 * 1_000
            )
            guard event.boardID == board.boardID,
                  event.groupID == board.groupID,
                  event.id == groupEvent.id,
                  event.clientTransactionID == groupEvent.clientTransactionID,
                  event.authorMemberHandle == groupEvent.authorMemberHandle,
                  event.authorCredentialHandle == groupEvent.authorCredentialHandle,
                  event.createdAtUnixMilliseconds == groupMilliseconds else {
                rejections.append(NoctBoardContainerRejection(
                    groupEventID: groupEvent.id,
                    reason: .envelopeBindingMismatch
                ))
                continue
            }
            appendExact(
                event,
                signedRecordBytes: signed.recordBytes,
                containerID: groupEvent.id
            )
        }
        return ExtractedEvents(
            events: events,
            reassertableEvents: reassertableEvents,
            historyManifest: historyManifest,
            historyBootstrapProvenance: historyBootstrapProvenance,
            rejections: rejections
        )
    }

    private static func admissionHistoryManifest(
        _ events: [ReassertableEvent],
        admissionID: UUID
    ) -> [NoctBoardAdmissionHistoryManifestEntry] {
        events.map { source in
            let digest = Data(SHA256.hash(data: source.signedRecordBytes))
            return NoctBoardAdmissionHistoryManifestEntry(
                historyGroupEventID: deterministicUUID(
                    domain: "org.noctboard.history.event.v1",
                    admissionID: admissionID,
                    eventID: source.event.id,
                    eventDigest: digest
                ),
                eventID: source.event.id,
                signedEventRecordDigest: digest
            )
        }.sorted {
            $0.historyGroupEventID.uuidString < $1.historyGroupEventID.uuidString
        }
    }

    static func verifyAdmissionHistoryManifest(
        expected: [NoctBoardAdmissionHistoryManifestEntry],
        received: [NoctBoardAdmissionHistoryManifestEntry]
    ) throws {
        guard !expected.isEmpty,
              expected.count <= maximumAdmissionHistoryEvents,
              Set(expected).count == expected.count,
              expected.allSatisfy(\.isStructurallyValid),
              Set(expected).isSubset(of: Set(received)) else {
            throw NoctBoardTransportError.admissionHistoryIncomplete
        }
    }

    static func boardConfiguration(
        board: NoctBoardReference,
        signedState: SignedGroupStateV2
    ) throws -> NoctBoardConfiguration {
        guard signedState.groupId == board.groupID else {
            throw NoctBoardTransportError.boardBindingMismatch
        }
        guard signedState.metadataDigest == Self.boardMetadataDigest(boardID: board.boardID) else {
            throw NoctBoardTransportError.invalidGroupState
        }
        guard signedState.members.allSatisfy({ $0.removedEpoch == nil }),
              signedState.memberCredentials.allSatisfy({ $0.removedEpoch == nil }) else {
            throw NoctBoardTransportError.membershipRemovalRequiresAuditSegmentation
        }
        let genesisMembers = signedState.members.filter { $0.addedEpoch == 1 }
        guard genesisMembers.count == 1,
              genesisMembers[0].role == .owner,
              signedState.members.allSatisfy({ member in
                  member.addedEpoch == 1
                      ? member.id == genesisMembers[0].id && member.role == .owner
                      : member.role == .member
              }) else {
            throw NoctBoardTransportError.groupRoleChangeRequiresAuditSegmentation
        }
        guard signedState.permissions == .default else {
            throw NoctBoardTransportError.groupPermissionChangeRequiresAuditSegmentation
        }
        guard signedState.memberCredentials.allSatisfy({ credential in
            credential.contentTypes.contains { $0.supports(Self.contentType) }
                && credential.contentTypes.contains {
                    $0.supports(Self.historyContentType)
                }
        }) else {
            throw NoctBoardTransportError.groupCapabilityChangeRequiresAuditSegmentation
        }
        let memberRoles = Dictionary(uniqueKeysWithValues: signedState.members.map {
            ($0.id, $0.role)
        })
        let credentialGroups = Dictionary(grouping: signedState.memberCredentials, by: \.memberHandle)
        // A single Core projection intentionally binds one credential per
        // member. Do not silently rewrite old evidence after credential
        // replacement; a future audit format must segment projections at that
        // epoch boundary and link their checkpoint digests.
        guard credentialGroups.values.allSatisfy({ $0.count == 1 }) else {
            throw NoctBoardTransportError.credentialRotationRequiresAuditSegmentation
        }
        let members = signedState.memberCredentials
            .filter { memberRoles[$0.memberHandle] != nil }
            .map { credential in
                NoctBoardMemberAuthorization(
                    memberHandle: credential.memberHandle,
                    credentialHandle: credential.credentialHandle,
                    role: credential.memberHandle == genesisMembers[0].id
                        ? .coordinator
                        : .worker
                )
            }
        let configuration = NoctBoardConfiguration(
            boardID: board.boardID,
            groupID: board.groupID,
            members: members
        )
        guard configuration.isStructurallyValid else {
            throw NoctBoardTransportError.invalidGroupState
        }
        return configuration
    }

    private static func canonicalDate(_ date: Date) -> Date {
        NoctweaveRendezvousV2.canonicalTimestamp(date)
    }

    private static func boardMetadataDigest(boardID: UUID) -> Data {
        Data(SHA256.hash(data: Data(
            "org.noctboard.metadata.v1\0\(boardID.uuidString.lowercased())".utf8
        )))
    }

    static func eventSignaturePayload(_ eventBytes: Data) -> Data {
        var payload = Data("org.noctboard.event-signature.v1".utf8)
        payload.append(0)
        payload.append(Data(SHA256.hash(data: eventBytes)))
        return payload
    }

    /// Noctweave runtime compaction is intentionally unavailable to the v1
    /// projector because removing sequence-zero or dependency events would
    /// make a full audit misleading. Count every stored group application
    /// event, including hostile unexpected-content spam, and fail closed before
    /// that runtime boundary. An admitted member can force this availability
    /// failure; recovery requires a future segmented checkpoint format.
    static func enforceAuditWindow(
        groupEventCount: Int,
        reservingNewEvents: Int = 0
    ) throws {
        guard groupEventCount >= 0,
              reservingNewEvents >= 0,
              reservingNewEvents <= NoctBoardLimits.maximumBoardEvents,
              groupEventCount <= NoctBoardLimits.maximumBoardEvents - reservingNewEvents else {
            throw NoctBoardTransportError.boardAuditWindowExceeded
        }
    }

    private static func data(hex: String) -> Data? {
        guard hex.count == 64 else { return nil }
        var result = Data()
        result.reserveCapacity(32)
        var index = hex.startIndex
        for _ in 0 ..< 32 {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index ..< next], radix: 16) else { return nil }
            result.append(byte)
            index = next
        }
        return result
    }

    private static func idempotencyKey(domain: String, id: UUID) -> Data {
        Data(SHA256.hash(data: Data("\(domain)\0\(id.uuidString.lowercased())".utf8)))
    }

    static func deterministicUUID(
        domain: String,
        admissionID: UUID,
        eventID: UUID,
        eventDigest: Data
    ) -> UUID {
        var material = Data(domain.utf8)
        material.append(0)
        material.append(Data(admissionID.uuidString.lowercased().utf8))
        material.append(0)
        material.append(Data(eventID.uuidString.lowercased().utf8))
        material.append(0)
        material.append(eventDigest)
        var bytes = Array(SHA256.hash(data: material).prefix(16))
        bytes[6] = (bytes[6] & 0x0F) | 0x50
        bytes[8] = (bytes[8] & 0x3F) | 0x80
        return UUID(uuid: (
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
            bytes[8], bytes[9], bytes[10], bytes[11],
            bytes[12], bytes[13], bytes[14], bytes[15]
        ))
    }
}

private struct NoctBoardSyncTransfer: Sendable {
    let receivedEventCount: Int
    let receivedEventIDs: [UUID]
    let hasMore: Bool
}

private struct NoctBoardRouteMaintenanceStatus: Sendable {
    let hasPendingRoute: Bool
    let activeRouteExpiresAt: Date?
}

private struct NoctBoardRouteRotationTransfer: Sendable {
    let announcementOperationID: UUID?
    let announcementComplete: Bool
}

/// Noctweave's immutable route-set graph is not annotated `Sendable`. This
/// wrapper makes the one-value ownership transfer explicit and keeps the raw
/// graph inside `HeadlessMessagingClient` actor isolation.
private struct NoctBoardRouteSetTransfer: @unchecked Sendable {
    let value: SignedGroupOpaqueRouteSetV2

    init(_ value: SignedGroupOpaqueRouteSetV2) {
        self.value = value
    }
}

private struct NoctBoardRouteSetsTransfer: @unchecked Sendable {
    let values: [SignedGroupOpaqueRouteSetV2]

    init(_ values: [SignedGroupOpaqueRouteSetV2]) {
        self.values = values
    }
}

private struct NoctBoardPreparedApplicationTransfer: Sendable {
    let transportOperationID: UUID?
}

private extension HeadlessMessagingClient {
    /// Converts Noctweave's immutable group sync values to the narrow Sendable
    /// summary the product actor needs before crossing the actor boundary.
    func noctBoardSyncTransfer(groupID: UUID) async throws -> NoctBoardSyncTransfer {
        let pages = try await syncGroup(groupID: groupID)
        let events = pages.flatMap(\.receivedEvents)
        return NoctBoardSyncTransfer(
            receivedEventCount: events.count,
            receivedEventIDs: events.map(\.id),
            hasMore: pages.contains(where: \.hasMore)
        )
    }

    func noctBoardRouteMaintenanceStatus(
        groupID: UUID
    ) async throws -> NoctBoardRouteMaintenanceStatus {
        let runtime = try openGroupRuntime(groupID: groupID)
        let inbound = await runtime.inboundTransportSnapshot()
        return NoctBoardRouteMaintenanceStatus(
            hasPendingRoute: inbound.pendingRoute != nil,
            activeRouteExpiresAt: inbound.localRoutes
                .filter { $0.advertisedState == .active }
                .map { $0.localRoute.route.lease.expiresAt }
                .max()
        )
    }

    func noctBoardRotateReceiveRoute(
        groupID: UUID,
        relay: RelayEndpoint,
        policy: OpaqueRoutePolicyV2,
        at date: Date
    ) async throws -> NoctBoardRouteRotationTransfer {
        let result = try await registerGroupReceiveRoute(
            groupID: groupID,
            relay: relay,
            policy: policy,
            at: date
        )
        return NoctBoardRouteRotationTransfer(
            announcementOperationID: result.announcementOperationID,
            announcementComplete: result.announcementComplete
        )
    }

    func noctBoardPrepareGroupApplication(
        _ event: GroupConversationEventV2,
        additionalRouteSet: NoctBoardRouteSetTransfer?,
        at date: Date
    ) async throws -> NoctBoardPreparedApplicationTransfer {
        let prepared = try await prepareGroupApplication(
            event,
            routeSets: additionalRouteSet.map { [$0.value] } ?? [],
            at: date
        )
        return NoctBoardPreparedApplicationTransfer(
            transportOperationID: prepared.transportOperation?.id
        )
    }
}

private extension NoctweavePQGroupRuntimeV2 {
    func noctBoardRecoverEpochTransport(
        intentID: UUID,
        routeSets: NoctBoardRouteSetsTransfer,
        at date: Date
    ) async throws -> UUID? {
        let operation = try await prepareEpochTransport(
            intentID: intentID,
            routeSets: routeSets.values,
            at: date
        )
        if operation == nil {
            try await finalizeEpoch(intentId: intentID, at: date)
        }
        return operation?.id
    }
}
