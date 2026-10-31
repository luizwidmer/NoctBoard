// SPDX-FileCopyrightText: 2026 Luiz Widmer
// SPDX-License-Identifier: AGPL-3.0-or-later

import CryptoKit
import Foundation
import NoctweaveCore

private struct PolicyCodingKey: CodingKey {
    let stringValue: String
    var intValue: Int? { nil }
    init?(stringValue: String) { self.stringValue = stringValue }
    init?(intValue: Int) { return nil }
}

private func requirePolicyKeys<Key: CodingKey & CaseIterable>(
    _ decoder: Decoder, _ type: Key.Type
) throws {
    let actual = try decoder.container(keyedBy: PolicyCodingKey.self)
    guard Set(actual.allKeys.map(\.stringValue))
            == Set(type.allCases.map(\.stringValue)) else {
        throw DecodingError.dataCorrupted(.init(
            codingPath: decoder.codingPath,
            debugDescription: "Policy checkpoint fields must match exactly"
        ))
    }
}

private func invalidPolicy(_ decoder: Decoder) -> DecodingError {
    .dataCorrupted(.init(
        codingPath: decoder.codingPath,
        debugDescription: "Invalid policy checkpoint"
    ))
}

/// Core-authenticated sender positions signed by the immutable group owner.
/// Application clocks and relay arrival order never establish a role cutoff.
public struct NoctBoardPolicyCheckpointV2: Codable, Equatable {
    public enum Kind: String, Codable { case snapshot, roleChange }

    public let kind: Kind
    public let owner: GroupScopedMemberHandleV2
    public let groupEpoch: UInt64
    public let groupTranscriptHash: Data
    public let previousCheckpointDigest: Data?
    public let frontiers: [GroupApplicationVerificationFrontierV2]
    /// Digest of every exact signed board event preceding this checkpoint in
    /// the owner's accepted, authenticated policy order.
    public let precedingHistoryDigest: Data
    /// A bounded owner-attested order for members admitted after earlier
    /// envelopes have been re-encrypted. Omitted for an existing member with
    /// its original Core receipts and a full prior checkpoint chain.
    public let precedingHistoryOrder: [NoctBoardHistoryPositionV2]?
    public let roleChange: NoctBoardSetRole?

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case kind, owner, groupEpoch, groupTranscriptHash
        case previousCheckpointDigest, frontiers, precedingHistoryDigest
        case precedingHistoryOrder, roleChange
    }

    public init(
        kind: Kind,
        owner: GroupScopedMemberHandleV2,
        groupEpoch: UInt64,
        groupTranscriptHash: Data,
        previousCheckpointDigest: Data?,
        frontiers: [GroupApplicationVerificationFrontierV2],
        precedingHistoryDigest: Data,
        precedingHistoryOrder: [NoctBoardHistoryPositionV2]? = nil,
        roleChange: NoctBoardSetRole? = nil
    ) {
        self.kind = kind
        self.owner = owner
        self.groupEpoch = groupEpoch
        self.groupTranscriptHash = groupTranscriptHash
        self.previousCheckpointDigest = previousCheckpointDigest
        self.frontiers = frontiers
        self.precedingHistoryDigest = precedingHistoryDigest
        self.precedingHistoryOrder = precedingHistoryOrder
        self.roleChange = roleChange
    }

    public var isStructurallyValid: Bool {
        owner.isStructurallyValid && groupEpoch > 0
            && groupTranscriptHash.count == SHA256.byteCount
            && (previousCheckpointDigest == nil
                || previousCheckpointDigest?.count == SHA256.byteCount)
            && precedingHistoryDigest.count == SHA256.byteCount
            && !frontiers.isEmpty && frontiers.count <= 128
            && frontiers.allSatisfy { frontier in
                frontier.isStructurallyValid
                    && frontier.epoch == groupEpoch
                    && frontier.transcriptHash == groupTranscriptHash
            }
            && frontiers == frontiers.sorted {
                $0.credentialHandle.rawValue < $1.credentialHandle.rawValue
            }
            && Set(frontiers.map(\.credentialHandle)).count == frontiers.count
            && (precedingHistoryOrder == nil
                || (precedingHistoryOrder!.count <= 128
                    && precedingHistoryOrder!.allSatisfy(\.isStructurallyValid)
                    && Set(precedingHistoryOrder!.map(\.eventID)).count
                        == precedingHistoryOrder!.count))
            && (kind == .snapshot ? roleChange == nil
                : (previousCheckpointDigest != nil
                    && roleChange?.isStructurallyValid == true
                    && roleChange?.memberHandle != owner))
    }

    public init(from decoder: Decoder) throws {
        try requirePolicyKeys(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            kind: try values.decode(Kind.self, forKey: .kind),
            owner: try values.decode(GroupScopedMemberHandleV2.self, forKey: .owner),
            groupEpoch: try values.decode(UInt64.self, forKey: .groupEpoch),
            groupTranscriptHash: try values.decode(Data.self, forKey: .groupTranscriptHash),
            previousCheckpointDigest: try values.decodeIfPresent(Data.self, forKey: .previousCheckpointDigest),
            frontiers: try values.decode([GroupApplicationVerificationFrontierV2].self, forKey: .frontiers),
            precedingHistoryDigest: try values.decode(Data.self, forKey: .precedingHistoryDigest),
            precedingHistoryOrder: try values.decodeIfPresent([NoctBoardHistoryPositionV2].self, forKey: .precedingHistoryOrder),
            roleChange: try values.decodeIfPresent(NoctBoardSetRole.self, forKey: .roleChange)
        )
        guard isStructurallyValid else { throw invalidPolicy(decoder) }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(self, .init(
                codingPath: encoder.codingPath,
                debugDescription: "Invalid policy checkpoint"
            ))
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(kind, forKey: .kind)
        try values.encode(owner, forKey: .owner)
        try values.encode(groupEpoch, forKey: .groupEpoch)
        try values.encode(groupTranscriptHash, forKey: .groupTranscriptHash)
        try values.encode(previousCheckpointDigest, forKey: .previousCheckpointDigest)
        try values.encode(frontiers, forKey: .frontiers)
        try values.encode(precedingHistoryDigest, forKey: .precedingHistoryDigest)
        try values.encode(precedingHistoryOrder, forKey: .precedingHistoryOrder)
        try values.encode(roleChange, forKey: .roleChange)
    }
}

public struct NoctBoardHistoryPositionV2: Codable, Equatable {
    public let eventID: UUID
    public let eventDigest: Data

    public init(eventID: UUID, eventDigest: Data) {
        self.eventID = eventID
        self.eventDigest = eventDigest
    }

    public var isStructurallyValid: Bool {
        eventID != UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
            && eventDigest.count == SHA256.byteCount
    }
}

extension NoctBoardPolicyCheckpointV2: @unchecked Sendable {}
extension NoctBoardHistoryPositionV2: @unchecked Sendable {}
