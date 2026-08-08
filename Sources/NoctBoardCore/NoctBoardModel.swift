// SPDX-FileCopyrightText: 2026 Luiz Widmer
// SPDX-License-Identifier: AGPL-3.0-or-later

import CryptoKit
import Foundation
import NoctweaveCore

private struct NoctBoardAnyCodingKey: CodingKey {
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

private func requireExactKeys<Key: CodingKey & CaseIterable>(
    _ decoder: Decoder,
    _ keyType: Key.Type
) throws where Key.AllCases: Collection {
    let strict = try decoder.container(keyedBy: NoctBoardAnyCodingKey.self)
    let actual = Set(strict.allKeys.map(\.stringValue))
    let expected = Set(keyType.allCases.map(\.stringValue))
    guard actual == expected else {
        throw DecodingError.dataCorrupted(
            .init(
                codingPath: decoder.codingPath,
                debugDescription: "NoctBoard fields must match the current schema exactly"
            )
        )
    }
}

private func rejectInvalidEncoding<T>(_ value: T, at encoder: Encoder) throws -> Never {
    throw EncodingError.invalidValue(
        value,
        .init(
            codingPath: encoder.codingPath,
            debugDescription: "Invalid NoctBoard value"
        )
    )
}

private extension UUID {
    static let noctBoardZero = UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))

    var isNoctBoardValid: Bool { self != .noctBoardZero }
}

private extension String {
    func isNoctBoardText(
        minimumUTF8Bytes: Int,
        maximumUTF8Bytes: Int,
        multiline: Bool
    ) -> Bool {
        let byteCount = utf8.count
        guard byteCount >= minimumUTF8Bytes,
              byteCount <= maximumUTF8Bytes,
              self == precomposedStringWithCanonicalMapping else {
            return false
        }

        return unicodeScalars.allSatisfy { scalar in
            if !CharacterSet.controlCharacters.contains(scalar) { return true }
            return multiline && (scalar.value == 0x09 || scalar.value == 0x0A || scalar.value == 0x0D)
        }
    }
}

public enum NoctBoardLimits {
    public static let maximumEventBytes = 32 * 1_024
    /// Stops conforming v1 clients before Noctweave runtime compaction can
    /// discard the sequence-zero and dependency events needed for full replay.
    public static let maximumBoardEvents = 3_000
    /// Matches the current Noctweave PQ group runtime's active-credential ceiling.
    public static let maximumMembers = 128
    public static let maximumThreadTitleBytes = 160
    public static let maximumTaskTitleBytes = 200
    public static let maximumTaskDetailsBytes = 8 * 1_024
    public static let maximumMessageBodyBytes = 16 * 1_024
    public static let earliestTimestampMilliseconds: Int64 = 1_577_836_800_000 // 2020-01-01
    public static let latestTimestampMilliseconds: Int64 = 7_258_118_400_000 // 2200-01-01
    /// NCJ-1 intentionally limits integers to the exactly interoperable JSON range.
    public static let maximumLogicalInteger: UInt64 = 9_007_199_254_740_991
}

public enum NoctBoardRole: String, Codable, CaseIterable, Equatable, Hashable, Sendable {
    case coordinator
    case worker
    case auditor
}

/// The authorization binding supplied by the accepted Noctweave group state.
/// Neither handle is an account, persona, installation, or cross-group identity.
public struct NoctBoardMemberAuthorization: Codable, Equatable, Hashable {
    public let memberHandle: GroupScopedMemberHandleV2
    public let credentialHandle: GroupScopedCredentialHandleV2
    public let role: NoctBoardRole

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case memberHandle
        case credentialHandle
        case role
    }

    public init(
        memberHandle: GroupScopedMemberHandleV2,
        credentialHandle: GroupScopedCredentialHandleV2,
        role: NoctBoardRole
    ) {
        self.memberHandle = memberHandle
        self.credentialHandle = credentialHandle
        self.role = role
    }

    public var isStructurallyValid: Bool {
        memberHandle.isStructurallyValid && credentialHandle.isStructurallyValid
    }

    public init(from decoder: Decoder) throws {
        try requireExactKeys(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            memberHandle: try values.decode(GroupScopedMemberHandleV2.self, forKey: .memberHandle),
            credentialHandle: try values.decode(
                GroupScopedCredentialHandleV2.self,
                forKey: .credentialHandle
            ),
            role: try values.decode(NoctBoardRole.self, forKey: .role)
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: decoder.codingPath, debugDescription: "Invalid member authorization")
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else { try rejectInvalidEncoding(self, at: encoder) }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(memberHandle, forKey: .memberHandle)
        try values.encode(credentialHandle, forKey: .credentialHandle)
        try values.encode(role, forKey: .role)
    }
}

public struct NoctBoardConfiguration: Codable, Equatable {
    public let boardID: UUID
    public let groupID: UUID
    public let members: [NoctBoardMemberAuthorization]

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case boardID
        case groupID
        case members
    }

    public init(
        boardID: UUID,
        groupID: UUID,
        members: [NoctBoardMemberAuthorization]
    ) {
        self.boardID = boardID
        self.groupID = groupID
        self.members = members.sorted {
            if $0.memberHandle.rawValue != $1.memberHandle.rawValue {
                return $0.memberHandle.rawValue < $1.memberHandle.rawValue
            }
            return $0.credentialHandle.rawValue < $1.credentialHandle.rawValue
        }
    }

    public var isStructurallyValid: Bool {
        boardID.isNoctBoardValid
            && groupID.isNoctBoardValid
            && boardID == groupID
            && !members.isEmpty
            && members.count <= NoctBoardLimits.maximumMembers
            && members.allSatisfy(\.isStructurallyValid)
            && Set(members.map(\.memberHandle)).count == members.count
            && Set(members.map(\.credentialHandle)).count == members.count
            && members.contains { $0.role == .coordinator }
    }

    public init(from decoder: Decoder) throws {
        try requireExactKeys(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            boardID: try values.decode(UUID.self, forKey: .boardID),
            groupID: try values.decode(UUID.self, forKey: .groupID),
            members: try values.decode([NoctBoardMemberAuthorization].self, forKey: .members)
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: decoder.codingPath, debugDescription: "Invalid board configuration")
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else { try rejectInvalidEncoding(self, at: encoder) }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(boardID, forKey: .boardID)
        try values.encode(groupID, forKey: .groupID)
        try values.encode(members, forKey: .members)
    }
}

public enum NoctBoardTaskState: String, Codable, CaseIterable, Equatable, Hashable, Sendable {
    case pending
    case active
    case blocked
    case completed
    case cancelled

    public var isTerminal: Bool { self == .completed || self == .cancelled }

    public func canTransition(to next: NoctBoardTaskState) -> Bool {
        switch (self, next) {
        case (.pending, .active), (.pending, .cancelled),
             (.active, .blocked), (.active, .completed), (.active, .cancelled),
             (.blocked, .active), (.blocked, .completed), (.blocked, .cancelled):
            return true
        default:
            return false
        }
    }
}

public struct NoctBoardCreateThread: Codable, Equatable {
    public let threadID: UUID
    public let title: String

    private enum CodingKeys: String, CodingKey, CaseIterable { case threadID, title }

    public init(threadID: UUID = UUID(), title: String) {
        self.threadID = threadID
        self.title = title
    }

    public var isStructurallyValid: Bool {
        threadID.isNoctBoardValid
            && title.isNoctBoardText(
                minimumUTF8Bytes: 1,
                maximumUTF8Bytes: NoctBoardLimits.maximumThreadTitleBytes,
                multiline: false
            )
    }

    public init(from decoder: Decoder) throws {
        try requireExactKeys(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            threadID: try values.decode(UUID.self, forKey: .threadID),
            title: try values.decode(String.self, forKey: .title)
        )
        guard isStructurallyValid else { throw invalidPayload(decoder, "thread.create") }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else { try rejectInvalidEncoding(self, at: encoder) }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(threadID, forKey: .threadID)
        try values.encode(title, forKey: .title)
    }
}

public struct NoctBoardCloseThread: Codable, Equatable {
    public let threadID: UUID

    private enum CodingKeys: String, CodingKey, CaseIterable { case threadID }

    public init(threadID: UUID) { self.threadID = threadID }
    public var isStructurallyValid: Bool { threadID.isNoctBoardValid }

    public init(from decoder: Decoder) throws {
        try requireExactKeys(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(threadID: try values.decode(UUID.self, forKey: .threadID))
        guard isStructurallyValid else { throw invalidPayload(decoder, "thread.close") }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else { try rejectInvalidEncoding(self, at: encoder) }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(threadID, forKey: .threadID)
    }
}

public struct NoctBoardCreateTask: Codable, Equatable {
    public let taskID: UUID
    public let threadID: UUID
    public let title: String
    public let details: String?
    public let assigneeMemberHandle: GroupScopedMemberHandleV2?

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case taskID, threadID, title, details, assigneeMemberHandle
    }

    public init(
        taskID: UUID = UUID(),
        threadID: UUID,
        title: String,
        details: String? = nil,
        assigneeMemberHandle: GroupScopedMemberHandleV2? = nil
    ) {
        self.taskID = taskID
        self.threadID = threadID
        self.title = title
        self.details = details
        self.assigneeMemberHandle = assigneeMemberHandle
    }

    public var isStructurallyValid: Bool {
        taskID.isNoctBoardValid
            && threadID.isNoctBoardValid
            && title.isNoctBoardText(
                minimumUTF8Bytes: 1,
                maximumUTF8Bytes: NoctBoardLimits.maximumTaskTitleBytes,
                multiline: false
            )
            && (details?.isNoctBoardText(
                minimumUTF8Bytes: 1,
                maximumUTF8Bytes: NoctBoardLimits.maximumTaskDetailsBytes,
                multiline: true
            ) ?? true)
            && (assigneeMemberHandle?.isStructurallyValid ?? true)
    }

    public init(from decoder: Decoder) throws {
        try requireExactKeys(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            taskID: try values.decode(UUID.self, forKey: .taskID),
            threadID: try values.decode(UUID.self, forKey: .threadID),
            title: try values.decode(String.self, forKey: .title),
            details: try values.decodeIfPresent(String.self, forKey: .details),
            assigneeMemberHandle: try values.decodeIfPresent(
                GroupScopedMemberHandleV2.self,
                forKey: .assigneeMemberHandle
            )
        )
        guard isStructurallyValid else { throw invalidPayload(decoder, "task.create") }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else { try rejectInvalidEncoding(self, at: encoder) }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(taskID, forKey: .taskID)
        try values.encode(threadID, forKey: .threadID)
        try values.encode(title, forKey: .title)
        try values.encode(details, forKey: .details)
        try values.encode(assigneeMemberHandle, forKey: .assigneeMemberHandle)
    }
}

public struct NoctBoardAssignTask: Codable, Equatable {
    public let taskID: UUID
    public let assigneeMemberHandle: GroupScopedMemberHandleV2?

    private enum CodingKeys: String, CodingKey, CaseIterable { case taskID, assigneeMemberHandle }

    public init(taskID: UUID, assigneeMemberHandle: GroupScopedMemberHandleV2?) {
        self.taskID = taskID
        self.assigneeMemberHandle = assigneeMemberHandle
    }

    public var isStructurallyValid: Bool {
        taskID.isNoctBoardValid && (assigneeMemberHandle?.isStructurallyValid ?? true)
    }

    public init(from decoder: Decoder) throws {
        try requireExactKeys(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            taskID: try values.decode(UUID.self, forKey: .taskID),
            assigneeMemberHandle: try values.decodeIfPresent(
                GroupScopedMemberHandleV2.self,
                forKey: .assigneeMemberHandle
            )
        )
        guard isStructurallyValid else { throw invalidPayload(decoder, "task.assign") }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else { try rejectInvalidEncoding(self, at: encoder) }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(taskID, forKey: .taskID)
        try values.encode(assigneeMemberHandle, forKey: .assigneeMemberHandle)
    }
}

public struct NoctBoardTransitionTask: Codable, Equatable {
    public let taskID: UUID
    public let from: NoctBoardTaskState
    public let to: NoctBoardTaskState

    private enum CodingKeys: String, CodingKey, CaseIterable { case taskID, from, to }

    public init(taskID: UUID, from: NoctBoardTaskState, to: NoctBoardTaskState) {
        self.taskID = taskID
        self.from = from
        self.to = to
    }

    public var isStructurallyValid: Bool {
        taskID.isNoctBoardValid && from.canTransition(to: to)
    }

    public init(from decoder: Decoder) throws {
        try requireExactKeys(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            taskID: try values.decode(UUID.self, forKey: .taskID),
            from: try values.decode(NoctBoardTaskState.self, forKey: .from),
            to: try values.decode(NoctBoardTaskState.self, forKey: .to)
        )
        guard isStructurallyValid else { throw invalidPayload(decoder, "task.transition") }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else { try rejectInvalidEncoding(self, at: encoder) }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(taskID, forKey: .taskID)
        try values.encode(from, forKey: .from)
        try values.encode(to, forKey: .to)
    }
}

public struct NoctBoardPostMessage: Codable, Equatable {
    public let messageID: UUID
    public let threadID: UUID
    public let taskID: UUID?
    /// Untrusted plain text. Renderers must display it as text, never markup or commands.
    public let body: String

    private enum CodingKeys: String, CodingKey, CaseIterable { case messageID, threadID, taskID, body }

    public init(
        messageID: UUID = UUID(),
        threadID: UUID,
        taskID: UUID? = nil,
        body: String
    ) {
        self.messageID = messageID
        self.threadID = threadID
        self.taskID = taskID
        self.body = body
    }

    public var isStructurallyValid: Bool {
        messageID.isNoctBoardValid
            && threadID.isNoctBoardValid
            && (taskID?.isNoctBoardValid ?? true)
            && body.isNoctBoardText(
                minimumUTF8Bytes: 1,
                maximumUTF8Bytes: NoctBoardLimits.maximumMessageBodyBytes,
                multiline: true
            )
    }

    public init(from decoder: Decoder) throws {
        try requireExactKeys(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            messageID: try values.decode(UUID.self, forKey: .messageID),
            threadID: try values.decode(UUID.self, forKey: .threadID),
            taskID: try values.decodeIfPresent(UUID.self, forKey: .taskID),
            body: try values.decode(String.self, forKey: .body)
        )
        guard isStructurallyValid else { throw invalidPayload(decoder, "message.post") }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else { try rejectInvalidEncoding(self, at: encoder) }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(messageID, forKey: .messageID)
        try values.encode(threadID, forKey: .threadID)
        try values.encode(taskID, forKey: .taskID)
        try values.encode(body, forKey: .body)
    }
}

public struct NoctBoardSetRole: Codable, Equatable {
    public let memberHandle: GroupScopedMemberHandleV2
    public let role: NoctBoardRole

    private enum CodingKeys: String, CodingKey, CaseIterable { case memberHandle, role }

    public init(memberHandle: GroupScopedMemberHandleV2, role: NoctBoardRole) {
        self.memberHandle = memberHandle
        self.role = role
    }

    public var isStructurallyValid: Bool { memberHandle.isStructurallyValid }

    public init(from decoder: Decoder) throws {
        try requireExactKeys(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            memberHandle: try values.decode(GroupScopedMemberHandleV2.self, forKey: .memberHandle),
            role: try values.decode(NoctBoardRole.self, forKey: .role)
        )
        guard isStructurallyValid else { throw invalidPayload(decoder, "member.set-role") }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else { try rejectInvalidEncoding(self, at: encoder) }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(memberHandle, forKey: .memberHandle)
        try values.encode(role, forKey: .role)
    }
}

private func invalidPayload(_ decoder: Decoder, _ operation: String) -> DecodingError {
    .dataCorrupted(
        .init(
            codingPath: decoder.codingPath,
            debugDescription: "Invalid bounded payload for \(operation)"
        )
    )
}

public enum NoctBoardOperation: Equatable {
    case createThread(NoctBoardCreateThread)
    case closeThread(NoctBoardCloseThread)
    case createTask(NoctBoardCreateTask)
    case assignTask(NoctBoardAssignTask)
    case transitionTask(NoctBoardTransitionTask)
    case postMessage(NoctBoardPostMessage)
    case setRole(NoctBoardSetRole)

    public var type: String {
        switch self {
        case .createThread: "thread.create"
        case .closeThread: "thread.close"
        case .createTask: "task.create"
        case .assignTask: "task.assign"
        case .transitionTask: "task.transition"
        case .postMessage: "message.post"
        case .setRole: "member.set-role"
        }
    }

    public var isStructurallyValid: Bool {
        switch self {
        case .createThread(let payload): payload.isStructurallyValid
        case .closeThread(let payload): payload.isStructurallyValid
        case .createTask(let payload): payload.isStructurallyValid
        case .assignTask(let payload): payload.isStructurallyValid
        case .transitionTask(let payload): payload.isStructurallyValid
        case .postMessage(let payload): payload.isStructurallyValid
        case .setRole(let payload): payload.isStructurallyValid
        }
    }
}

extension NoctBoardOperation: Codable {
    private enum CodingKeys: String, CodingKey, CaseIterable { case type, payload }

    public init(from decoder: Decoder) throws {
        try requireExactKeys(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        let type = try values.decode(String.self, forKey: .type)
        switch type {
        case "thread.create":
            self = .createThread(try values.decode(NoctBoardCreateThread.self, forKey: .payload))
        case "thread.close":
            self = .closeThread(try values.decode(NoctBoardCloseThread.self, forKey: .payload))
        case "task.create":
            self = .createTask(try values.decode(NoctBoardCreateTask.self, forKey: .payload))
        case "task.assign":
            self = .assignTask(try values.decode(NoctBoardAssignTask.self, forKey: .payload))
        case "task.transition":
            self = .transitionTask(try values.decode(NoctBoardTransitionTask.self, forKey: .payload))
        case "message.post":
            self = .postMessage(try values.decode(NoctBoardPostMessage.self, forKey: .payload))
        case "member.set-role":
            self = .setRole(try values.decode(NoctBoardSetRole.self, forKey: .payload))
        default:
            throw DecodingError.dataCorruptedError(
                forKey: .type,
                in: values,
                debugDescription: "Unsupported NoctBoard operation"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else { try rejectInvalidEncoding(self, at: encoder) }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(type, forKey: .type)
        switch self {
        case .createThread(let payload): try values.encode(payload, forKey: .payload)
        case .closeThread(let payload): try values.encode(payload, forKey: .payload)
        case .createTask(let payload): try values.encode(payload, forKey: .payload)
        case .assignTask(let payload): try values.encode(payload, forKey: .payload)
        case .transitionTask(let payload): try values.encode(payload, forKey: .payload)
        case .postMessage(let payload): try values.encode(payload, forKey: .payload)
        case .setRole(let payload): try values.encode(payload, forKey: .payload)
        }
    }
}

/// The immutable application event carried inside a Noctweave group message.
public struct NoctBoardEvent: Codable, Equatable, Identifiable {
    public static let currentSchema = "org.noctboard/event:1.0"

    public let schema: String
    public let id: UUID
    public let clientTransactionID: UUID
    public let boardID: UUID
    public let groupID: UUID
    public let authorMemberHandle: GroupScopedMemberHandleV2
    public let authorCredentialHandle: GroupScopedCredentialHandleV2
    /// Lamport-style board ordering metadata. The projector still uses stable tie-breakers.
    public let logicalClock: UInt64
    /// Zero-based continuity counter scoped to `authorMemberHandle` within this board.
    public let authorSequence: UInt64
    /// SHA-256 digest of that author's preceding canonical NoctBoard event.
    public let previousAuthorEventDigest: Data?
    public let createdAtUnixMilliseconds: Int64
    public let operation: NoctBoardOperation

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case schema
        case id
        case clientTransactionID
        case boardID
        case groupID
        case authorMemberHandle
        case authorCredentialHandle
        case logicalClock
        case authorSequence
        case previousAuthorEventDigest
        case createdAtUnixMilliseconds
        case operation
    }

    public init(
        schema: String = Self.currentSchema,
        id: UUID = UUID(),
        clientTransactionID: UUID = UUID(),
        boardID: UUID,
        groupID: UUID,
        authorMemberHandle: GroupScopedMemberHandleV2,
        authorCredentialHandle: GroupScopedCredentialHandleV2,
        logicalClock: UInt64,
        authorSequence: UInt64,
        previousAuthorEventDigest: Data?,
        createdAtUnixMilliseconds: Int64,
        operation: NoctBoardOperation
    ) {
        self.schema = schema
        self.id = id
        self.clientTransactionID = clientTransactionID
        self.boardID = boardID
        self.groupID = groupID
        self.authorMemberHandle = authorMemberHandle
        self.authorCredentialHandle = authorCredentialHandle
        self.logicalClock = logicalClock
        self.authorSequence = authorSequence
        self.previousAuthorEventDigest = previousAuthorEventDigest
        self.createdAtUnixMilliseconds = createdAtUnixMilliseconds
        self.operation = operation
    }

    public var isStructurallyValid: Bool {
        schema == Self.currentSchema
            && id.isNoctBoardValid
            && clientTransactionID.isNoctBoardValid
            && boardID.isNoctBoardValid
            && groupID.isNoctBoardValid
            && authorMemberHandle.isStructurallyValid
            && authorCredentialHandle.isStructurallyValid
            && logicalClock <= NoctBoardLimits.maximumLogicalInteger
            && authorSequence <= NoctBoardLimits.maximumLogicalInteger
            && ((authorSequence == 0 && previousAuthorEventDigest == nil)
                || (authorSequence > 0 && previousAuthorEventDigest?.count == 32))
            && createdAtUnixMilliseconds >= NoctBoardLimits.earliestTimestampMilliseconds
            && createdAtUnixMilliseconds <= NoctBoardLimits.latestTimestampMilliseconds
            && operation.isStructurallyValid
    }

    public init(from decoder: Decoder) throws {
        try requireExactKeys(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            schema: try values.decode(String.self, forKey: .schema),
            id: try values.decode(UUID.self, forKey: .id),
            clientTransactionID: try values.decode(UUID.self, forKey: .clientTransactionID),
            boardID: try values.decode(UUID.self, forKey: .boardID),
            groupID: try values.decode(UUID.self, forKey: .groupID),
            authorMemberHandle: try values.decode(
                GroupScopedMemberHandleV2.self,
                forKey: .authorMemberHandle
            ),
            authorCredentialHandle: try values.decode(
                GroupScopedCredentialHandleV2.self,
                forKey: .authorCredentialHandle
            ),
            logicalClock: try values.decode(UInt64.self, forKey: .logicalClock),
            authorSequence: try values.decode(UInt64.self, forKey: .authorSequence),
            previousAuthorEventDigest: try values.decodeIfPresent(
                Data.self,
                forKey: .previousAuthorEventDigest
            ),
            createdAtUnixMilliseconds: try values.decode(
                Int64.self,
                forKey: .createdAtUnixMilliseconds
            ),
            operation: try values.decode(NoctBoardOperation.self, forKey: .operation)
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: decoder.codingPath, debugDescription: "Invalid NoctBoard event")
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else { try rejectInvalidEncoding(self, at: encoder) }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(schema, forKey: .schema)
        try values.encode(id, forKey: .id)
        try values.encode(clientTransactionID, forKey: .clientTransactionID)
        try values.encode(boardID, forKey: .boardID)
        try values.encode(groupID, forKey: .groupID)
        try values.encode(authorMemberHandle, forKey: .authorMemberHandle)
        try values.encode(authorCredentialHandle, forKey: .authorCredentialHandle)
        try values.encode(logicalClock, forKey: .logicalClock)
        try values.encode(authorSequence, forKey: .authorSequence)
        try values.encode(previousAuthorEventDigest, forKey: .previousAuthorEventDigest)
        try values.encode(createdAtUnixMilliseconds, forKey: .createdAtUnixMilliseconds)
        try values.encode(operation, forKey: .operation)
    }
}

public enum NoctBoardCodecError: Error, Equatable, Sendable {
    case eventTooLarge(maximumBytes: Int)
    case nonCanonicalJSON
}

public enum NoctBoardCodec {
    public static func encode(_ event: NoctBoardEvent) throws -> Data {
        let data = try NoctweaveCoder.encode(event, sortedKeys: true)
        guard data.count <= NoctBoardLimits.maximumEventBytes else {
            throw NoctBoardCodecError.eventTooLarge(maximumBytes: NoctBoardLimits.maximumEventBytes)
        }
        return data
    }

    public static func decode(_ data: Data) throws -> NoctBoardEvent {
        guard data.count <= NoctBoardLimits.maximumEventBytes else {
            throw NoctBoardCodecError.eventTooLarge(maximumBytes: NoctBoardLimits.maximumEventBytes)
        }
        guard NoctweaveCanonicalJSON.isCanonical(data) else {
            throw NoctBoardCodecError.nonCanonicalJSON
        }
        return try NoctweaveCoder.decode(NoctBoardEvent.self, from: data)
    }

    public static func digest(_ event: NoctBoardEvent) throws -> Data {
        Data(SHA256.hash(data: try encode(event)))
    }

    public static func digestHex(_ event: NoctBoardEvent) throws -> String {
        try digest(event).map { String(format: "%02x", $0) }.joined()
    }
}

// Noctweave's group handles are immutable value wrappers but predate Swift 6
// Sendable annotations. These containing values have no shared mutable state.
extension NoctBoardMemberAuthorization: @unchecked Sendable {}
extension NoctBoardConfiguration: @unchecked Sendable {}
extension NoctBoardCreateThread: @unchecked Sendable {}
extension NoctBoardCloseThread: @unchecked Sendable {}
extension NoctBoardCreateTask: @unchecked Sendable {}
extension NoctBoardAssignTask: @unchecked Sendable {}
extension NoctBoardTransitionTask: @unchecked Sendable {}
extension NoctBoardPostMessage: @unchecked Sendable {}
extension NoctBoardSetRole: @unchecked Sendable {}
extension NoctBoardOperation: Sendable {}
extension NoctBoardEvent: @unchecked Sendable {}
