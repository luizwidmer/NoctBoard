// SPDX-FileCopyrightText: 2026 Luiz Widmer
// SPDX-License-Identifier: AGPL-3.0-or-later

import Foundation
import NoctweaveCore

public struct NoctBoardThread: Codable, Equatable, Identifiable {
    public let id: UUID
    public let title: String
    public let createdBy: GroupScopedMemberHandleV2
    public let createdAtUnixMilliseconds: Int64
    public let closedAtUnixMilliseconds: Int64?

    public var isClosed: Bool { closedAtUnixMilliseconds != nil }
}

public struct NoctBoardTask: Codable, Equatable, Identifiable {
    public let id: UUID
    public let threadID: UUID
    public let title: String
    public let details: String?
    public let assigneeMemberHandle: GroupScopedMemberHandleV2?
    public let state: NoctBoardTaskState
    public let createdBy: GroupScopedMemberHandleV2
    public let createdAtUnixMilliseconds: Int64
    public let updatedAtUnixMilliseconds: Int64
}

public struct NoctBoardMessage: Codable, Equatable, Identifiable {
    public let id: UUID
    public let threadID: UUID
    public let taskID: UUID?
    public let authorMemberHandle: GroupScopedMemberHandleV2
    /// Untrusted plain text. Consumers must never interpret it as markup or executable input.
    public let body: String
    public let createdAtUnixMilliseconds: Int64
}

public struct NoctBoardProjection: Codable, Equatable {
    public let boardID: UUID
    public let groupID: UUID
    public let members: [NoctBoardMemberAuthorization]
    public let threads: [NoctBoardThread]
    public let tasks: [NoctBoardTask]
    public let messages: [NoctBoardMessage]
    public let acceptedEventIDs: [UUID]

    public func thread(id: UUID) -> NoctBoardThread? { threads.first { $0.id == id } }
    public func task(id: UUID) -> NoctBoardTask? { tasks.first { $0.id == id } }
    public func message(id: UUID) -> NoctBoardMessage? { messages.first { $0.id == id } }

    public static func project(
        events: [NoctBoardEvent],
        configuration: NoctBoardConfiguration
    ) throws -> NoctBoardProjectionResult {
        try NoctBoardProjector.project(events: events, configuration: configuration)
    }
}

public enum NoctBoardLedgerOutcome: String, Codable, Equatable, Sendable {
    case accepted
    case replayed
    case rejected
}

public enum NoctBoardRejectionReason: String, Codable, Equatable, Sendable {
    case boardBindingMismatch
    case groupBindingMismatch
    case unknownAuthor
    case credentialBindingMismatch
    case eventIDConflict
    case duplicateTransaction
    case authorSequenceGap
    case authorSequenceConflict
    case authorChainMismatch
    case logicalClockGap
    case unauthorized
    case unknownThread
    case duplicateThread
    case threadClosed
    case threadHasOpenTasks
    case unknownTask
    case duplicateTask
    case unknownAssignee
    case invalidAssigneeRole
    case taskThreadMismatch
    case staleTaskState
    case invalidTaskTransition
    case taskAlreadyAssigned
    case duplicateMessage
    case noStateChange
    case lastCoordinator
    case memberHasOpenTasks
}

public struct NoctBoardLedgerEntry: Codable, Equatable {
    public let order: Int
    public let eventID: UUID
    public let clientTransactionID: UUID
    public let logicalClock: UInt64
    public let authorSequence: UInt64
    public let previousAuthorEventDigest: String?
    public let createdAtUnixMilliseconds: Int64
    public let authorMemberHandle: GroupScopedMemberHandleV2
    public let authorCredentialHandle: GroupScopedCredentialHandleV2
    /// True only when this occurrence advanced the verified per-author chain.
    public let authorChainConsumed: Bool
    public let operationType: String
    public let eventDigest: String
    public let outcome: NoctBoardLedgerOutcome
    public let rejectionReason: NoctBoardRejectionReason?
}

public struct NoctBoardLedger: Codable, Equatable {
    public let entries: [NoctBoardLedgerEntry]

    public var accepted: [NoctBoardLedgerEntry] {
        entries.filter { $0.outcome == .accepted }
    }

    public var replayed: [NoctBoardLedgerEntry] {
        entries.filter { $0.outcome == .replayed }
    }

    public var rejected: [NoctBoardLedgerEntry] {
        entries.filter { $0.outcome == .rejected }
    }
}

public struct NoctBoardProjectionResult: Equatable {
    public let projection: NoctBoardProjection
    public let ledger: NoctBoardLedger
    public let projectionDigest: String
}

public enum NoctBoardProjectionError: Error, Equatable, Sendable {
    case invalidConfiguration
    case eventLimitExceeded
    case invalidEvent(UUID)
}

private struct MutableThread {
    var value: NoctBoardThread
}

private struct MutableTask {
    var value: NoctBoardTask
}

private struct AuthorChainState {
    var nextSequence: UInt64
    var previousDigest: Data?
}

private struct OrderedEvent {
    let event: NoctBoardEvent
    let digest: Data
    let digestHex: String
}

public enum NoctBoardProjector {
    public static func project(
        events: [NoctBoardEvent],
        configuration: NoctBoardConfiguration
    ) throws -> NoctBoardProjectionResult {
        guard configuration.isStructurallyValid else {
            throw NoctBoardProjectionError.invalidConfiguration
        }
        guard events.count <= NoctBoardLimits.maximumBoardEvents else {
            throw NoctBoardProjectionError.eventLimitExceeded
        }

        var ordered: [OrderedEvent] = []
        ordered.reserveCapacity(events.count)
        for event in events {
            guard event.isStructurallyValid else {
                throw NoctBoardProjectionError.invalidEvent(event.id)
            }
            let digest = try NoctBoardCodec.digest(event)
            ordered.append(
                OrderedEvent(
                    event: event,
                    digest: digest,
                    digestHex: digest.map { String(format: "%02x", $0) }.joined()
                )
            )
        }

        ordered.sort(by: deterministicOrder)

        var members = Dictionary(
            uniqueKeysWithValues: configuration.members.map { ($0.memberHandle, $0) }
        )
        var threads: [UUID: MutableThread] = [:]
        var tasks: [UUID: MutableTask] = [:]
        var messages: [UUID: NoctBoardMessage] = [:]
        var seenEventIDs: [UUID: Data] = [:]
        var seenTransactionIDs: [UUID: Data] = [:]
        var authorChains: [GroupScopedMemberHandleV2: AuthorChainState] = [:]
        var maximumConsumedLogicalClock: UInt64?
        var acceptedEventIDs: [UUID] = []
        var ledgerEntries: [NoctBoardLedgerEntry] = []
        ledgerEntries.reserveCapacity(ordered.count)

        func append(
            _ orderedEvent: OrderedEvent,
            outcome: NoctBoardLedgerOutcome,
            reason: NoctBoardRejectionReason? = nil,
            authorChainConsumed: Bool = false
        ) {
            ledgerEntries.append(
                NoctBoardLedgerEntry(
                    order: ledgerEntries.count,
                    eventID: orderedEvent.event.id,
                    clientTransactionID: orderedEvent.event.clientTransactionID,
                    logicalClock: orderedEvent.event.logicalClock,
                    authorSequence: orderedEvent.event.authorSequence,
                    previousAuthorEventDigest: orderedEvent.event.previousAuthorEventDigest?
                        .map { String(format: "%02x", $0) }
                        .joined(),
                    createdAtUnixMilliseconds: orderedEvent.event.createdAtUnixMilliseconds,
                    authorMemberHandle: orderedEvent.event.authorMemberHandle,
                    authorCredentialHandle: orderedEvent.event.authorCredentialHandle,
                    authorChainConsumed: authorChainConsumed,
                    operationType: orderedEvent.event.operation.type,
                    eventDigest: orderedEvent.digestHex,
                    outcome: outcome,
                    rejectionReason: reason
                )
            )
        }

        for item in ordered {
            let event = item.event

            guard event.boardID == configuration.boardID else {
                append(item, outcome: .rejected, reason: .boardBindingMismatch)
                continue
            }
            guard event.groupID == configuration.groupID else {
                append(item, outcome: .rejected, reason: .groupBindingMismatch)
                continue
            }
            guard let author = members[event.authorMemberHandle] else {
                append(item, outcome: .rejected, reason: .unknownAuthor)
                continue
            }
            guard author.credentialHandle == event.authorCredentialHandle else {
                append(item, outcome: .rejected, reason: .credentialBindingMismatch)
                continue
            }

            if let prior = seenEventIDs[event.id] {
                append(
                    item,
                    outcome: prior == item.digest ? .replayed : .rejected,
                    reason: prior == item.digest ? nil : .eventIDConflict
                )
                continue
            }
            if seenTransactionIDs[event.clientTransactionID] != nil {
                append(item, outcome: .rejected, reason: .duplicateTransaction)
                continue
            }

            let chain = authorChains[event.authorMemberHandle]
                ?? AuthorChainState(nextSequence: 0, previousDigest: nil)
            guard event.authorSequence == chain.nextSequence else {
                append(
                    item,
                    outcome: .rejected,
                    reason: event.authorSequence < chain.nextSequence
                        ? .authorSequenceConflict
                        : .authorSequenceGap
                )
                continue
            }
            guard event.previousAuthorEventDigest == chain.previousDigest else {
                append(item, outcome: .rejected, reason: .authorChainMismatch)
                continue
            }
            if let maximumConsumedLogicalClock {
                let nextAllowed = maximumConsumedLogicalClock == NoctBoardLimits.maximumLogicalInteger
                    ? maximumConsumedLogicalClock
                    : maximumConsumedLogicalClock + 1
                guard event.logicalClock <= nextAllowed else {
                    append(item, outcome: .rejected, reason: .logicalClockGap)
                    continue
                }
            }

            // A valid author-chain link is consumed even when its application operation is denied.
            // This keeps an unauthorized operation auditable without poisoning every later link.
            seenEventIDs[event.id] = item.digest
            seenTransactionIDs[event.clientTransactionID] = item.digest
            authorChains[event.authorMemberHandle] = AuthorChainState(
                nextSequence: event.authorSequence + 1,
                previousDigest: item.digest
            )
            maximumConsumedLogicalClock = max(
                maximumConsumedLogicalClock ?? event.logicalClock,
                event.logicalClock
            )

            if let rejection = apply(
                event,
                author: author,
                members: &members,
                threads: &threads,
                tasks: &tasks,
                messages: &messages
            ) {
                append(
                    item,
                    outcome: .rejected,
                    reason: rejection,
                    authorChainConsumed: true
                )
            } else {
                acceptedEventIDs.append(event.id)
                append(item, outcome: .accepted, authorChainConsumed: true)
            }
        }

        let projection = NoctBoardProjection(
            boardID: configuration.boardID,
            groupID: configuration.groupID,
            members: members.values.sorted(by: memberOrder),
            threads: threads.values.map(\.value).sorted { uuidOrder($0.id, $1.id) },
            tasks: tasks.values.map(\.value).sorted { uuidOrder($0.id, $1.id) },
            messages: messages.values.sorted {
                if $0.createdAtUnixMilliseconds != $1.createdAtUnixMilliseconds {
                    return $0.createdAtUnixMilliseconds < $1.createdAtUnixMilliseconds
                }
                return uuidOrder($0.id, $1.id)
            },
            acceptedEventIDs: acceptedEventIDs
        )
        let ledger = NoctBoardLedger(entries: ledgerEntries)
        return NoctBoardProjectionResult(
            projection: projection,
            ledger: ledger,
            projectionDigest: try NoctBoardAuditExporter.projectionDigest(for: projection)
        )
    }

    private static func deterministicOrder(_ left: OrderedEvent, _ right: OrderedEvent) -> Bool {
        if left.event.logicalClock != right.event.logicalClock {
            return left.event.logicalClock < right.event.logicalClock
        }
        if left.event.createdAtUnixMilliseconds != right.event.createdAtUnixMilliseconds {
            return left.event.createdAtUnixMilliseconds < right.event.createdAtUnixMilliseconds
        }
        let leftID = left.event.id.uuidString.lowercased()
        let rightID = right.event.id.uuidString.lowercased()
        if leftID != rightID { return leftID < rightID }
        return left.digest.lexicographicallyPrecedes(right.digest)
    }

    private static func apply(
        _ event: NoctBoardEvent,
        author: NoctBoardMemberAuthorization,
        members: inout [GroupScopedMemberHandleV2: NoctBoardMemberAuthorization],
        threads: inout [UUID: MutableThread],
        tasks: inout [UUID: MutableTask],
        messages: inout [UUID: NoctBoardMessage]
    ) -> NoctBoardRejectionReason? {
        switch event.operation {
        case .createThread(let payload):
            guard author.role == .coordinator else { return .unauthorized }
            guard threads[payload.threadID] == nil else { return .duplicateThread }
            threads[payload.threadID] = MutableThread(
                value: NoctBoardThread(
                    id: payload.threadID,
                    title: payload.title,
                    createdBy: author.memberHandle,
                    createdAtUnixMilliseconds: event.createdAtUnixMilliseconds,
                    closedAtUnixMilliseconds: nil
                )
            )

        case .closeThread(let payload):
            guard author.role == .coordinator else { return .unauthorized }
            guard var thread = threads[payload.threadID] else { return .unknownThread }
            guard !thread.value.isClosed else { return .threadClosed }
            guard !tasks.values.contains(where: {
                $0.value.threadID == payload.threadID && !$0.value.state.isTerminal
            }) else { return .threadHasOpenTasks }
            thread.value = NoctBoardThread(
                id: thread.value.id,
                title: thread.value.title,
                createdBy: thread.value.createdBy,
                createdAtUnixMilliseconds: thread.value.createdAtUnixMilliseconds,
                closedAtUnixMilliseconds: event.createdAtUnixMilliseconds
            )
            threads[payload.threadID] = thread

        case .createTask(let payload):
            guard author.role == .coordinator else { return .unauthorized }
            guard let thread = threads[payload.threadID] else { return .unknownThread }
            guard !thread.value.isClosed else { return .threadClosed }
            guard tasks[payload.taskID] == nil else { return .duplicateTask }
            if let assignee = payload.assigneeMemberHandle {
                guard let member = members[assignee] else { return .unknownAssignee }
                guard member.role == .worker else { return .invalidAssigneeRole }
            }
            tasks[payload.taskID] = MutableTask(
                value: NoctBoardTask(
                    id: payload.taskID,
                    threadID: payload.threadID,
                    title: payload.title,
                    details: payload.details,
                    assigneeMemberHandle: payload.assigneeMemberHandle,
                    state: .pending,
                    createdBy: author.memberHandle,
                    createdAtUnixMilliseconds: event.createdAtUnixMilliseconds,
                    updatedAtUnixMilliseconds: event.createdAtUnixMilliseconds
                )
            )

        case .assignTask(let payload):
            guard var task = tasks[payload.taskID] else { return .unknownTask }
            guard let thread = threads[task.value.threadID] else { return .unknownThread }
            guard !thread.value.isClosed else { return .threadClosed }
            guard !task.value.state.isTerminal else { return .invalidTaskTransition }
            switch author.role {
            case .coordinator:
                break
            case .worker:
                guard payload.assigneeMemberHandle == author.memberHandle else {
                    return .unauthorized
                }
                guard task.value.assigneeMemberHandle == nil else {
                    return .taskAlreadyAssigned
                }
            case .auditor:
                return .unauthorized
            }
            if let assignee = payload.assigneeMemberHandle {
                guard let member = members[assignee] else { return .unknownAssignee }
                guard member.role == .worker else { return .invalidAssigneeRole }
            }
            guard task.value.assigneeMemberHandle != payload.assigneeMemberHandle else {
                return .noStateChange
            }
            task.value = NoctBoardTask(
                id: task.value.id,
                threadID: task.value.threadID,
                title: task.value.title,
                details: task.value.details,
                assigneeMemberHandle: payload.assigneeMemberHandle,
                state: task.value.state,
                createdBy: task.value.createdBy,
                createdAtUnixMilliseconds: task.value.createdAtUnixMilliseconds,
                updatedAtUnixMilliseconds: event.createdAtUnixMilliseconds
            )
            tasks[payload.taskID] = task

        case .transitionTask(let payload):
            guard var task = tasks[payload.taskID] else { return .unknownTask }
            guard let thread = threads[task.value.threadID] else { return .unknownThread }
            guard !thread.value.isClosed else { return .threadClosed }
            guard task.value.state == payload.from else { return .staleTaskState }
            guard payload.from.canTransition(to: payload.to) else { return .invalidTaskTransition }
            switch author.role {
            case .coordinator:
                break
            case .worker:
                guard task.value.assigneeMemberHandle == author.memberHandle,
                      payload.to != .cancelled else {
                    return .unauthorized
                }
            case .auditor:
                return .unauthorized
            }
            task.value = NoctBoardTask(
                id: task.value.id,
                threadID: task.value.threadID,
                title: task.value.title,
                details: task.value.details,
                assigneeMemberHandle: task.value.assigneeMemberHandle,
                state: payload.to,
                createdBy: task.value.createdBy,
                createdAtUnixMilliseconds: task.value.createdAtUnixMilliseconds,
                updatedAtUnixMilliseconds: event.createdAtUnixMilliseconds
            )
            tasks[payload.taskID] = task

        case .postMessage(let payload):
            guard author.role != .auditor else { return .unauthorized }
            guard let thread = threads[payload.threadID] else { return .unknownThread }
            guard !thread.value.isClosed else { return .threadClosed }
            guard messages[payload.messageID] == nil else { return .duplicateMessage }
            if let taskID = payload.taskID {
                guard let task = tasks[taskID] else { return .unknownTask }
                guard task.value.threadID == payload.threadID else { return .taskThreadMismatch }
            }
            messages[payload.messageID] = NoctBoardMessage(
                id: payload.messageID,
                threadID: payload.threadID,
                taskID: payload.taskID,
                authorMemberHandle: author.memberHandle,
                body: payload.body,
                createdAtUnixMilliseconds: event.createdAtUnixMilliseconds
            )

        case .setRole(let payload):
            guard author.role == .coordinator else { return .unauthorized }
            guard let target = members[payload.memberHandle] else { return .unknownAuthor }
            guard target.role != payload.role else { return .noStateChange }
            if target.role == .worker && payload.role != .worker {
                guard !tasks.values.contains(where: {
                    $0.value.assigneeMemberHandle == target.memberHandle
                        && !$0.value.state.isTerminal
                }) else { return .memberHasOpenTasks }
            }
            if target.role == .coordinator && payload.role != .coordinator {
                let coordinatorCount = members.values.filter { $0.role == .coordinator }.count
                guard coordinatorCount > 1 else { return .lastCoordinator }
            }
            members[payload.memberHandle] = NoctBoardMemberAuthorization(
                memberHandle: target.memberHandle,
                credentialHandle: target.credentialHandle,
                role: payload.role
            )
        }
        return nil
    }

    private static func uuidOrder(_ left: UUID, _ right: UUID) -> Bool {
        left.uuidString.lowercased() < right.uuidString.lowercased()
    }

    private static func memberOrder(
        _ left: NoctBoardMemberAuthorization,
        _ right: NoctBoardMemberAuthorization
    ) -> Bool {
        left.memberHandle.rawValue < right.memberHandle.rawValue
    }
}

extension NoctBoardThread: @unchecked Sendable {}
extension NoctBoardTask: @unchecked Sendable {}
extension NoctBoardMessage: @unchecked Sendable {}
extension NoctBoardProjection: @unchecked Sendable {}
extension NoctBoardLedgerEntry: @unchecked Sendable {}
extension NoctBoardLedger: @unchecked Sendable {}
extension NoctBoardProjectionResult: @unchecked Sendable {}
