// SPDX-FileCopyrightText: 2026 Luiz Widmer
// SPDX-License-Identifier: AGPL-3.0-or-later

import Foundation
import NoctBoardCore
import NoctweaveCore

/// A fixed projection used by the standalone audit console and previews.
/// It deliberately contains both an auditor write denial and a foreign-group denial.
enum NoctBoardDemoFixture {
    static func make() throws -> NoctBoardProjectionResult {
        let boardID = uuid("00000000-0000-4000-8000-000000000001")
        let groupID = boardID
        let threadID = uuid("00000000-0000-4000-8000-000000000101")
        let taskID = uuid("00000000-0000-4000-8000-000000000201")
        let pendingTaskID = uuid("00000000-0000-4000-8000-000000000202")
        let coordinator = member(0x11, 0x21, .coordinator)
        let worker = member(0x12, 0x22, .worker)
        let auditor = member(0x13, 0x23, .auditor)
        let outsider = member(0x14, 0x24, .worker)
        let configuration = NoctBoardConfiguration(
            boardID: boardID,
            groupID: groupID,
            members: [coordinator, worker, auditor]
        )

        let createThread = event(
            1, boardID, groupID, coordinator, 0, 0, nil,
            .createThread(NoctBoardCreateThread(threadID: threadID, title: "Release readiness"))
        )
        let createThreadDigest = try NoctBoardCodec.digest(createThread)
        let createTask = event(
            2, boardID, groupID, coordinator, 1, 1, createThreadDigest,
            .createTask(
                NoctBoardCreateTask(
                    taskID: taskID,
                    threadID: threadID,
                    title: "Audit the release candidate",
                    details: "Check deterministic projection and rejection evidence.",
                    assigneeMemberHandle: worker.memberHandle
                )
            )
        )
        let createTaskDigest = try NoctBoardCodec.digest(createTask)
        let activate = event(
            3, boardID, groupID, worker, 2, 0, nil,
            .transitionTask(NoctBoardTransitionTask(taskID: taskID, from: .pending, to: .active))
        )
        let activateDigest = try NoctBoardCodec.digest(activate)
        let workerMessage = event(
            4, boardID, groupID, worker, 3, 1, activateDigest,
            .postMessage(
                NoctBoardPostMessage(
                    messageID: uuid("00000000-0000-4000-8000-000000000301"),
                    threadID: threadID,
                    taskID: taskID,
                    body: "Projection reproduced. Reviewing the rejected boundary attempts now."
                )
            )
        )
        let workerMessageDigest = try NoctBoardCodec.digest(workerMessage)
        let deniedAuditorWrite = event(
            5, boardID, groupID, auditor, 4, 0, nil,
            .postMessage(
                NoctBoardPostMessage(
                    messageID: uuid("00000000-0000-4000-8000-000000000302"),
                    threadID: threadID,
                    body: "This must remain rejected because auditors are read-only."
                )
            )
        )
        let deniedForeignGroup = event(
            6,
            boardID,
            uuid("00000000-0000-4000-8000-000000000003"),
            outsider,
            5,
            0,
            nil,
            .postMessage(
                NoctBoardPostMessage(
                    messageID: uuid("00000000-0000-4000-8000-000000000303"),
                    threadID: threadID,
                    body: "A different swarm must not enter this board."
                )
            )
        )
        let createAuditTask = event(
            7, boardID, groupID, coordinator, 5, 2, createTaskDigest,
            .createTask(
                NoctBoardCreateTask(
                    taskID: pendingTaskID,
                    threadID: threadID,
                    title: "Publish the redacted audit",
                    details: "Export ledger metadata without message or task plaintext."
                )
            )
        )
        let createAuditTaskDigest = try NoctBoardCodec.digest(createAuditTask)
        let coordinatorMessage = event(
            8, boardID, groupID, coordinator, 6, 3, createAuditTaskDigest,
            .postMessage(
                NoctBoardPostMessage(
                    messageID: uuid("00000000-0000-4000-8000-000000000304"),
                    threadID: threadID,
                    body: "Human audit gate is open; no global agent identity is required."
                )
            )
        )
        let complete = event(
            9, boardID, groupID, worker, 7, 2, workerMessageDigest,
            .transitionTask(NoctBoardTransitionTask(taskID: taskID, from: .active, to: .completed))
        )

        return try NoctBoardProjector.project(
            events: [
                complete, deniedForeignGroup, createThread, coordinatorMessage, activate,
                deniedAuditorWrite, createTask, workerMessage, createAuditTask,
            ],
            configuration: configuration
        )
    }

    private static func member(
        _ memberByte: UInt8,
        _ credentialByte: UInt8,
        _ role: NoctBoardRole
    ) -> NoctBoardMemberAuthorization {
        NoctBoardMemberAuthorization(
            memberHandle: GroupScopedMemberHandleV2(
                rawValue: Data(repeating: memberByte, count: 32).base64EncodedString()
            ),
            credentialHandle: GroupScopedCredentialHandleV2(
                rawValue: Data(repeating: credentialByte, count: 32).base64EncodedString()
            ),
            role: role
        )
    }

    private static func event(
        _ number: Int,
        _ boardID: UUID,
        _ groupID: UUID,
        _ author: NoctBoardMemberAuthorization,
        _ logicalClock: UInt64,
        _ authorSequence: UInt64,
        _ previousDigest: Data?,
        _ operation: NoctBoardOperation
    ) -> NoctBoardEvent {
        NoctBoardEvent(
            id: uuid(String(format: "00000000-0000-4000-8000-%012d", 400 + number)),
            clientTransactionID: uuid(String(format: "00000000-0000-4000-8000-%012d", 500 + number)),
            boardID: boardID,
            groupID: groupID,
            authorMemberHandle: author.memberHandle,
            authorCredentialHandle: author.credentialHandle,
            logicalClock: logicalClock,
            authorSequence: authorSequence,
            previousAuthorEventDigest: previousDigest,
            createdAtUnixMilliseconds: 1_800_000_000_000 + Int64(number * 1_000),
            operation: operation
        )
    }

    private static func uuid(_ value: String) -> UUID { UUID(uuidString: value)! }
}
