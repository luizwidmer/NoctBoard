// SPDX-FileCopyrightText: 2026 Luiz Widmer
// SPDX-License-Identifier: AGPL-3.0-or-later

import Darwin
import Foundation
import NoctBoardCore
import NoctweaveCore

@main
enum NoctBoardDemo {
    static func main() {
        do {
            let result = try makeProjection()
            let output = Output(
                mode: "deterministic-core-projection",
                acceptedCount: result.ledger.accepted.count,
                rejectedCount: result.ledger.rejected.count,
                projectionDigest: result.projectionDigest,
                projection: result.projection,
                ledger: result.ledger
            )
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
            var data = try encoder.encode(output)
            data.append(0x0A)
            FileHandle.standardOutput.write(data)
        } catch {
            FileHandle.standardError.write(Data("NoctBoardDemo: \(error.localizedDescription)\n".utf8))
            Darwin.exit(1)
        }
    }

    private static func makeProjection() throws -> NoctBoardProjectionResult {
        let boardID = uuid("10000000-0000-4000-8000-000000000001")
        let groupID = boardID
        let foreignGroupID = uuid("10000000-0000-4000-8000-000000000003")
        let threadID = uuid("10000000-0000-4000-8000-000000000101")
        let coordinator = authorization(0x31, 0x41, .coordinator)
        let worker = authorization(0x32, 0x42, .worker)
        let configuration = NoctBoardConfiguration(
            boardID: boardID,
            groupID: groupID,
            members: [coordinator, worker]
        )

        let create = NoctBoardEvent(
            id: uuid("10000000-0000-4000-8000-000000000401"),
            clientTransactionID: uuid("10000000-0000-4000-8000-000000000501"),
            boardID: boardID,
            groupID: groupID,
            authorMemberHandle: coordinator.memberHandle,
            authorCredentialHandle: coordinator.credentialHandle,
            logicalClock: 0,
            authorSequence: 0,
            previousAuthorEventDigest: nil,
            createdAtUnixMilliseconds: 1_800_100_000_000,
            operation: .createThread(
                NoctBoardCreateThread(threadID: threadID, title: "Agent swarm handoff")
            )
        )
        let createDigest = try NoctBoardCodec.digest(create)
        let message = NoctBoardEvent(
            id: uuid("10000000-0000-4000-8000-000000000402"),
            clientTransactionID: uuid("10000000-0000-4000-8000-000000000502"),
            boardID: boardID,
            groupID: groupID,
            authorMemberHandle: coordinator.memberHandle,
            authorCredentialHandle: coordinator.credentialHandle,
            logicalClock: 1,
            authorSequence: 1,
            previousAuthorEventDigest: createDigest,
            createdAtUnixMilliseconds: 1_800_100_001_000,
            operation: .postMessage(
                NoctBoardPostMessage(
                    messageID: uuid("10000000-0000-4000-8000-000000000301"),
                    threadID: threadID,
                    body: "The board is ready for a human audit."
                )
            )
        )
        let blockedForeignMessage = NoctBoardEvent(
            id: uuid("10000000-0000-4000-8000-000000000403"),
            clientTransactionID: uuid("10000000-0000-4000-8000-000000000503"),
            boardID: boardID,
            groupID: foreignGroupID,
            authorMemberHandle: worker.memberHandle,
            authorCredentialHandle: worker.credentialHandle,
            logicalClock: 2,
            authorSequence: 0,
            previousAuthorEventDigest: nil,
            createdAtUnixMilliseconds: 1_800_100_002_000,
            operation: .postMessage(
                NoctBoardPostMessage(
                    messageID: uuid("10000000-0000-4000-8000-000000000302"),
                    threadID: threadID,
                    body: "A foreign group cannot append here."
                )
            )
        )

        return try NoctBoardProjector.project(
            events: [blockedForeignMessage, message, create],
            configuration: configuration
        )
    }

    private static func authorization(
        _ memberByte: UInt8,
        _ credentialByte: UInt8,
        _ role: NoctBoardRole
    ) -> NoctBoardMemberAuthorization {
        NoctBoardMemberAuthorization(
            memberHandle: .init(
                rawValue: Data(repeating: memberByte, count: 32).base64EncodedString()
            ),
            credentialHandle: .init(
                rawValue: Data(repeating: credentialByte, count: 32).base64EncodedString()
            ),
            role: role
        )
    }

    private static func uuid(_ string: String) -> UUID { UUID(uuidString: string)! }

    private struct Output: Encodable {
        let mode: String
        let acceptedCount: Int
        let rejectedCount: Int
        let projectionDigest: String
        let projection: NoctBoardProjection
        let ledger: NoctBoardLedger
    }
}
