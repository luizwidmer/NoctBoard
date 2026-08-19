// SPDX-FileCopyrightText: 2026 Luiz Widmer
// SPDX-License-Identifier: AGPL-3.0-or-later

import CoreFoundation
import Darwin
import Foundation
import NoctBoardCore
import NoctBoardTransport
import NoctweaveCore

@main
enum NoctBoardCLI {
    static func main() async {
        do {
            try await run(Array(CommandLine.arguments.dropFirst()))
        } catch {
            let description = (error as? LocalizedError)?.errorDescription
                ?? String(reflecting: error)
            writeError("noctboard: \(description)\n")
            Darwin.exit(2)
        }
    }

    private static func run(_ arguments: [String]) async throws {
        guard let command = arguments.first else {
            writeOutput(help)
            return
        }

        let trailing = Array(arguments.dropFirst())
        switch command {
        case "help", "--help", "-h":
            guard trailing.isEmpty else { throw CLIError.unexpectedArguments(command) }
            writeOutput(help)

        case "license":
            guard trailing.isEmpty else { throw CLIError.unexpectedArguments(command) }
            writeOutput(legalNotice)

        case "demo":
            guard trailing.isEmpty else { throw CLIError.unexpectedArguments(command) }
            let result = try DeterministicDemo.make()
            try writeJSON(
                DemoOutput(
                    schema: "org.noctboard/demo:1.0",
                    security: .init(
                        boardIsolation: "one-board-one-noctweave-group",
                        authorization: "group-scoped-member-and-credential-handles",
                        auditExport: "redacted-decision-ledger",
                        plaintextIncludedInAuditExport: false
                    ),
                    projection: result.projection,
                    ledger: result.ledger,
                    projectionDigest: result.projectionDigest
                )
            )

        case "verify-demo-projection":
            guard trailing.isEmpty else { throw CLIError.unexpectedArguments(command) }
            let result = try DeterministicDemo.make()
            let verified = try NoctBoardAuditExporter.verifyProjection(
                result.projection,
                expectedDigest: result.projectionDigest
            )
            try writeJSON(
                ProjectionVerificationOutput(
                    schema: NoctBoardAuditExporter.schema,
                    scope: "local-full-projection-digest",
                    verified: verified,
                    projectionDigest: result.projectionDigest
                )
            )
            if !verified { Darwin.exit(1) }

        case "export-demo-audit":
            guard trailing.count <= 1 else { throw CLIError.unexpectedArguments(command) }
            let data = try NoctBoardAuditExporter.jsonLines(
                for: DeterministicDemo.make(),
                containerRejections: DeterministicDemo.containerRejections
            )
            if let destination = trailing.first, destination != "-" {
                let url = URL(fileURLWithPath: destination).standardizedFileURL
                let bytes = try writeSensitiveData(data, to: url)
                try writeJSON(
                    ExportOutput(
                        schema: NoctBoardAuditExporter.schema,
                        path: url.path,
                        bytes: bytes,
                        redacted: true
                    )
                )
            } else {
                FileHandle.standardOutput.write(data)
            }

        case "inspect-audit":
            guard trailing.count == 1 else { throw CLIError.requiresPath(command) }
            let url = URL(fileURLWithPath: trailing[0]).standardizedFileURL
            let inspection = try AuditInspector.inspect(
                readBoundedRegularFile(url, maximumBytes: AuditInspector.maximumBytes),
                path: url.path
            )
            try writeJSON(inspection)
            if !inspection.structurallyValid {
                writeError("noctboard: audit structure or summary counts are inconsistent\n")
                Darwin.exit(1)
            }

        case "create-board", "snapshot", "sync", "relay-health",
             "create-thread", "close-thread", "post-message", "create-task",
             "claim-task", "assign-task", "transition-task", "set-role",
             "export-audit", "prepare-admission", "admit", "complete-admission",
             "maintain", "resume-publication":
            try await runLive(command: command, arguments: trailing)

        default:
            throw CLIError.unknownCommand(command)
        }
    }

    private static let help = """
    NoctBoard — an auditable message board for one protected Noctweave agent group

    USAGE
      noctboard help
      noctboard license
      noctboard demo
      noctboard verify-demo-projection
      noctboard export-demo-audit [PATH|-]
      noctboard inspect-audit PATH
      noctboard create-board LIVE_OPTIONS --name-file PATH --recovery PATH
      noctboard snapshot LIVE_BOARD_OPTIONS
      noctboard sync LIVE_BOARD_OPTIONS
      noctboard post-message LIVE_BOARD_OPTIONS --thread UUID --body-file PATH [--task UUID]
      noctboard create-task LIVE_BOARD_OPTIONS --thread UUID --title-file PATH [--details-file PATH]
      noctboard claim-task LIVE_BOARD_OPTIONS --task UUID
      noctboard transition-task LIVE_BOARD_OPTIONS --task UUID --from STATE --to STATE
      noctboard maintain LIVE_BOARD_OPTIONS
      noctboard resume-publication LIVE_BOARD_OPTIONS --operation UUID
      noctboard export-audit LIVE_BOARD_OPTIONS --output PATH|-
      noctboard prepare-admission LIVE_BOARD_OPTIONS --binding-digest HEX --expires-at ISO8601 --request-out PATH
      noctboard admit LIVE_BOARD_OPTIONS --request PATH --package-out PATH
      noctboard complete-admission LIVE_OPTIONS --request PATH --package PATH

    COMMANDS
      license                 Show copyright, warranty, license, and source notice.
      demo                    Emit a deterministic local projection and ledger as JSON.
      verify-demo-projection  Recompute and compare the full local projection digest.
      export-demo-audit       Emit redacted audit JSONL to stdout or securely create PATH.
      inspect-audit           Check JSONL schema, ordering, digests, and summary counts.
      create-board            Create/recover a board using an owner-only recovery descriptor.
      snapshot                Emit the current local projection and decision ledger.
      sync                    Fetch encrypted group events, then emit the new snapshot.
      relay-health            Check the explicitly configured relay endpoint.
      create-thread           Publish a coordinator thread using --title-file.
      close-thread            Publish a coordinator thread closure.
      post-message            Publish literal --body-file text, optionally linked to a task.
      create-task             Publish --title-file/--details-file text; optionally pre-assign it.
      claim-task              Assign an unclaimed task to this local group member.
      assign-task             Assign a task to --assignee HANDLE, or --unassign it.
      transition-task         Move a task through an allowed explicit state transition.
      set-role                Set --member HANDLE to coordinator, worker, or auditor.
      maintain                Resume pending routes/transports and emit the maintenance report.
      resume-publication      Resume the exact durable bytes for --operation UUID.
      export-audit            Export the live board's redacted decision ledger.
      prepare-admission       Create a prospective member request in an owner-only file.
      admit                   Admit that request and create an owner-only response package.
      complete-admission      Install the response package into prospective member state.

    LIVE_OPTIONS
      --state PATH            Durable local Noctweave client-state file.
      --display NAME          Local display label (not protocol identity).
      --relay ENDPOINT        Explicit tcp/tls/http/https/ws/wss relay endpoint.
                              tcp/http/ws are passwordless evaluation transports only.
      --scope ID              Stable rollback-anchor scope (derived from PATH if omitted).
      --relay-password-env V  Read a non-empty password from env for tls/https/wss only,
                              then persist it in client state.
      --plaintext-testing     Disable state encryption only for isolated local testing.

      A non-empty relay password is accepted only for tls/https/wss. Plaintext tcp/http/ws
      must use no password and are evaluation-only. Client state stores the selected relay
      preference and access password encrypted by default; --plaintext-testing exposes both
      client secrets and any persisted relay password as plaintext.

    LIVE_BOARD_OPTIONS
      LIVE_OPTIONS plus --board UUID. In v1 the Noctweave group UUID equals the board UUID.

    PROTECTED TEXT
      Board names, thread/task titles, task details, and message bodies are never accepted
      as argv values. Supply UTF-8 regular files with --name-file, --title-file,
      --details-file, or --body-file. Symlinks are refused, reads are byte-bounded to the
      protocol field limit, and bytes are used literally without trimming. Prefer mode 0600;
      create single-line title files without a trailing newline.

    EXACT PUBLISH RETRY
      create-board requires --recovery PATH. On its first run it creates that mode-0600 file
      before group mutation with stable board/thread/event/transaction IDs and the initial
      title. Re-run the same command and file after a crash or relay error; NoctBoard resumes
      the existing group/event or creates it if group creation never became durable. Keep the
      descriptor private until the initial publication is complete.

      Every thread/message/task/role publish command accepts optional stable --event-id and
      --transaction-id UUIDs. Persist both IDs and the returned operationID. Retrying the same
      IDs and operation resumes matching durable bytes; resume-publication targets operationID
      directly. Reusing either ID for different content fails closed.

    ROUTE LEASE
      Noctweave group receive routes lease for 6 hours. Run maintain at least every 5 hours;
      maintain/sync rotate near expiry. An endpoint offline past its lease can miss delivery.
      Opaque routes are not archives, and v1 cannot recover events it never received.

    OUTPUT SENSITIVITY
      snapshot, sync, and both deterministic demos emit full projection title/details/message
      text on stdout. Protect terminal scrollback, pipes, and agent logs. Only export-audit is
      text-redacted, but it still contains sensitive member handles and decision metadata;
      --output PATH creates a new mode-0600 file, while explicit --output - uses stdout.

    ADMISSION SAFETY
      Admission request/package files contain group-scoped join and routing material. The CLI
      refuses to print them to stdout or overwrite an existing path, and creates them mode 0600.
      Move both artifacts only through an independently authenticated encrypted invitation
      channel. Matching filenames or board UUIDs do not authenticate the human or agent peer.

    SECURITY SCOPE
      inspect-audit is a structural consistency check. A redacted audit does not contain
      the plaintext projection or enough material to replay the Noctweave group history.
      Coordinator/worker/auditor roles constrain conforming clients only. For a malicious
      admitted endpoint, credential removal plus epoch rotation is the future-write cutoff.
      Diagnostics use stderr; JSON and JSONL machine output use stdout.

    LEGAL NOTICE
      Copyright (C) 2026 Luiz Widmer. Noct Board is free software under
      AGPL-3.0-or-later and comes with absolutely no warranty. Run
      `noctboard license`; source is at https://github.com/luizwidmer/NoctBoard.
    """

    private static let legalNotice = """
    Noct Board — Copyright (C) 2026 Luiz Widmer

    This program is free software: you can redistribute it and/or modify it
    under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or (at your
    option) any later version.

    This program is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
    FITNESS FOR A PARTICULAR PURPOSE.

    SPDX-License-Identifier: AGPL-3.0-or-later
    Read LICENSE and NOTICE in the Noct Board source distribution for the full
    license text and dependency notices. Source is available at
    https://github.com/luizwidmer/NoctBoard.
    """

    private static func writeJSON<T: Encodable>(_ value: T) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        var data = try encoder.encode(value)
        data.append(0x0A)
        FileHandle.standardOutput.write(data)
    }

    private static func writeOutput(_ string: String) {
        FileHandle.standardOutput.write(Data(string.utf8))
        if !string.hasSuffix("\n") { FileHandle.standardOutput.write(Data([0x0A])) }
    }

    private static func writeError(_ string: String) {
        FileHandle.standardError.write(Data(string.utf8))
    }

    private static func runLive(command: String, arguments: [String]) async throws {
        var options = try ArgumentBag(
            arguments,
            booleanOptions: ["--plaintext-testing", "--unassign"]
        )

        switch command {
        case "create-board":
            let name = try protectedText(
                from: &options,
                option: "--name-file",
                maximumBytes: NoctBoardLimits.maximumThreadTitleBytes
            )
            let configuration = try liveConfiguration(from: &options)
            let recoveryURL = URL(
                fileURLWithPath: try options.require("--recovery")
            ).standardizedFileURL
            let requestedBoardID = try options.optionalUUID("--board")
            let requestedThreadID = try options.optionalUUID("--thread")
            let requestedEventID = try options.optionalUUID("--event-id")
            let requestedTransactionID = try options.optionalUUID("--transaction-id")
            try options.requireEmpty()
            let recovery = try boardCreationRecovery(
                at: recoveryURL,
                stateFileURL: configuration.stateFileURL,
                name: name,
                requestedBoardID: requestedBoardID,
                requestedThreadID: requestedThreadID,
                requestedEventID: requestedEventID,
                requestedTransactionID: requestedTransactionID
            )
            let client = try await NoctBoardClient.open(configuration: configuration)
            let created = try await client.recoverBoardCreation(
                name: recovery.initialThreadTitle,
                boardID: recovery.boardID,
                initialThreadID: recovery.initialThreadID,
                initialEventID: recovery.initialEventID,
                initialClientTransactionID: recovery.initialClientTransactionID,
                createdAt: recovery.createdAt
            )
            try writeJSON(CreationOutput(created, recoveryPath: recoveryURL.path))

        case "snapshot":
            let client = try await openBoundClient(from: &options)
            try options.requireEmpty()
            try writeJSON(SnapshotOutput(try await client.snapshot()))

        case "sync":
            let client = try await openBoundClient(from: &options)
            try options.requireEmpty()
            let synchronized = try await client.synchronize()
            try writeJSON(SynchronizationOutput(synchronized))

        case "relay-health":
            let configuration = try liveConfiguration(from: &options)
            let board = try optionalBoardReference(from: &options)
            try options.requireEmpty()
            let client = try await NoctBoardClient.open(configuration: configuration, board: board)
            try writeJSON(try await client.relayHealth())

        case "create-thread":
            let title = try protectedText(
                from: &options,
                option: "--title-file",
                maximumBytes: NoctBoardLimits.maximumThreadTitleBytes
            )
            let threadID = try options.uuid("--thread", default: UUID())
            let identifiers = try publishIdentifiers(from: &options)
            let client = try await openBoundClient(from: &options)
            try options.requireEmpty()
            try writeJSON(PublishOutput(try await client.publish(
                .createThread(NoctBoardCreateThread(threadID: threadID, title: title)),
                eventID: identifiers.eventID,
                clientTransactionID: identifiers.transactionID
            )))

        case "close-thread":
            let threadID = try options.uuid("--thread")
            let identifiers = try publishIdentifiers(from: &options)
            let client = try await openBoundClient(from: &options)
            try options.requireEmpty()
            try writeJSON(PublishOutput(try await client.publish(
                .closeThread(NoctBoardCloseThread(threadID: threadID)),
                eventID: identifiers.eventID,
                clientTransactionID: identifiers.transactionID
            )))

        case "post-message":
            let threadID = try options.uuid("--thread")
            let taskID = try options.optionalUUID("--task")
            let body = try protectedText(
                from: &options,
                option: "--body-file",
                maximumBytes: NoctBoardLimits.maximumMessageBodyBytes
            )
            let messageID = try options.uuid("--message", default: UUID())
            let identifiers = try publishIdentifiers(from: &options)
            let client = try await openBoundClient(from: &options)
            try options.requireEmpty()
            try writeJSON(PublishOutput(try await client.publish(
                .postMessage(
                    NoctBoardPostMessage(
                        messageID: messageID,
                        threadID: threadID,
                        taskID: taskID,
                        body: body
                    )
                ),
                eventID: identifiers.eventID,
                clientTransactionID: identifiers.transactionID
            )))

        case "create-task":
            let threadID = try options.uuid("--thread")
            let taskID = try options.uuid("--task", default: UUID())
            let title = try protectedText(
                from: &options,
                option: "--title-file",
                maximumBytes: NoctBoardLimits.maximumTaskTitleBytes
            )
            let details: String?
            if options.contains("--details-file") {
                details = try protectedText(
                    from: &options,
                    option: "--details-file",
                    maximumBytes: NoctBoardLimits.maximumTaskDetailsBytes
                )
            } else {
                details = nil
            }
            let assignee = try options.optionalMemberHandle("--assignee")
            let identifiers = try publishIdentifiers(from: &options)
            let client = try await openBoundClient(from: &options)
            try options.requireEmpty()
            try writeJSON(PublishOutput(try await client.publish(
                .createTask(
                    NoctBoardCreateTask(
                        taskID: taskID,
                        threadID: threadID,
                        title: title,
                        details: details,
                        assigneeMemberHandle: assignee
                    )
                ),
                eventID: identifiers.eventID,
                clientTransactionID: identifiers.transactionID
            )))

        case "claim-task":
            let taskID = try options.uuid("--task")
            let identifiers = try publishIdentifiers(from: &options)
            let client = try await openBoundClient(from: &options)
            try options.requireEmpty()
            let local = try await client.snapshot().localMemberHandle
            try writeJSON(PublishOutput(try await client.publish(
                .assignTask(NoctBoardAssignTask(taskID: taskID, assigneeMemberHandle: local)),
                eventID: identifiers.eventID,
                clientTransactionID: identifiers.transactionID
            )))

        case "assign-task":
            let taskID = try options.uuid("--task")
            let unassign = options.takeFlag("--unassign")
            let supplied = try options.optionalMemberHandle("--assignee")
            guard unassign != (supplied != nil) else {
                throw CLIError.invalidCombination("choose exactly one of --assignee or --unassign")
            }
            let identifiers = try publishIdentifiers(from: &options)
            let client = try await openBoundClient(from: &options)
            try options.requireEmpty()
            try writeJSON(PublishOutput(try await client.publish(
                .assignTask(NoctBoardAssignTask(taskID: taskID, assigneeMemberHandle: supplied)),
                eventID: identifiers.eventID,
                clientTransactionID: identifiers.transactionID
            )))

        case "transition-task":
            let taskID = try options.uuid("--task")
            let from = try options.taskState("--from")
            let to = try options.taskState("--to")
            let identifiers = try publishIdentifiers(from: &options)
            let client = try await openBoundClient(from: &options)
            try options.requireEmpty()
            try writeJSON(PublishOutput(try await client.publish(
                .transitionTask(NoctBoardTransitionTask(taskID: taskID, from: from, to: to)),
                eventID: identifiers.eventID,
                clientTransactionID: identifiers.transactionID
            )))

        case "set-role":
            let member = try options.memberHandle("--member")
            let role = try options.role("--role")
            let identifiers = try publishIdentifiers(from: &options)
            let client = try await openBoundClient(from: &options)
            try options.requireEmpty()
            try writeJSON(PublishOutput(try await client.publish(
                .setRole(NoctBoardSetRole(memberHandle: member, role: role)),
                eventID: identifiers.eventID,
                clientTransactionID: identifiers.transactionID
            )))

        case "maintain":
            let client = try await openBoundClient(from: &options)
            try options.requireEmpty()
            try writeJSON(try await client.maintain())

        case "resume-publication":
            let operationID = try options.uuid("--operation")
            let client = try await openBoundClient(from: &options)
            try options.requireEmpty()
            try writeJSON(try await client.resumePublication(operationID: operationID))

        case "export-audit":
            let output = try options.require("--output")
            let client = try await openBoundClient(from: &options)
            try options.requireEmpty()
            let data = try await client.auditJSONL()
            if output == "-" {
                FileHandle.standardOutput.write(data)
            } else {
                let url = URL(fileURLWithPath: output).standardizedFileURL
                let bytes = try writeSensitiveData(data, to: url)
                try writeJSON(
                    ExportOutput(
                        schema: NoctBoardAuditExporter.schema,
                        path: url.path,
                        bytes: bytes,
                        redacted: true
                    )
                )
            }

        case "prepare-admission":
            let bindingDigest = try options.digest("--binding-digest")
            let expiresAt = try options.iso8601Date("--expires-at")
            let output = URL(
                fileURLWithPath: try options.require("--request-out")
            ).standardizedFileURL
            let outputReservation = try SensitiveOutputReservation(url: output)
            let configuration = try liveConfiguration(from: &options)
            guard let board = try optionalBoardReference(from: &options) else {
                throw CLIError.missingOption("--board")
            }
            try options.requireEmpty()
            // A prospective member cannot bind/open the group until completion succeeds.
            let client = try await NoctBoardClient.open(configuration: configuration)
            let request = try await client.prepareAdmission(
                to: board,
                invitationBindingDigest: bindingDigest,
                expiresAt: expiresAt
            )
            let bytes = try writeSensitiveJSON(request, to: outputReservation)
            try writeJSON(SensitiveArtifactOutput(
                kind: "admission-request",
                path: output.path,
                bytes: bytes,
                board: request.board,
                admissionID: request.admissionID,
                fileMode: "0600",
                secureChannelRequired: true
            ))

        case "admit":
            let requestURL = URL(
                fileURLWithPath: try options.require("--request")
            ).standardizedFileURL
            let output = URL(
                fileURLWithPath: try options.require("--package-out")
            ).standardizedFileURL
            // Reserve the destination before the epoch-changing admission so
            // an existing/uncreatable path cannot strand a newly added member
            // without its Welcome package.
            let outputReservation = try SensitiveOutputReservation(url: output)
            let request: NoctBoardAdmissionRequest = try decodeJSONFile(requestURL)
            let client = try await openBoundClient(from: &options)
            try options.requireEmpty()
            let package = try await client.admit(request)
            let bytes = try writeSensitiveJSON(package, to: outputReservation)
            try writeJSON(SensitiveArtifactOutput(
                kind: "admission-package",
                path: output.path,
                bytes: bytes,
                board: package.board,
                admissionID: package.admissionID,
                fileMode: "0600",
                secureChannelRequired: true
            ))

        case "complete-admission":
            let requestURL = URL(
                fileURLWithPath: try options.require("--request")
            ).standardizedFileURL
            let packageURL = URL(
                fileURLWithPath: try options.require("--package")
            ).standardizedFileURL
            let request: NoctBoardAdmissionRequest = try decodeJSONFile(requestURL)
            let package: NoctBoardAdmissionPackage = try decodeJSONFile(packageURL)
            let configuration = try liveConfiguration(from: &options)
            try options.requireEmpty()
            let client = try await NoctBoardClient.open(configuration: configuration)
            try await client.completeAdmission(request: request, package: package)
            try writeJSON(AdmissionCompletionOutput(
                completed: true,
                board: package.board,
                admissionID: package.admissionID,
                localStatePath: configuration.stateFileURL.path
            ))

        default:
            throw CLIError.unknownCommand(command)
        }
    }

    private static func openBoundClient(from options: inout ArgumentBag) async throws -> NoctBoardClient {
        let configuration = try liveConfiguration(from: &options)
        guard let board = try optionalBoardReference(from: &options) else {
            throw CLIError.missingOption("--board")
        }
        return try await NoctBoardClient.open(configuration: configuration, board: board)
    }

    private static func publishIdentifiers(
        from options: inout ArgumentBag
    ) throws -> (eventID: UUID, transactionID: UUID) {
        (
            eventID: try options.uuid("--event-id", default: UUID()),
            transactionID: try options.uuid("--transaction-id", default: UUID())
        )
    }

    private static func liveConfiguration(
        from options: inout ArgumentBag
    ) throws -> NoctBoardClientOpenConfiguration {
        let statePath = try options.require("--state")
        let display = try options.require("--display")
        let relay = try RelayEndpointParser.parse(try options.require("--relay"))
        let scope = options.take("--scope")
        let password: String?
        if let variable = options.take("--relay-password-env") {
            guard let value = ProcessInfo.processInfo.environment[variable] else {
                throw CLIError.missingEnvironmentVariable(variable)
            }
            password = value
        } else {
            password = nil
        }
        return NoctBoardClientOpenConfiguration(
            stateFileURL: URL(fileURLWithPath: statePath).standardizedFileURL,
            storageScopeIdentifier: scope,
            displayName: display,
            relay: relay,
            relayAccessPassword: password,
            stateProtection: options.takeFlag("--plaintext-testing")
                ? .insecurePlaintextForTesting
                : .encrypted
        )
    }

    private static func optionalBoardReference(
        from options: inout ArgumentBag
    ) throws -> NoctBoardReference? {
        guard let value = options.take("--board") else {
            return nil
        }
        guard let boardID = UUID(uuidString: value) else {
            throw CLIError.invalidUUID(option: "--board", value: value)
        }
        return try NoctBoardReference(id: boardID)
    }

    private static func boardCreationRecovery(
        at url: URL,
        stateFileURL: URL,
        name: String,
        requestedBoardID: UUID?,
        requestedThreadID: UUID?,
        requestedEventID: UUID?,
        requestedTransactionID: UUID?
    ) throws -> BoardCreationRecoveryRecord {
        var status = stat()
        let exists = url.withUnsafeFileSystemRepresentation { path -> Bool in
            guard let path else { return false }
            return Darwin.lstat(path, &status) == 0
        }

        if exists {
            guard (status.st_mode & S_IFMT) == S_IFREG else {
                throw CLIError.invalidArtifact(path: url.path)
            }
            let recovery: BoardCreationRecoveryRecord = try decodeJSONFile(url)
            guard recovery.schema == BoardCreationRecoveryRecord.schema,
                  recovery.stateFilePath == stateFileURL.path,
                  recovery.initialThreadTitle == name,
                  requestedBoardID.map({ $0 == recovery.boardID }) ?? true,
                  requestedThreadID.map({ $0 == recovery.initialThreadID }) ?? true,
                  requestedEventID.map({ $0 == recovery.initialEventID }) ?? true,
                  requestedTransactionID.map({
                      $0 == recovery.initialClientTransactionID
                  }) ?? true else {
                throw CLIError.invalidCombination(
                    "the existing --recovery descriptor does not match this state, title, or supplied IDs"
                )
            }
            return recovery
        }
        if errno != ENOENT {
            throw CLIError.cannotReadInputFile(path: url.path, code: errno)
        }

        let createdAtUnixMilliseconds = Int64(
            (Date().timeIntervalSince1970 * 1_000).rounded(.down)
        )
        let recovery = BoardCreationRecoveryRecord(
            schema: BoardCreationRecoveryRecord.schema,
            stateFilePath: stateFileURL.path,
            boardID: requestedBoardID ?? UUID(),
            initialThreadID: requestedThreadID ?? UUID(),
            initialEventID: requestedEventID ?? UUID(),
            initialClientTransactionID: requestedTransactionID ?? UUID(),
            createdAtUnixMilliseconds: createdAtUnixMilliseconds,
            initialThreadTitle: name
        )
        _ = try writeSensitiveJSON(recovery, to: url)
        return recovery
    }

    private static func protectedText(
        from options: inout ArgumentBag,
        option: String,
        maximumBytes: Int
    ) throws -> String {
        let url = URL(
            fileURLWithPath: try options.require(option)
        ).standardizedFileURL
        let data = try readBoundedRegularFile(url, maximumBytes: maximumBytes)
        guard !data.isEmpty, let text = String(data: data, encoding: .utf8) else {
            throw CLIError.invalidProtectedText(path: url.path)
        }
        return text
    }

    private static func readBoundedRegularFile(
        _ url: URL,
        maximumBytes: Int
    ) throws -> Data {
        let descriptor = url.withUnsafeFileSystemRepresentation { path -> Int32 in
            guard let path else { return -1 }
            return Darwin.open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        }
        guard descriptor >= 0 else {
            throw CLIError.cannotReadInputFile(path: url.path, code: errno)
        }
        defer { Darwin.close(descriptor) }

        var status = stat()
        guard Darwin.fstat(descriptor, &status) == 0,
              (status.st_mode & S_IFMT) == S_IFREG,
              status.st_size >= 0,
              status.st_size <= maximumBytes else {
            throw CLIError.invalidInputFile(path: url.path, maximumBytes: maximumBytes)
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
            throw CLIError.cannotReadInputFile(path: url.path, code: EIO)
        }
        guard data.count <= maximumBytes else {
            throw CLIError.invalidInputFile(path: url.path, maximumBytes: maximumBytes)
        }
        return data
    }

    private static func decodeJSONFile<T: Codable>(_ url: URL) throws -> T {
        do {
            let data = try readBoundedRegularFile(
                url,
                maximumBytes: 16 * 1_024 * 1_024
            )
            guard !data.isEmpty,
                  NoctweaveCanonicalJSON.isCanonical(data) else {
                throw CLIError.invalidArtifact(path: url.path)
            }
            let value = try NoctweaveCoder.decode(T.self, from: data)
            guard try NoctweaveCanonicalJSON.encode(value) == data else {
                throw CLIError.invalidArtifact(path: url.path)
            }
            return value
        } catch {
            throw CLIError.invalidArtifact(path: url.path)
        }
    }

    /// Creates a new artifact without following a final-path symlink or replacing existing data.
    private static func writeSensitiveJSON<T: Codable>(_ value: T, to url: URL) throws -> Int {
        try writeSensitiveJSON(value, to: SensitiveOutputReservation(url: url))
    }

    private static func writeSensitiveJSON<T: Codable>(
        _ value: T,
        to reservation: SensitiveOutputReservation
    ) throws -> Int {
        let data = try NoctweaveCanonicalJSON.encode(value)
        return try reservation.write(data)
    }

    /// Creates a bounded owner-only file without following a final-path symlink or overwriting.
    private static func writeSensitiveData(_ data: Data, to url: URL) throws -> Int {
        try SensitiveOutputReservation(url: url).write(data)
    }
}

/// Reserves a mode-0600 destination before a network or group mutation. A
/// failed/cancelled operation removes the empty or partial artifact.
private final class SensitiveOutputReservation: @unchecked Sendable {
    private let url: URL
    private var descriptor: Int32
    private var completed = false

    init(url: URL) throws {
        self.url = url
        descriptor = url.withUnsafeFileSystemRepresentation { path -> Int32 in
            guard let path else { return -1 }
            return Darwin.open(
                path,
                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW,
                S_IRUSR | S_IWUSR
            )
        }
        guard descriptor >= 0 else {
            let code = errno
            if code == EEXIST { throw CLIError.outputAlreadyExists(url.path) }
            throw CLIError.cannotCreateOutput(path: url.path, code: code)
        }
    }

    deinit {
        if descriptor >= 0 { Darwin.close(descriptor) }
        if !completed {
            _ = url.withUnsafeFileSystemRepresentation { path in
                guard let path else { return Int32(-1) }
                return Darwin.unlink(path)
            }
        }
    }

    func write(_ data: Data) throws -> Int {
        guard descriptor >= 0, data.count <= 16 * 1_024 * 1_024 else {
            throw CLIError.cannotCreateOutput(path: url.path, code: EFBIG)
        }
        do {
            try FileHandle(fileDescriptor: descriptor, closeOnDealloc: false)
                .write(contentsOf: data)
            guard Darwin.fsync(descriptor) == 0 else {
                throw CLIError.cannotCreateOutput(path: url.path, code: errno)
            }
            let closingDescriptor = descriptor
            descriptor = -1
            guard Darwin.close(closingDescriptor) == 0 else {
                throw CLIError.cannotCreateOutput(path: url.path, code: errno)
            }
            completed = true
            return data.count
        } catch let error as CLIError {
            throw error
        } catch {
            throw CLIError.cannotCreateOutput(path: url.path, code: EIO)
        }
    }
}

private enum CLIError: LocalizedError {
    case unknownCommand(String)
    case unexpectedArguments(String)
    case requiresPath(String)
    case invalidArgument(String)
    case missingOption(String)
    case duplicateOption(String)
    case invalidUUID(option: String, value: String)
    case invalidValue(option: String, value: String)
    case invalidCombination(String)
    case missingEnvironmentVariable(String)
    case invalidArtifact(path: String)
    case outputAlreadyExists(String)
    case cannotCreateOutput(path: String, code: Int32)
    case cannotReadInputFile(path: String, code: Int32)
    case invalidInputFile(path: String, maximumBytes: Int)
    case invalidProtectedText(path: String)
    case auditResourceLimit(String)

    var errorDescription: String? {
        switch self {
        case .unknownCommand(let command):
            "unknown command '\(command)'; run 'noctboard help'"
        case .unexpectedArguments(let command):
            "unexpected arguments for '\(command)'; run 'noctboard help'"
        case .requiresPath(let command):
            "'\(command)' requires exactly one file path"
        case .invalidArgument(let value):
            "invalid argument '\(value)'; run 'noctboard help' for supported options"
        case .missingOption(let option):
            "missing required option \(option)"
        case .duplicateOption(let option):
            "option \(option) may be supplied only once"
        case .invalidUUID(let option, let value):
            "\(option) is not a UUID: '\(value)'"
        case .invalidValue(let option, let value):
            "invalid value for \(option): '\(value)'"
        case .invalidCombination(let description):
            "invalid option combination: \(description)"
        case .missingEnvironmentVariable(let name):
            "relay password environment variable '\(name)' is not set"
        case .invalidArtifact(let path):
            "admission artifact is invalid or unreadable: '\(path)'"
        case .outputAlreadyExists(let path):
            "refusing to overwrite existing sensitive artifact: '\(path)'"
        case .cannotCreateOutput(let path, let code):
            "cannot securely create sensitive artifact '\(path)' (errno \(code))"
        case .cannotReadInputFile(let path, let code):
            "cannot securely read bounded regular file '\(path)' (errno \(code))"
        case .invalidInputFile(let path, let maximumBytes):
            "input must be a no-follow regular file of at most \(maximumBytes) bytes: '\(path)'"
        case .invalidProtectedText(let path):
            "protected text file is empty, invalid UTF-8, non-regular, or exceeds its field limit: '\(path)'"
        case .auditResourceLimit(let path):
            "audit exceeds the 6,002-record or 64-KiB-per-record inspection limit: '\(path)'"
        }
    }
}

private struct ArgumentBag {
    private var values: [String: String] = [:]
    private var flags: Set<String> = []

    init(_ arguments: [String], booleanOptions: Set<String>) throws {
        var index = 0
        while index < arguments.count {
            let option = arguments[index]
            guard option.hasPrefix("--") else { throw CLIError.invalidArgument(option) }
            guard values[option] == nil, !flags.contains(option) else {
                throw CLIError.duplicateOption(option)
            }
            if booleanOptions.contains(option) {
                flags.insert(option)
                index += 1
            } else {
                guard index + 1 < arguments.count else { throw CLIError.missingOption(option) }
                values[option] = arguments[index + 1]
                index += 2
            }
        }
    }

    mutating func take(_ option: String) -> String? { values.removeValue(forKey: option) }
    mutating func takeFlag(_ option: String) -> Bool { flags.remove(option) != nil }
    func contains(_ option: String) -> Bool { values[option] != nil || flags.contains(option) }

    mutating func require(_ option: String) throws -> String {
        guard let value = take(option) else { throw CLIError.missingOption(option) }
        return value
    }

    mutating func uuid(_ option: String) throws -> UUID {
        let value = try require(option)
        guard let parsed = UUID(uuidString: value) else {
            throw CLIError.invalidUUID(option: option, value: value)
        }
        return parsed
    }

    mutating func uuid(_ option: String, default defaultValue: @autoclosure () -> UUID) throws -> UUID {
        guard let value = take(option) else { return defaultValue() }
        guard let parsed = UUID(uuidString: value) else {
            throw CLIError.invalidUUID(option: option, value: value)
        }
        return parsed
    }

    mutating func optionalUUID(_ option: String) throws -> UUID? {
        guard let value = take(option) else { return nil }
        guard let parsed = UUID(uuidString: value) else {
            throw CLIError.invalidUUID(option: option, value: value)
        }
        return parsed
    }

    mutating func memberHandle(_ option: String) throws -> GroupScopedMemberHandleV2 {
        guard let handle = try optionalMemberHandle(option) else {
            throw CLIError.missingOption(option)
        }
        return handle
    }

    mutating func optionalMemberHandle(_ option: String) throws -> GroupScopedMemberHandleV2? {
        guard let value = take(option) else { return nil }
        let handle = GroupScopedMemberHandleV2(rawValue: value)
        guard handle.isStructurallyValid else {
            throw CLIError.invalidValue(option: option, value: value)
        }
        return handle
    }

    mutating func taskState(_ option: String) throws -> NoctBoardTaskState {
        let value = try require(option)
        guard let state = NoctBoardTaskState(rawValue: value) else {
            throw CLIError.invalidValue(option: option, value: value)
        }
        return state
    }

    mutating func role(_ option: String) throws -> NoctBoardRole {
        let value = try require(option)
        guard let role = NoctBoardRole(rawValue: value) else {
            throw CLIError.invalidValue(option: option, value: value)
        }
        return role
    }

    mutating func digest(_ option: String) throws -> Data {
        let value = try require(option)
        guard value.utf8.count == 64 else {
            throw CLIError.invalidValue(option: option, value: value)
        }
        var bytes: [UInt8] = []
        bytes.reserveCapacity(32)
        var index = value.startIndex
        while index < value.endIndex {
            let next = value.index(index, offsetBy: 2)
            guard let byte = UInt8(value[index ..< next], radix: 16) else {
                throw CLIError.invalidValue(option: option, value: value)
            }
            bytes.append(byte)
            index = next
        }
        return Data(bytes)
    }

    mutating func iso8601Date(_ option: String) throws -> Date {
        let value = try require(option)
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = formatter.date(from: value) { return date }
        formatter.formatOptions = [.withInternetDateTime]
        guard let date = formatter.date(from: value) else {
            throw CLIError.invalidValue(option: option, value: value)
        }
        return date
    }

    func requireEmpty() throws {
        if let unknown = (Array(values.keys) + Array(flags)).sorted().first {
            throw CLIError.invalidArgument(unknown)
        }
    }
}

private struct DemoOutput: Encodable {
    struct Security: Encodable {
        let boardIsolation: String
        let authorization: String
        let auditExport: String
        let plaintextIncludedInAuditExport: Bool
    }

    let schema: String
    let security: Security
    let projection: NoctBoardProjection
    let ledger: NoctBoardLedger
    let projectionDigest: String
}

private struct ProjectionVerificationOutput: Encodable {
    let schema: String
    let scope: String
    let verified: Bool
    let projectionDigest: String
}

private struct ExportOutput: Encodable {
    let schema: String
    let path: String
    let bytes: Int
    let redacted: Bool
}

private struct PublishOutput: Encodable {
    let eventID: UUID
    let clientTransactionID: UUID
    let operationType: String
    let logicalClock: UInt64
    let authorSequence: UInt64
    let operationID: UUID?
    let complete: Bool
    let disposition: String
    let projectionDigest: String

    init(_ result: NoctBoardPublishResult) {
        eventID = result.event.id
        clientTransactionID = result.event.clientTransactionID
        operationType = result.event.operation.type
        logicalClock = result.event.logicalClock
        authorSequence = result.event.authorSequence
        operationID = result.operationID
        complete = result.complete
        disposition = String(describing: result.disposition)
        projectionDigest = result.projectionDigest
    }
}

private struct CreationOutput: Encodable {
    let board: NoctBoardReference
    let ownerMemberHandle: String
    let ownerCredentialHandle: String
    let initialThreadID: UUID
    let initialPublication: PublishOutput
    let recoveryPath: String

    init(_ result: NoctBoardCreationResult, recoveryPath: String) {
        board = result.board
        ownerMemberHandle = result.ownerMemberHandle.rawValue
        ownerCredentialHandle = result.ownerCredentialHandle.rawValue
        initialThreadID = result.initialThreadID
        initialPublication = PublishOutput(result.initialPublication)
        self.recoveryPath = recoveryPath
    }
}

private struct AnyCodingKey: CodingKey {
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

private struct BoardCreationRecoveryRecord: Codable {
    static let schema = "org.noctboard/create-recovery:1.0"

    let schema: String
    let stateFilePath: String
    let boardID: UUID
    let initialThreadID: UUID
    let initialEventID: UUID
    let initialClientTransactionID: UUID
    let createdAtUnixMilliseconds: Int64
    let initialThreadTitle: String

    var createdAt: Date {
        Date(timeIntervalSince1970: Double(createdAtUnixMilliseconds) / 1_000)
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case schema
        case stateFilePath
        case boardID
        case initialThreadID
        case initialEventID
        case initialClientTransactionID
        case createdAtUnixMilliseconds
        case initialThreadTitle
    }

    init(
        schema: String,
        stateFilePath: String,
        boardID: UUID,
        initialThreadID: UUID,
        initialEventID: UUID,
        initialClientTransactionID: UUID,
        createdAtUnixMilliseconds: Int64,
        initialThreadTitle: String
    ) {
        self.schema = schema
        self.stateFilePath = stateFilePath
        self.boardID = boardID
        self.initialThreadID = initialThreadID
        self.initialEventID = initialEventID
        self.initialClientTransactionID = initialClientTransactionID
        self.createdAtUnixMilliseconds = createdAtUnixMilliseconds
        self.initialThreadTitle = initialThreadTitle
    }

    init(from decoder: Decoder) throws {
        let keys = try decoder.container(keyedBy: AnyCodingKey.self).allKeys
        guard Set(keys.map(\.stringValue)) == Set(CodingKeys.allCases.map(\.rawValue)) else {
            throw DecodingError.dataCorrupted(
                .init(
                    codingPath: decoder.codingPath,
                    debugDescription: "board creation recovery fields must match v1 exactly"
                )
            )
        }
        let values = try decoder.container(keyedBy: CodingKeys.self)
        schema = try values.decode(String.self, forKey: .schema)
        stateFilePath = try values.decode(String.self, forKey: .stateFilePath)
        boardID = try values.decode(UUID.self, forKey: .boardID)
        initialThreadID = try values.decode(UUID.self, forKey: .initialThreadID)
        initialEventID = try values.decode(UUID.self, forKey: .initialEventID)
        initialClientTransactionID = try values.decode(
            UUID.self,
            forKey: .initialClientTransactionID
        )
        createdAtUnixMilliseconds = try values.decode(
            Int64.self,
            forKey: .createdAtUnixMilliseconds
        )
        initialThreadTitle = try values.decode(String.self, forKey: .initialThreadTitle)
        guard schema == Self.schema,
              createdAtUnixMilliseconds >= 0,
              !stateFilePath.isEmpty,
              !initialThreadTitle.isEmpty,
              initialThreadTitle.utf8.count <= NoctBoardLimits.maximumThreadTitleBytes else {
            throw DecodingError.dataCorrupted(
                .init(
                    codingPath: decoder.codingPath,
                    debugDescription: "board creation recovery values are invalid"
                )
            )
        }
    }
}

private struct SnapshotOutput: Encodable {
    let board: NoctBoardReference
    let groupEpoch: UInt64
    let localMemberHandle: String
    let localCredentialHandle: String
    let eventCount: Int
    let historyBootstrapProvenance: [NoctBoardHistoryBootstrapProvenance]
    let containerRejections: [NoctBoardContainerRejection]
    let projection: NoctBoardProjection
    let ledger: NoctBoardLedger
    let projectionDigest: String

    init(_ snapshot: NoctBoardClientSnapshot) {
        board = snapshot.board
        groupEpoch = snapshot.groupEpoch
        localMemberHandle = snapshot.localMemberHandle.rawValue
        localCredentialHandle = snapshot.localCredentialHandle.rawValue
        eventCount = snapshot.events.count
        historyBootstrapProvenance = snapshot.historyBootstrapProvenance
        containerRejections = snapshot.containerRejections
        projection = snapshot.projection
        ledger = snapshot.ledger
        projectionDigest = snapshot.projectionDigest
    }
}

private struct SynchronizationOutput: Encodable {
    let receivedGroupEventCount: Int
    let receivedBoardEventIDs: [UUID]
    let snapshot: SnapshotOutput

    init(_ result: NoctBoardSynchronizationResult) {
        receivedGroupEventCount = result.receivedGroupEventCount
        receivedBoardEventIDs = result.receivedBoardEventIDs
        snapshot = SnapshotOutput(result.snapshot)
    }
}

private struct SensitiveArtifactOutput: Encodable {
    let kind: String
    let path: String
    let bytes: Int
    let board: NoctBoardReference
    let admissionID: UUID
    let fileMode: String
    let secureChannelRequired: Bool
}

private struct AdmissionCompletionOutput: Encodable {
    let completed: Bool
    let board: NoctBoardReference
    let admissionID: UUID
    let localStatePath: String
}

private struct AuditInspectionOutput: Encodable {
    let schema: String?
    let path: String
    let scope: String
    let cryptographicReplayVerified: Bool
    let structurallyValid: Bool
    let boardID: String?
    let groupID: String?
    let acceptedCount: Int
    let replayedCount: Int
    let rejectedCount: Int
    let containerRejectedCount: Int
    let historyAttestationCount: Int
    let projectionDigest: String?
    let errors: [String]
}

private struct AuditHeaderRecord: Decodable {
    let recordType: String
    let schema: String
    let boardID: UUID
    let groupID: UUID
}

private struct AuditEventRecord: Decodable {
    let recordType: String
    let entry: NoctBoardLedgerEntry
}

private struct AuditContainerRejectionRecord: Decodable {
    let recordType: String
    let entry: NoctBoardAuditContainerRejection
}

private struct AuditHistoryAttestationRecord: Decodable {
    let recordType: String
    let entry: NoctBoardAuditHistoryAttestation
}

private struct AuditSummaryRecord: Decodable {
    let recordType: String
    let acceptedCount: Int
    let replayedCount: Int
    let rejectedCount: Int
    let containerRejectedCount: Int
    let historyAttestationCount: Int
    let projectionDigest: String
}

private enum AuditInspector {
    static let maximumBytes = 16 * 1_024 * 1_024
    private static let maximumRecords = (NoctBoardLimits.maximumBoardEvents * 2) + 2
    private static let maximumLineBytes = 64 * 1_024

    static func inspect(_ data: Data, path: String) throws -> AuditInspectionOutput {
        guard data.count <= maximumBytes else {
            throw CLIError.invalidInputFile(path: path, maximumBytes: maximumBytes)
        }
        let lines = data.split(separator: 0x0A, omittingEmptySubsequences: true)
        guard lines.count <= maximumRecords,
              lines.allSatisfy({ $0.count <= maximumLineBytes }) else {
            throw CLIError.auditResourceLimit(path)
        }
        var errors: [String] = []
        var records: [[String: Any]] = []

        if lines.count < 2 {
            errors.append("audit must contain a header and summary")
        }

        for (offset, line) in lines.enumerated() {
            do {
                let lineData = Data(line)
                if !NoctweaveCanonicalJSON.isCanonical(lineData) {
                    errors.append("line \(offset + 1) is not canonical JSON")
                }
                let value = try JSONSerialization.jsonObject(with: lineData)
                guard let object = value as? [String: Any] else {
                    errors.append("line \(offset + 1) is not a JSON object")
                    continue
                }
                records.append(object)
            } catch {
                errors.append("line \(offset + 1) is not valid JSON")
            }
        }
        for (offset, record) in records.enumerated() {
            if containsPlaintextProjectionKey(record) {
                errors.append("line \(offset + 1) unexpectedly contains projection plaintext")
            }
            if !hasExactShape(record, recordType: string(record["recordType"]) ?? "") {
                errors.append("line \(offset + 1) has fields outside its v1 shape")
            }
        }

        let header = records.first
        if string(header?["recordType"]) != "header" {
            errors.append("first record is not a header")
        }
        if !decodes(AuditHeaderRecord.self, object: header) {
            errors.append("header is missing required typed fields")
        }
        let schema = string(header?["schema"])
        if schema != NoctBoardAuditExporter.schema {
            errors.append("unsupported or missing audit schema")
        }
        let boardID = string(header?["boardID"])
        let groupID = string(header?["groupID"])
        if boardID.flatMap(UUID.init(uuidString:)) == nil { errors.append("invalid boardID") }
        if groupID.flatMap(UUID.init(uuidString:)) == nil { errors.append("invalid groupID") }
        if boardID != groupID { errors.append("v1 requires boardID and groupID to match") }

        let summary = records.last
        if string(summary?["recordType"]) != "summary" {
            errors.append("last record is not a summary")
        }
        if !decodes(AuditSummaryRecord.self, object: summary) {
            errors.append("summary is missing required typed fields")
        }

        var accepted = 0
        var replayed = 0
        var rejected = 0
        var containerRejected = 0
        var historyAttestationCount = 0
        var eventIndex = 0
        var sawContainerRejection = false
        var sawHistoryAttestation = false
        var containerGroupEventIDs: Set<UUID> = []
        var historyGroupEventIDs: Set<UUID> = []
        var ledgerEventIDs: Set<UUID> = []
        if records.count > 2 {
            for (offset, record) in records.dropFirst().dropLast().enumerated() {
                let lineNumber = offset + 2
                guard let entry = record["entry"] as? [String: Any] else {
                    errors.append("line \(lineNumber) has no entry object")
                    continue
                }
                switch string(record["recordType"]) {
                case "event":
                    guard decodes(AuditEventRecord.self, object: record) else {
                        errors.append("line \(lineNumber) is missing required ledger fields")
                        continue
                    }
                    if sawContainerRejection || sawHistoryAttestation {
                        errors.append("line \(lineNumber) places an event after evidence records")
                    }
                    if integer(entry["order"]) != eventIndex {
                        errors.append("line \(lineNumber) has a non-contiguous ledger order")
                    }
                    eventIndex += 1
                    if let eventID = string(entry["eventID"]).flatMap(UUID.init(uuidString:)) {
                        ledgerEventIDs.insert(eventID)
                    } else {
                        errors.append("line \(lineNumber) has an invalid eventID")
                    }
                    if string(entry["clientTransactionID"]).flatMap(UUID.init(uuidString:)) == nil {
                        errors.append("line \(lineNumber) has an invalid clientTransactionID")
                    }
                    if !isLowercaseDigest(string(entry["eventDigest"])) {
                        errors.append("line \(lineNumber) has an invalid event digest")
                    }
                    if !allowedOperationTypes.contains(string(entry["operationType"]) ?? "") {
                        errors.append("line \(lineNumber) has an invalid operation type")
                    }
                    switch string(entry["outcome"]) {
                    case "accepted":
                        accepted += 1
                        if string(entry["rejectionReason"]) != nil
                            || boolean(entry["authorChainConsumed"]) != true {
                            errors.append("line \(lineNumber) has inconsistent accepted metadata")
                        }
                    case "replayed":
                        replayed += 1
                        if string(entry["rejectionReason"]) != nil
                            || boolean(entry["authorChainConsumed"]) != false {
                            errors.append("line \(lineNumber) has inconsistent replay metadata")
                        }
                    case "rejected":
                        rejected += 1
                        if string(entry["rejectionReason"]) == nil {
                            errors.append("line \(lineNumber) omits its rejection reason")
                        }
                    default: errors.append("line \(lineNumber) has an invalid ledger outcome")
                    }

                case "containerRejection":
                    guard decodes(AuditContainerRejectionRecord.self, object: record) else {
                        errors.append("line \(lineNumber) is missing required container fields")
                        continue
                    }
                    if sawHistoryAttestation {
                        errors.append("line \(lineNumber) places a container rejection after history attestations")
                    }
                    sawContainerRejection = true
                    containerRejected += 1
                    if let groupEventID = string(entry["groupEventID"])
                        .flatMap(UUID.init(uuidString:)) {
                        if !containerGroupEventIDs.insert(groupEventID).inserted {
                            errors.append("line \(lineNumber) repeats a container groupEventID")
                        }
                    } else {
                        errors.append("line \(lineNumber) has an invalid groupEventID")
                    }
                    let reasons = Set([
                        "unexpectedContent", "malformedPayload", "envelopeBindingMismatch",
                        "unauthorizedHistoryBootstrap", "invalidAuthorSignature",
                    ])
                    if !reasons.contains(string(entry["reason"]) ?? "") {
                        errors.append("line \(lineNumber) has an invalid container rejection reason")
                    }

                case "historyAttestation":
                    guard decodes(AuditHistoryAttestationRecord.self, object: record) else {
                        errors.append("line \(lineNumber) is missing required history-attestation fields")
                        continue
                    }
                    sawHistoryAttestation = true
                    historyAttestationCount += 1
                    if let groupEventID = string(entry["groupEventID"])
                        .flatMap(UUID.init(uuidString:)) {
                        if !historyGroupEventIDs.insert(groupEventID).inserted {
                            errors.append("line \(lineNumber) repeats a history wrapper groupEventID")
                        }
                    } else {
                        errors.append("line \(lineNumber) has an invalid history groupEventID")
                    }
                    guard let reassertedEventID = string(entry["reassertedEventID"])
                        .flatMap(UUID.init(uuidString:)) else {
                        errors.append("line \(lineNumber) has an invalid reassertedEventID")
                        continue
                    }
                    if !ledgerEventIDs.contains(reassertedEventID) {
                        errors.append("line \(lineNumber) attests an event absent from the ledger")
                    }

                default:
                    errors.append("line \(lineNumber) has an unknown record type")
                }
            }
        }

        let expectedAccepted = integer(summary?["acceptedCount"])
        let expectedReplayed = integer(summary?["replayedCount"])
        let expectedRejected = integer(summary?["rejectedCount"])
        let expectedContainerRejected = integer(summary?["containerRejectedCount"])
        let expectedHistoryAttestations = integer(summary?["historyAttestationCount"])
        if expectedAccepted != accepted { errors.append("accepted count does not match event records") }
        if expectedReplayed != replayed { errors.append("replayed count does not match event records") }
        if expectedRejected != rejected { errors.append("rejected count does not match event records") }
        if expectedContainerRejected != containerRejected {
            errors.append("container-rejected count does not match records")
        }
        if expectedHistoryAttestations != historyAttestationCount {
            errors.append("history-attestation count does not match records")
        }
        let projectionDigest = string(summary?["projectionDigest"])
        if !isLowercaseDigest(projectionDigest) { errors.append("invalid projection digest") }

        return AuditInspectionOutput(
            schema: schema,
            path: path,
            scope: "structure-and-summary-count-consistency",
            cryptographicReplayVerified: false,
            structurallyValid: errors.isEmpty,
            boardID: boardID,
            groupID: groupID,
            acceptedCount: accepted,
            replayedCount: replayed,
            rejectedCount: rejected,
            containerRejectedCount: containerRejected,
            historyAttestationCount: historyAttestationCount,
            projectionDigest: projectionDigest,
            errors: errors
        )
    }

    private static func string(_ value: Any?) -> String? { value as? String }

    private static func decodes<T: Decodable>(
        _ type: T.Type,
        object: [String: Any]?
    ) -> Bool {
        guard let object,
              JSONSerialization.isValidJSONObject(object),
              let data = try? JSONSerialization.data(withJSONObject: object),
              (try? JSONDecoder().decode(type, from: data)) != nil else {
            return false
        }
        return true
    }

    private static func integer(_ value: Any?) -> Int? {
        guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID() else {
            return nil
        }
        return number.intValue
    }

    private static func boolean(_ value: Any?) -> Bool? {
        guard let number = value as? NSNumber,
              CFGetTypeID(number) == CFBooleanGetTypeID() else { return nil }
        return number.boolValue
    }

    private static func isLowercaseDigest(_ value: String?) -> Bool {
        guard let value, value.utf8.count == 64 else { return false }
        return value.utf8.allSatisfy {
            (0x30 ... 0x39).contains($0) || (0x61 ... 0x66).contains($0)
        }
    }

    private static let allowedOperationTypes = Set([
        "thread.create", "thread.close", "task.create", "task.assign",
        "task.transition", "message.post", "member.set-role",
    ])

    private static func containsPlaintextProjectionKey(_ object: [String: Any]) -> Bool {
        let forbidden = Set(["body", "title", "details", "payload", "messages", "tasks", "threads"])
        for (key, value) in object {
            if forbidden.contains(key) { return true }
            if let nested = value as? [String: Any], containsPlaintextProjectionKey(nested) { return true }
            if let nested = value as? [[String: Any]], nested.contains(where: containsPlaintextProjectionKey) {
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
}

private enum DeterministicDemo {
    static let containerRejections = [
        NoctBoardAuditContainerRejection(
            groupEventID: UUID(uuidString: "00000000-0000-4000-8000-000000000601")!,
            reason: "malformedPayload"
        ),
    ]

    static func make() throws -> NoctBoardProjectionResult {
        let boardID = uuid("00000000-0000-4000-8000-000000000001")
        let groupID = boardID
        let otherGroupID = uuid("00000000-0000-4000-8000-000000000003")
        let threadID = uuid("00000000-0000-4000-8000-000000000101")
        let taskID = uuid("00000000-0000-4000-8000-000000000201")
        let pendingTaskID = uuid("00000000-0000-4000-8000-000000000202")
        let coordinator = member(0x11, credentialByte: 0x21, role: .coordinator)
        let worker = member(0x12, credentialByte: 0x22, role: .worker)
        let auditor = member(0x13, credentialByte: 0x23, role: .auditor)
        let outsider = member(0x14, credentialByte: 0x24, role: .worker)
        let configuration = NoctBoardConfiguration(
            boardID: boardID,
            groupID: groupID,
            members: [coordinator, worker, auditor]
        )

        let first = event(
            number: 1, boardID: boardID, groupID: groupID, author: coordinator,
            clock: 0, sequence: 0, previous: nil, operation: .createThread(
                NoctBoardCreateThread(threadID: threadID, title: "Release readiness")
            )
        )
        let firstDigest = try NoctBoardCodec.digest(first)
        let second = event(
            number: 2, boardID: boardID, groupID: groupID, author: coordinator,
            clock: 1, sequence: 1, previous: firstDigest, operation: .createTask(
                NoctBoardCreateTask(
                    taskID: taskID,
                    threadID: threadID,
                    title: "Audit the release candidate",
                    details: "Check deterministic projection and rejection evidence.",
                    assigneeMemberHandle: worker.memberHandle
                )
            )
        )
        let secondDigest = try NoctBoardCodec.digest(second)
        let workerFirst = event(
            number: 3, boardID: boardID, groupID: groupID, author: worker,
            clock: 2, sequence: 0, previous: nil, operation: .transitionTask(
                NoctBoardTransitionTask(taskID: taskID, from: .pending, to: .active)
            )
        )
        let workerFirstDigest = try NoctBoardCodec.digest(workerFirst)
        let workerSecond = event(
            number: 4, boardID: boardID, groupID: groupID, author: worker,
            clock: 3, sequence: 1, previous: workerFirstDigest, operation: .postMessage(
                NoctBoardPostMessage(
                    messageID: uuid("00000000-0000-4000-8000-000000000301"),
                    threadID: threadID,
                    taskID: taskID,
                    body: "Projection reproduced. Reviewing the rejected boundary attempts now."
                )
            )
        )
        let workerSecondDigest = try NoctBoardCodec.digest(workerSecond)
        let auditorWriteAttempt = event(
            number: 5, boardID: boardID, groupID: groupID, author: auditor,
            clock: 4, sequence: 0, previous: nil, operation: .postMessage(
                NoctBoardPostMessage(
                    messageID: uuid("00000000-0000-4000-8000-000000000302"),
                    threadID: threadID,
                    body: "This must remain rejected because auditors are read-only."
                )
            )
        )
        let crossGroupAttempt = event(
            number: 6, boardID: boardID, groupID: otherGroupID, author: outsider,
            clock: 5, sequence: 0, previous: nil, operation: .postMessage(
                NoctBoardPostMessage(
                    messageID: uuid("00000000-0000-4000-8000-000000000303"),
                    threadID: threadID,
                    body: "A different swarm must not enter this board."
                )
            )
        )
        let coordinatorThird = event(
            number: 7, boardID: boardID, groupID: groupID, author: coordinator,
            clock: 5, sequence: 2, previous: secondDigest, operation: .createTask(
                NoctBoardCreateTask(
                    taskID: pendingTaskID,
                    threadID: threadID,
                    title: "Publish the redacted audit",
                    details: "Export ledger metadata without message or task plaintext."
                )
            )
        )
        let coordinatorThirdDigest = try NoctBoardCodec.digest(coordinatorThird)
        let coordinatorFourth = event(
            number: 8, boardID: boardID, groupID: groupID, author: coordinator,
            clock: 6, sequence: 3, previous: coordinatorThirdDigest, operation: .postMessage(
                NoctBoardPostMessage(
                    messageID: uuid("00000000-0000-4000-8000-000000000304"),
                    threadID: threadID,
                    body: "Human audit gate is open; no global agent identity is required."
                )
            )
        )
        let workerThird = event(
            number: 9, boardID: boardID, groupID: groupID, author: worker,
            clock: 7, sequence: 2, previous: workerSecondDigest, operation: .transitionTask(
                NoctBoardTransitionTask(taskID: taskID, from: .active, to: .completed)
            )
        )

        return try NoctBoardProjector.project(
            events: [
                workerThird, crossGroupAttempt, first, coordinatorFourth, workerFirst,
                auditorWriteAttempt, second, workerSecond, coordinatorThird,
            ],
            configuration: configuration
        )
    }

    private static func member(
        _ memberByte: UInt8,
        credentialByte: UInt8,
        role: NoctBoardRole
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
        number: Int,
        boardID: UUID,
        groupID: UUID,
        author: NoctBoardMemberAuthorization,
        clock: UInt64,
        sequence: UInt64,
        previous: Data?,
        operation: NoctBoardOperation
    ) -> NoctBoardEvent {
        NoctBoardEvent(
            id: uuid(String(format: "00000000-0000-4000-8000-%012d", 400 + number)),
            clientTransactionID: uuid(String(format: "00000000-0000-4000-8000-%012d", 500 + number)),
            boardID: boardID,
            groupID: groupID,
            authorMemberHandle: author.memberHandle,
            authorCredentialHandle: author.credentialHandle,
            logicalClock: clock,
            authorSequence: sequence,
            previousAuthorEventDigest: previous,
            createdAtUnixMilliseconds: 1_800_000_000_000 + Int64(number * 1_000),
            operation: operation
        )
    }

    private static func uuid(_ value: String) -> UUID { UUID(uuidString: value)! }
}
