// SPDX-FileCopyrightText: 2026 Luiz Widmer
// SPDX-License-Identifier: AGPL-3.0-or-later

import Foundation
import XCTest
@testable import NoctBoardTransport
import NoctBoardCore
@preconcurrency import NoctweaveCore

final class NoctBoardTransportIntegrationTests: XCTestCase {
    func testRelayPasswordsRequireTLS() throws {
        for transport in RelayEndpointTransport.allCases {
            XCTAssertThrowsError(try NoctBoardClient.validateRelayAuthentication(
                endpoint: RelayEndpoint(
                    host: "relay.example",
                    port: 443,
                    useTLS: false,
                    transport: transport
                ),
                accessPassword: "secret"
            )) {
                XCTAssertEqual(
                    $0 as? NoctBoardTransportError,
                    .insecureRelayAuthentication
                )
            }
            XCTAssertNoThrow(try NoctBoardClient.validateRelayAuthentication(
                endpoint: RelayEndpoint(
                    host: "relay.example",
                    port: 443,
                    useTLS: true,
                    transport: transport
                ),
                accessPassword: "secret"
            ))
        }
        XCTAssertNoThrow(try NoctBoardClient.validateRelayAuthentication(
            endpoint: RelayEndpoint(host: "127.0.0.1", port: 9340),
            accessPassword: nil
        ))
        XCTAssertNoThrow(try NoctBoardClient.validateRelayAuthentication(
            endpoint: RelayEndpoint(host: "127.0.0.1", port: 9340),
            accessPassword: ""
        ))
    }

    func testAdmissionHistoryManifestRequiresEveryExactSignedRecord() throws {
        let expected = NoctBoardAdmissionHistoryManifestEntry(
            historyGroupEventID: UUID(),
            eventID: UUID(),
            signedEventRecordDigest: Data(repeating: 0xA5, count: 32)
        )
        XCTAssertNoThrow(try NoctBoardClient.verifyAdmissionHistoryManifest(
            expected: [expected],
            received: [expected]
        ))
        XCTAssertThrowsError(try NoctBoardClient.verifyAdmissionHistoryManifest(
            expected: [expected],
            received: []
        )) {
            XCTAssertEqual($0 as? NoctBoardTransportError, .admissionHistoryIncomplete)
        }
        let altered = NoctBoardAdmissionHistoryManifestEntry(
            historyGroupEventID: expected.historyGroupEventID,
            eventID: expected.eventID,
            signedEventRecordDigest: Data(repeating: 0x5A, count: 32)
        )
        XCTAssertThrowsError(try NoctBoardClient.verifyAdmissionHistoryManifest(
            expected: [expected],
            received: [altered]
        )) {
            XCTAssertEqual($0 as? NoctBoardTransportError, .admissionHistoryIncomplete)
        }
    }

    func testAdmissionHandoffExpiryIncludesEveryExistingRoute() {
        let base = Date(timeIntervalSince1970: 2_000_000_000)
        XCTAssertEqual(
            NoctBoardClient.admissionHandoffExpiry(
                admissionExpiresAt: base.addingTimeInterval(3_600),
                initialRouteExpiresAt: base.addingTimeInterval(3_000),
                existingRouteExpiresAt: [
                    base.addingTimeInterval(2_400),
                    base.addingTimeInterval(1_800)
                ]
            ),
            base.addingTimeInterval(1_800)
        )
    }

    func testAdmissionExpiryBoundariesFailBeforeIrreversibleMutation() {
        let expiry = Date(timeIntervalSince1970: 2_000_000_000)
        XCTAssertTrue(NoctBoardClient.admissionArtifactIsUsableForFreshInstall(
            observedAt: expiry.addingTimeInterval(-0.001),
            expiresAt: expiry
        ))
        XCTAssertFalse(NoctBoardClient.admissionArtifactIsUsableForFreshInstall(
            observedAt: expiry,
            expiresAt: expiry
        ))
        XCTAssertTrue(NoctBoardClient.preparedAdmissionHasMinimumValidity(
            observedAt: expiry.addingTimeInterval(
                -NoctBoardClient.minimumAdmissionHandoffValidity
            ),
            expiresAt: expiry
        ))
        XCTAssertFalse(NoctBoardClient.preparedAdmissionHasMinimumValidity(
            observedAt: expiry.addingTimeInterval(
                -NoctBoardClient.minimumAdmissionHandoffValidity + 0.001
            ),
            expiresAt: expiry
        ))
    }

    func testAdmissionStoreReservesMaximumCanonicalPackageBeforeMutation() throws {
        let maximumPackage = Data(
            repeating: 0xA5,
            count: NoctBoardAdmissionCodec.maximumArtifactBytes
        )
        let encodedField = try NoctweaveCoder.encode(
            MaximumPackageField(packageBytes: maximumPackage),
            sortedKeys: true
        )
        XCTAssertLessThanOrEqual(
            encodedField.count,
            NoctBoardAdmissionStateStore.maximumPackageReservationBytes
        )
        let exactBoundary = NoctBoardAdmissionStateStore.maximumPlaintextBytes
            - NoctBoardAdmissionStateStore.maximumPackageReservationBytes
        XCTAssertTrue(NoctBoardAdmissionStateStore.reservedCapacityFits(
            encodedDocumentBytes: exactBoundary,
            outstandingPackageCount: 1
        ))
        XCTAssertFalse(NoctBoardAdmissionStateStore.reservedCapacityFits(
            encodedDocumentBytes: exactBoundary + 1,
            outstandingPackageCount: 1
        ))
    }

    func testOwnerOperationLeaseIsCrossStoreAndNonblocking() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(
            "noctboard-owner-lease-\(UUID().uuidString)",
            isDirectory: true
        )
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let stateFile = root.appendingPathComponent("client.json")
        let firstStore = NoctBoardAdmissionStateStore(
            stateFileURL: stateFile,
            protection: .insecurePlaintextForTesting,
            storageScopeIdentifier: "lease-test"
        )
        let secondStore = NoctBoardAdmissionStateStore(
            stateFileURL: stateFile,
            protection: .insecurePlaintextForTesting,
            storageScopeIdentifier: "lease-test"
        )
        let firstLease = try await firstStore.acquireOwnerOperationLease()
        do {
            _ = try await secondStore.acquireOwnerOperationLease()
            XCTFail("a concurrent owner mutation must fail instead of blocking its store actor")
        } catch {
            XCTAssertEqual(
                error as? NoctBoardAdmissionStateStoreError,
                .storageUnavailable
            )
        }
        firstLease.release()
        let recoveredLease = try await secondStore.acquireOwnerOperationLease()
        recoveredLease.release()
    }

    func testJoinReceiptCannotBeReplacedOrRegressed() async throws {
        let board = try NoctBoardReference(id: UUID())
        let manifest = NoctBoardAdmissionHistoryManifestEntry(
            historyGroupEventID: UUID(),
            eventID: UUID(),
            signedEventRecordDigest: Data(repeating: 0x44, count: 32)
        )
        let receipt = NoctBoardJoinAdmissionReceipt(
            board: board,
            admissionID: UUID(),
            originJoinAnchorID: UUID(),
            destinationMemberHandle: .generate(),
            destinationCredentialHandle: .generate(),
            destinationAdmissionDigest: Data(repeating: 0x55, count: 32),
            requestDigest: Data(repeating: 0x66, count: 32),
            packageDigest: Data(repeating: 0x77, count: 32),
            historyManifest: [manifest],
            expiresAt: Date(timeIntervalSince1970: 2_000_003_600),
            status: .pending
        )
        let store = NoctBoardAdmissionStateStore()
        try await store.beginJoinReceipt(receipt)
        try await store.beginJoinReceipt(receipt)
        try await store.markJoinReceiptVerified(
            board: board,
            admissionID: receipt.admissionID,
            requestDigest: receipt.requestDigest,
            packageDigest: receipt.packageDigest
        )
        try await store.beginJoinReceipt(receipt)
        let verifiedReceipt = try await store.joinReceipt(board: board)
        XCTAssertEqual(verifiedReceipt?.status, .verified)

        let conflicting = NoctBoardJoinAdmissionReceipt(
            board: board,
            admissionID: UUID(),
            originJoinAnchorID: UUID(),
            destinationMemberHandle: .generate(),
            destinationCredentialHandle: .generate(),
            destinationAdmissionDigest: Data(repeating: 0x88, count: 32),
            requestDigest: Data(repeating: 0x99, count: 32),
            packageDigest: Data(repeating: 0xAA, count: 32),
            historyManifest: [manifest],
            expiresAt: receipt.expiresAt,
            status: .pending
        )
        do {
            try await store.beginJoinReceipt(conflicting)
            XCTFail("one board cannot accept a different durable admission receipt")
        } catch {
            XCTAssertEqual(
                error as? NoctBoardAdmissionStateStoreError,
                .conflictingAdmission
            )
        }
    }

    func testAdmissionCodecRejectsUnknownAndDuplicateTopLevelKeys() throws {
        let unknownRequest = Data(
            #"{"admission":null,"admissionID":null,"board":null,"extra":true,"initialRouteSet":null,"invitationBindingDigest":null}"#.utf8
        )
        XCTAssertThrowsError(
            try JSONDecoder().decode(NoctBoardAdmissionRequest.self, from: unknownRequest)
        )
        let duplicateRequest = Data(
            #"{"admission":null,"admission":null,"admissionID":null,"board":null,"initialRouteSet":null,"invitationBindingDigest":null}"#.utf8
        )
        XCTAssertThrowsError(try NoctBoardAdmissionCodec.decodeRequest(duplicateRequest)) {
            XCTAssertEqual($0 as? NoctBoardAdmissionCodecError, .invalidArtifact)
        }

        let unknownPackage = Data(
            #"{"admissionID":null,"anchor":null,"board":null,"existingMemberRouteAnnouncements":[],"expiresAt":null,"extra":true,"historyManifest":[],"transition":null,"welcome":null}"#.utf8
        )
        XCTAssertThrowsError(
            try JSONDecoder().decode(NoctBoardAdmissionPackage.self, from: unknownPackage)
        )
        let duplicatePackage = Data(
            #"{"admissionID":null,"anchor":null,"board":null,"board":null,"existingMemberRouteAnnouncements":[],"expiresAt":null,"historyManifest":[],"transition":null,"welcome":null}"#.utf8
        )
        XCTAssertThrowsError(try NoctBoardAdmissionCodec.decodePackage(duplicatePackage)) {
            XCTAssertEqual($0 as? NoctBoardAdmissionCodecError, .invalidArtifact)
        }
    }

    func testV1ReferenceRejectsCrossBoundBoardAndGroupIDs() throws {
        let boardID = UUID()
        let groupID = UUID()
        XCTAssertThrowsError(try NoctBoardReference(boardID: boardID, groupID: groupID)) {
            XCTAssertEqual($0 as? NoctBoardReferenceError, .boardAndGroupMustMatch)
        }

        let encoded = Data(
            "{\"boardID\":\"\(boardID.uuidString)\",\"groupID\":\"\(groupID.uuidString)\"}".utf8
        )
        XCTAssertThrowsError(try JSONDecoder().decode(NoctBoardReference.self, from: encoded))
        XCTAssertEqual(try NoctBoardReference(id: boardID).boardID, boardID)
        XCTAssertEqual(try NoctBoardReference(id: boardID).groupID, boardID)
        XCTAssertThrowsError(try NoctBoardReference(
            id: UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
        ))

        let extraKey = Data(
            "{\"boardID\":\"\(boardID.uuidString)\",\"groupID\":\"\(boardID.uuidString)\",\"extra\":true}".utf8
        )
        XCTAssertThrowsError(try JSONDecoder().decode(NoctBoardReference.self, from: extraKey))
    }

    func testAuditWindowFailsClosedBeforeRuntimeCompaction() throws {
        XCTAssertNoThrow(try NoctBoardClient.enforceAuditWindow(
            groupEventCount: NoctBoardLimits.maximumBoardEvents
        ))
        XCTAssertThrowsError(try NoctBoardClient.enforceAuditWindow(
            groupEventCount: NoctBoardLimits.maximumBoardEvents + 1
        )) {
            XCTAssertEqual($0 as? NoctBoardTransportError, .boardAuditWindowExceeded)
        }
        XCTAssertThrowsError(try NoctBoardClient.enforceAuditWindow(
            groupEventCount: NoctBoardLimits.maximumBoardEvents,
            reservingNewEvents: 1
        )) {
            XCTAssertEqual($0 as? NoctBoardTransportError, .boardAuditWindowExceeded)
        }
    }

    func testReceiveRouteRotationDecisionIsProactiveAndCrashResumable() {
        let now = Date(timeIntervalSince1970: 2_000_000_000)
        XCTAssertFalse(NoctBoardClient.shouldRotateReceiveRoute(
            hasPendingRoute: false,
            activeRouteExpiresAt: now.addingTimeInterval(
                NoctBoardClient.receiveRouteRotationLeadTime + 1
            ),
            at: now
        ))
        XCTAssertTrue(NoctBoardClient.shouldRotateReceiveRoute(
            hasPendingRoute: false,
            activeRouteExpiresAt: now.addingTimeInterval(
                NoctBoardClient.receiveRouteRotationLeadTime
            ),
            at: now
        ))
        XCTAssertTrue(NoctBoardClient.shouldRotateReceiveRoute(
            hasPendingRoute: true,
            activeRouteExpiresAt: now.addingTimeInterval(10_000),
            at: now
        ))
        XCTAssertTrue(NoctBoardClient.shouldRotateReceiveRoute(
            hasPendingRoute: false,
            activeRouteExpiresAt: nil,
            at: now
        ))
    }

    func testAdmissionCompletionVerifiesOwnerReassertedHistory() async throws {
        try requireRelayIntegration()
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(
            "noctboard-admission-history-\(UUID().uuidString)",
            isDirectory: true
        )
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }

        let port = UInt16.random(in: 40_000 ... 57_000)
        let endpoint = RelayEndpoint(host: "127.0.0.1", port: port)
        let relayStore = RelayStore()
        let opaqueRouteStore = OpaqueRouteRelayStoreV2()
        let server = RelayServer(store: relayStore, opaqueRouteStore: opaqueRouteStore)
        try server.start(host: "127.0.0.1", port: port)
        defer { server.stop() }
        try await Task.sleep(nanoseconds: 100_000_000)

        let ownerFile = root.appendingPathComponent("owner.json")
        let owner = try await makeClient(
            named: "history owner",
            file: ownerFile,
            relay: endpoint
        )
        let member = try await makeClient(
            named: "history member",
            file: root.appendingPathComponent("member.json"),
            relay: endpoint
        )
        let base = NoctweaveRendezvousV2.canonicalTimestamp(
            Date().addingTimeInterval(-60)
        )
        let created = try await owner.createBoard(
            name: "Admission history",
            createdAt: base
        )
        trace("focused-admission-board-created")
        let request = try await member.prepareAdmission(
            to: created.board,
            invitationBindingDigest: Data(repeating: 0xC3, count: 32),
            expiresAt: base.addingTimeInterval(3_600),
            createdAt: base.addingTimeInterval(1)
        )
        let recoveredRequest = try await member.prepareAdmission(
            to: created.board,
            invitationBindingDigest: Data(repeating: 0xC3, count: 32),
            expiresAt: base.addingTimeInterval(3_600),
            createdAt: base.addingTimeInterval(1.5)
        )
        XCTAssertEqual(recoveredRequest, request)
        XCTAssertEqual(
            try NoctBoardAdmissionCodec.decodeRequest(
                NoctBoardAdmissionCodec.encodeRequest(request)
            ),
            request
        )

        await owner.setAdmissionTestInterruption(.afterOwnerPlanJournaled)
        do {
            _ = try await owner.admit(
                request,
                createdAt: base.addingTimeInterval(2)
            )
            XCTFail("the test interruption must leave only a durable admission plan")
        } catch let error as NoctBoardTransportError {
            XCTAssertEqual(error, .publicationIncomplete(.pendingRetry))
        }
        let rotation = try await owner.maintain(
            at: base.addingTimeInterval(2.1),
            forceReceiveRouteRotation: true
        )
        XCTAssertTrue(rotation.rotatedReceiveRoute)
        do {
            _ = try await owner.admit(
                request,
                createdAt: base.addingTimeInterval(2.2)
            )
            XCTFail("a stale route plan must abort before adding a member")
        } catch let error as NoctBoardTransportError {
            XCTAssertEqual(error, .admissionPlanStale)
        }

        await owner.setAdmissionTestInterruption(.afterCoreEpochPrepared)
        do {
            _ = try await owner.admit(
                request,
                createdAt: base.addingTimeInterval(2.3)
            )
            XCTFail("the test interruption must model a crash after Core epoch prepare")
        } catch let error as NoctBoardTransportError {
            XCTAssertEqual(error, .publicationIncomplete(.pendingRetry))
        }
        let preparedOwner = try await NoctBoardClient.open(
            configuration: NoctBoardClientOpenConfiguration(
                stateFileURL: ownerFile,
                displayName: "history owner",
                relay: endpoint,
                stateProtection: .insecurePlaintextForTesting
            ),
            board: created.board
        )
        await preparedOwner.setAdmissionTestInterruption(.afterEpochPackageJournaled)
        do {
            _ = try await preparedOwner.admit(
                request,
                createdAt: base.addingTimeInterval(2.3)
            )
            XCTFail("the test interruption must model a crash after package journaling")
        } catch let error as NoctBoardTransportError {
            XCTAssertEqual(error, .publicationIncomplete(.pendingRetry))
        }
        let recoveredOwner = try await NoctBoardClient.open(
            configuration: NoctBoardClientOpenConfiguration(
                stateFileURL: ownerFile,
                displayName: "history owner",
                relay: endpoint,
                stateProtection: .insecurePlaintextForTesting
            ),
            board: created.board
        )
        let package = try await recoveredOwner.admit(
            request,
            createdAt: base.addingTimeInterval(2.3)
        )
        let recoveredPackage = try await recoveredOwner.admit(
            request,
            createdAt: base.addingTimeInterval(99)
        )
        XCTAssertEqual(
            try NoctBoardAdmissionCodec.encodePackage(recoveredPackage),
            try NoctBoardAdmissionCodec.encodePackage(package)
        )
        XCTAssertEqual(
            try NoctBoardAdmissionCodec.decodePackage(
                NoctBoardAdmissionCodec.encodePackage(package)
            ),
            package
        )
        XCTAssertEqual(package.anchor.baseState.epoch, 1)
        XCTAssertEqual(package.transition.nextState.epoch, 2)
        try assertStrictAdmissionArtifactRejectsUnknownAndDuplicateKeys(
            NoctBoardAdmissionCodec.encodeRequest(request),
            decode: NoctBoardAdmissionCodec.decodeRequest
        )
        try assertStrictAdmissionArtifactRejectsUnknownAndDuplicateKeys(
            NoctBoardAdmissionCodec.encodePackage(package),
            decode: NoctBoardAdmissionCodec.decodePackage
        )
        XCTAssertEqual(package.historyManifest.map(\.eventID), [
            created.initialPublication.event.id
        ])
        XCTAssertLessThanOrEqual(package.expiresAt, request.initialRouteSet.expiresAt)
        server.stop()
        do {
            try await member.completeAdmission(
                request: request,
                package: package,
                observedAt: base.addingTimeInterval(3)
            )
            XCTFail("history verification must not succeed while its relay is offline")
        } catch {
            // Welcome installation is intentionally irreversible; the durable
            // pending receipt must gate application use until exact retry.
        }
        do {
            _ = try await member.snapshot()
            XCTFail("an installed runtime with unverified history must remain gated")
        } catch let error as NoctBoardTransportError {
            XCTAssertEqual(error, .admissionVerificationPending)
        }

        try await Task.sleep(nanoseconds: 100_000_000)
        let restartedServer = RelayServer(
            store: relayStore,
            opaqueRouteStore: opaqueRouteStore
        )
        try restartedServer.start(host: "127.0.0.1", port: port)
        defer { restartedServer.stop() }
        try await Task.sleep(nanoseconds: 100_000_000)
        try await member.completeAdmission(
            request: request,
            package: package,
            observedAt: base.addingTimeInterval(4)
        )
        let snapshot = try await member.snapshot()
        XCTAssertNotNil(snapshot.projection.thread(id: created.initialThreadID))
        XCTAssertEqual(
            Set(snapshot.historyBootstrapProvenance.map(\.groupEventID)),
            Set(package.historyManifest.map(\.historyGroupEventID))
        )
        trace("focused-admission-history-verified")
    }

    func testProactiveRouteRotationCreatesSuccessorAndPolicyDriftFailsClosed() async throws {
        try requireRelayIntegration()
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(
            "noctboard-rotation-\(UUID().uuidString)",
            isDirectory: true
        )
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }

        let port = UInt16.random(in: 40_000 ... 57_000)
        let endpoint = RelayEndpoint(host: "127.0.0.1", port: port)
        let server = RelayServer(
            store: RelayStore(),
            opaqueRouteStore: OpaqueRouteRelayStoreV2()
        )
        try server.start(host: "127.0.0.1", port: port)
        defer { server.stop() }
        try await Task.sleep(nanoseconds: 100_000_000)

        let (client, headless) = try await makeClientWithHeadless(
            named: "rotation owner",
            file: root.appendingPathComponent("owner.json"),
            relay: endpoint
        )
        let maintainedAt = NoctweaveRendezvousV2.canonicalTimestamp(
            Date().addingTimeInterval(-2)
        )
        let created = try await client.createBoard(
            name: "Rotating board",
            createdAt: maintainedAt
        )
        let rotation = try await client.maintain(
            at: maintainedAt.addingTimeInterval(1),
            forceReceiveRouteRotation: true
        )
        XCTAssertTrue(rotation.rotatedReceiveRoute)
        XCTAssertEqual(rotation.routeAnnouncementComplete, true)
        XCTAssertFalse(rotation.requiresFollowUp)
        let healthy = try await client.maintain(at: maintainedAt.addingTimeInterval(2))
        XCTAssertFalse(healthy.rotatedReceiveRoute)
        XCTAssertNil(healthy.routeAnnouncementComplete)

        let afterRotation = try await client.publish(
            .createThread(NoctBoardCreateThread(title: "After successor route")),
            createdAt: maintainedAt.addingTimeInterval(2)
        )
        XCTAssertTrue(afterRotation.complete)
        let rotatedSnapshot = try await client.snapshot()
        XCTAssertEqual(rotatedSnapshot.projection.threads.count, 2)

        let runtime = try await headless.openGroupRuntime(groupID: created.board.groupID)
        let validState = await runtime.snapshot().signedState
        XCTAssertNoThrow(try NoctBoardClient.boardConfiguration(
            board: created.board,
            signedState: validState
        ))

        let owner = try XCTUnwrap(validState.members.first)
        let changedRole = replacing(
            validState,
            members: [GroupMemberV2(
                id: owner.id,
                role: .admin,
                addedEpoch: owner.addedEpoch
            )]
        )
        XCTAssertThrowsError(try NoctBoardClient.boardConfiguration(
            board: created.board,
            signedState: changedRole
        )) {
            XCTAssertEqual(
                $0 as? NoctBoardTransportError,
                .groupRoleChangeRequiresAuditSegmentation
            )
        }

        let changedPolicy = replacing(
            validState,
            permissions: GroupPermissionPolicy(entries: validState.permissions.entries.map {
                GroupPermissionEntry(
                    permission: $0.permission,
                    rule: $0.permission == .addMember ? .everyone : $0.rule
                )
            })
        )
        XCTAssertThrowsError(try NoctBoardClient.boardConfiguration(
            board: created.board,
            signedState: changedPolicy
        )) {
            XCTAssertEqual(
                $0 as? NoctBoardTransportError,
                .groupPermissionChangeRequiresAuditSegmentation
            )
        }

        let credential = try XCTUnwrap(validState.memberCredentials.first)
        let changedCapability = replacing(
            validState,
            credentials: [copyCredential(
                credential,
                contentTypes: ProtocolCapabilityManifest.defaultContentTypes
            )]
        )
        XCTAssertThrowsError(try NoctBoardClient.boardConfiguration(
            board: created.board,
            signedState: changedCapability
        )) {
            XCTAssertEqual(
                $0 as? NoctBoardTransportError,
                .groupCapabilityChangeRequiresAuditSegmentation
            )
        }

        let changedMetadata = replacing(
            validState,
            metadataDigest: Data(repeating: 0xE1, count: 32)
        )
        XCTAssertThrowsError(try NoctBoardClient.boardConfiguration(
            board: created.board,
            signedState: changedMetadata
        )) {
            XCTAssertEqual($0 as? NoctBoardTransportError, .invalidGroupState)
        }

        let removedState = replacing(
            validState,
            members: [GroupMemberV2(
                id: owner.id,
                role: owner.role,
                addedEpoch: owner.addedEpoch,
                removedEpoch: validState.epoch + 1
            )],
            credentials: [copyCredential(
                credential,
                removedEpoch: validState.epoch + 1
            )]
        )
        XCTAssertThrowsError(try NoctBoardClient.boardConfiguration(
            board: created.board,
            signedState: removedState
        )) {
            XCTAssertEqual(
                $0 as? NoctBoardTransportError,
                .membershipRemovalRequiresAuditSegmentation
            )
        }
    }

    func testHumanAndAgentsConvergeWhileUnrelatedSwarmCannotCrossBind() async throws {
        try requireRelayIntegration()
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(
            "noctboard-transport-\(UUID().uuidString)",
            isDirectory: true
        )
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: root) }

        let port = UInt16.random(in: 40_000 ... 57_000)
        let endpoint = RelayEndpoint(host: "127.0.0.1", port: port)
        let opaqueStore = OpaqueRouteRelayStoreV2()
        let server = RelayServer(
            store: RelayStore(),
            opaqueRouteStore: opaqueStore
        )
        try server.start(host: "127.0.0.1", port: port)
        defer { server.stop() }
        try await Task.sleep(nanoseconds: 100_000_000)

        let (owner, ownerHeadless) = try await makeClientWithHeadless(
            named: "human owner",
            file: root.appendingPathComponent("owner.json"),
            relay: endpoint
        )
        let agentA = try await makeClient(
            named: "planner agent",
            file: root.appendingPathComponent("agent-a.json"),
            relay: endpoint
        )
        let (agentB, agentBHeadless) = try await makeClientWithHeadless(
            named: "review agent",
            file: root.appendingPathComponent("agent-b.json"),
            relay: endpoint
        )
        // Keep authored protocol timestamps behind the relay's wall clock;
        // future-dated route authorizations are correctly rejected.
        let base = NoctweaveRendezvousV2.canonicalTimestamp(
            Date().addingTimeInterval(-60)
        )
        let boardID = UUID()
        let initialThreadID = UUID()
        let initialEventID = UUID()
        let initialTransactionID = UUID()
        let created = try await owner.createBoard(
            name: "Human-audited swarm",
            boardID: boardID,
            initialThreadID: initialThreadID,
            initialEventID: initialEventID,
            initialClientTransactionID: initialTransactionID,
            createdAt: base
        )
        trace("board-created")
        XCTAssertTrue(created.initialPublication.complete)
        let recovered = try await owner.recoverBoardCreation(
            name: "Human-audited swarm",
            boardID: boardID,
            initialThreadID: initialThreadID,
            initialEventID: initialEventID,
            initialClientTransactionID: initialTransactionID,
            createdAt: base
        )
        XCTAssertEqual(recovered.initialPublication.event, created.initialPublication.event)
        XCTAssertTrue(recovered.initialPublication.complete)
        let recoveredSnapshot = try await owner.snapshot()
        XCTAssertEqual(
            recoveredSnapshot.events.filter { $0.id == initialEventID }.count,
            1,
            "crash recovery must reuse the exact accepted event"
        )
        trace("board-recovery-idempotent")
        let health = try await owner.relayHealth()
        XCTAssertTrue(health.healthy)

        try await admit(
            agentA,
            to: owner,
            board: created.board,
            bindingByte: 0xA1,
            at: base.addingTimeInterval(2)
        )
        trace("agent-a-admitted")
        _ = try await owner.synchronize()
        trace("owner-synced-agent-a-route")

        try await admit(
            agentB,
            to: owner,
            board: created.board,
            bindingByte: 0xB2,
            at: base.addingTimeInterval(5)
        )
        trace("agent-b-admitted")
        _ = try await owner.synchronize()
        _ = try await agentA.synchronize()
        // Agent A processed the new epoch and published its exact replacement
        // route announcement during synchronization. Let the owner ingest it
        // before publishing work that must fan out to Agent A.
        _ = try await owner.synchronize()
        trace("epoch-three-converged")

        trace("history-snapshot-owner-start")
        let historyAtOwner = try await owner.snapshot()
        trace("history-snapshot-owner-done")
        XCTAssertEqual(
            historyAtOwner.events.filter { $0.id == created.initialPublication.event.id }.count,
            1,
            "exact history reassertions must deduplicate before projection"
        )
        XCTAssertEqual(
            historyAtOwner.historyBootstrapProvenance.filter {
                $0.reassertedEventID == created.initialPublication.event.id
            }.count,
            2,
            "each admission must retain explicit genesis-owner attestation provenance"
        )
        let historyAtAgentA = try await agentA.snapshot()
        trace("history-snapshot-agent-a-done")
        XCTAssertNotNil(historyAtAgentA.projection.thread(id: created.initialThreadID))
        let ownerRuntime = try await ownerHeadless.openGroupRuntime(
            groupID: created.board.groupID
        )
        let ownerGroupState = await ownerRuntime.snapshot()
        let initialSignedRecordBytes = try XCTUnwrap(ownerGroupState.events.first {
            $0.id == created.initialPublication.event.id
        }?.content.payload)

        let hostileHistoryDate = NoctweaveRendezvousV2.canonicalTimestamp(
            base.addingTimeInterval(7)
        )
        let hostileHistorySnapshot = try await agentB.snapshot()
        let hostileHistory = GroupConversationEventV2(
            groupID: created.board.groupID,
            authorMemberHandle: hostileHistorySnapshot.localMemberHandle,
            authorCredentialHandle: hostileHistorySnapshot.localCredentialHandle,
            createdAt: hostileHistoryDate,
            kind: .application,
            content: EncodedContent(
                type: NoctBoardClient.historyContentType,
                payload: try NoctweaveCoder.encode(
                    NoctBoardHistoryRecord(
                        boardID: created.board.boardID,
                        groupID: created.board.groupID,
                        signedEventRecordBytes: initialSignedRecordBytes
                    ),
                    sortedKeys: true
                ),
                disposition: .silent
            )
        )
        trace("hostile-history-member-send-start")
        try await sendRawGroupEvent(
            hostileHistory,
            with: agentBHeadless,
            at: hostileHistoryDate
        )
        trace("hostile-history-member-send-done")

        let malformedHistoryDate = NoctweaveRendezvousV2.canonicalTimestamp(
            base.addingTimeInterval(7.2)
        )
        let malformedHistory = GroupConversationEventV2(
            groupID: created.board.groupID,
            authorMemberHandle: historyAtOwner.localMemberHandle,
            authorCredentialHandle: historyAtOwner.localCredentialHandle,
            createdAt: malformedHistoryDate,
            kind: .application,
            content: EncodedContent(
                type: NoctBoardClient.historyContentType,
                payload: Data("{malformed".utf8),
                disposition: .silent
            )
        )
        trace("malformed-history-owner-send-start")
        try await sendRawGroupEvent(
            malformedHistory,
            with: ownerHeadless,
            at: malformedHistoryDate
        )
        trace("malformed-history-owner-send-done")
        let forgedHistoryDate = NoctweaveRendezvousV2.canonicalTimestamp(
            base.addingTimeInterval(7.4)
        )
        let forgedSignedRecord = NoctBoardSignedEventRecord(
            eventBytes: try NoctBoardCodec.encode(created.initialPublication.event),
            authorSignature: Data([0x01])
        )
        let forgedHistory = GroupConversationEventV2(
            groupID: created.board.groupID,
            authorMemberHandle: historyAtOwner.localMemberHandle,
            authorCredentialHandle: historyAtOwner.localCredentialHandle,
            createdAt: forgedHistoryDate,
            kind: .application,
            content: EncodedContent(
                type: NoctBoardClient.historyContentType,
                payload: try NoctweaveCoder.encode(
                    NoctBoardHistoryRecord(
                        boardID: created.board.boardID,
                        groupID: created.board.groupID,
                        signedEventRecordBytes: try NoctweaveCoder.encode(
                            forgedSignedRecord,
                            sortedKeys: true
                        )
                    ),
                    sortedKeys: true
                ),
                disposition: .silent
            )
        )
        trace("forged-history-owner-send-start")
        try await sendRawGroupEvent(
            forgedHistory,
            with: ownerHeadless,
            at: forgedHistoryDate
        )
        trace("forged-history-owner-send-done")
        _ = try await owner.synchronize()
        let rejectedHistory = try await owner.snapshot()
        XCTAssertTrue(rejectedHistory.containerRejections.contains {
            $0.groupEventID == hostileHistory.id
                && $0.reason == .unauthorizedHistoryBootstrap
        })
        XCTAssertTrue(rejectedHistory.containerRejections.contains {
            $0.groupEventID == malformedHistory.id && $0.reason == .malformedPayload
        })
        XCTAssertTrue(rejectedHistory.containerRejections.contains {
            $0.groupEventID == forgedHistory.id && $0.reason == .invalidAuthorSignature
        })

        let agentAHandle = try await agentA.snapshot().localMemberHandle
        let taskID = UUID()
        let task = NoctBoardCreateTask(
            taskID: taskID,
            threadID: created.initialThreadID,
            title: "Inspect the swarm result",
            details: "Only typed board operations are authority.",
            assigneeMemberHandle: nil
        )
        let taskPublication = try await owner.publish(
            .createTask(task),
            createdAt: base.addingTimeInterval(8)
        )
        try await requireComplete(
            taskPublication,
            client: owner,
            at: base.addingTimeInterval(8)
        )
        trace("task-published")
        let agentATaskSync = try await agentA.synchronize()
        _ = try await agentB.synchronize()
        trace(
            "task-synced-agent-a-received=\(agentATaskSync.receivedBoardEventIDs.count)"
        )
        XCTAssertNotNil(agentATaskSync.snapshot.projection.task(id: taskID))

        let beforeRejectedPublish = try await agentA.snapshot().events.count
        do {
            _ = try await agentA.publish(
                .createThread(NoctBoardCreateThread(title: "worker cannot create this")),
                createdAt: base.addingTimeInterval(9)
            )
            XCTFail("worker thread creation must fail local authorization preflight")
        } catch let error as NoctBoardTransportError {
            XCTAssertEqual(error, .localAuthorizationRejected(.unauthorized))
        }
        let afterRejectedPublish = try await agentA.snapshot().events.count
        XCTAssertEqual(afterRejectedPublish, beforeRejectedPublish)

        let assignmentPublication = try await agentA.publish(
            .assignTask(NoctBoardAssignTask(
                taskID: taskID,
                assigneeMemberHandle: agentAHandle
            )),
            createdAt: base.addingTimeInterval(10)
        )
        try await requireComplete(
            assignmentPublication,
            client: agentA,
            at: base.addingTimeInterval(10)
        )
        let activationPublication = try await agentA.publish(
            .transitionTask(NoctBoardTransitionTask(
                taskID: taskID,
                from: .pending,
                to: .active
            )),
            createdAt: base.addingTimeInterval(11)
        )
        try await requireComplete(
            activationPublication,
            client: agentA,
            at: base.addingTimeInterval(11)
        )
        trace("task-claimed")
        _ = try await agentB.synchronize()

        // An admitted agent can submit an otherwise well-bound event with a
        // near-maximum Lamport value. Core records the attempt as a logical
        // clock gap without consuming its author chain; honest publication can
        // therefore continue with a deterministic small next clock.
        let agentBBeforePoison = try await agentB.snapshot()
        let poisonDate = NoctweaveRendezvousV2.canonicalTimestamp(
            base.addingTimeInterval(11.5)
        )
        let poisonOperation = NoctBoardOperation.postMessage(NoctBoardPostMessage(
            threadID: created.initialThreadID,
            taskID: taskID,
            body: "hostile clock advance"
        ))
        let poison = NoctBoardEvent(
            boardID: created.board.boardID,
            groupID: created.board.groupID,
            authorMemberHandle: agentBBeforePoison.localMemberHandle,
            authorCredentialHandle: agentBBeforePoison.localCredentialHandle,
            logicalClock: NoctBoardLimits.maximumLogicalInteger,
            authorSequence: 0,
            previousAuthorEventDigest: nil,
            createdAtUnixMilliseconds: Int64(poisonDate.timeIntervalSince1970 * 1_000),
            operation: poisonOperation
        )
        let agentBRuntime = try await agentBHeadless.openGroupRuntime(
            groupID: created.board.groupID
        )
        let agentBGroupState = await agentBRuntime.snapshot()
        let poisonGroupEvent = GroupConversationEventV2(
            id: poison.id,
            clientTransactionID: poison.clientTransactionID,
            groupID: created.board.groupID,
            authorMemberHandle: poison.authorMemberHandle,
            authorCredentialHandle: poison.authorCredentialHandle,
            createdAt: poisonDate,
            kind: .application,
            content: try signedEventContent(
                poison,
                signingKey: agentBGroupState.localCredential.signingKey
            )
        )
        let preparedPoison = try await agentBHeadless.prepareGroupApplication(
            poisonGroupEvent,
            at: poisonDate
        )
        if let operation = preparedPoison.transportOperation {
            let resumed = try await agentBHeadless.resumeGroupTransport(
                groupID: created.board.groupID,
                operationID: operation.id,
                at: poisonDate
            )
            XCTAssertTrue(resumed.complete)
        }
        let poisonAtOwner = try await owner.synchronize().snapshot
        let poisonLedgerEntry = poisonAtOwner.ledger.entries.last { $0.eventID == poison.id }
        XCTAssertEqual(poisonLedgerEntry?.rejectionReason, .logicalClockGap)
        XCTAssertEqual(poisonLedgerEntry?.authorChainConsumed, false)
        do {
            _ = try await agentB.publish(
                poisonOperation,
                eventID: poison.id,
                clientTransactionID: poison.clientTransactionID,
                createdAt: poisonDate
            )
            XCTFail("an exact retry of a rejected event must not report success")
        } catch let error as NoctBoardTransportError {
            XCTAssertEqual(error, .localAuthorizationRejected(.logicalClockGap))
        }
        trace("clock-poison-rejected")

        let marker = "NOCTBOARD-PLAINTEXT-MARKER-\(UUID().uuidString)"
        let resultPublication = try await agentB.publish(
            .postMessage(NoctBoardPostMessage(
                threadID: created.initialThreadID,
                taskID: taskID,
                body: "result \(marker)"
            )),
            createdAt: base.addingTimeInterval(12)
        )
        try await requireComplete(
            resultPublication,
            client: agentB,
            at: base.addingTimeInterval(12)
        )
        trace("result-published")

        // Inspect while ciphertext is still retained for other recipients.
        let relaySnapshot = try await opaqueStore.snapshot()
        let relayBytes = try NoctweaveCoder.encode(relaySnapshot, sortedKeys: true)
        XCTAssertNil(relayBytes.range(of: Data(marker.utf8)))

        _ = try await agentA.synchronize()
        let completionPublication = try await agentA.publish(
            .transitionTask(NoctBoardTransitionTask(
                taskID: taskID,
                from: .active,
                to: .completed
            )),
            createdAt: base.addingTimeInterval(13)
        )
        try await requireComplete(
            completionPublication,
            client: agentA,
            at: base.addingTimeInterval(13)
        )
        trace("task-completed")
        _ = try await owner.synchronize()
        _ = try await agentB.synchronize()

        let ownerSnapshot = try await owner.snapshot()
        let agentASnapshot = try await agentA.snapshot()
        let agentBSnapshot = try await agentB.snapshot()
        XCTAssertEqual(ownerSnapshot.projectionDigest, agentASnapshot.projectionDigest)
        XCTAssertEqual(ownerSnapshot.projectionDigest, agentBSnapshot.projectionDigest)
        XCTAssertEqual(ownerSnapshot.projection.task(id: taskID)?.state, .completed)
        XCTAssertEqual(
            ownerSnapshot.projection.task(id: taskID)?.assigneeMemberHandle,
            agentAHandle
        )
        XCTAssertEqual(ownerSnapshot.projection.messages.count, 1)
        XCTAssertTrue(ownerSnapshot.containerRejections.contains {
            $0.reason == .unauthorizedHistoryBootstrap
        })
        XCTAssertTrue(ownerSnapshot.containerRejections.contains {
            $0.reason == .malformedPayload
        })
        XCTAssertEqual(
            ownerSnapshot.ledger.entries.last { $0.eventID == poison.id }?.rejectionReason,
            .authorSequenceConflict
        )
        trace("green-converged")

        let audit = try await owner.auditJSONL()
        XCTAssertNil(audit.range(of: Data(marker.utf8)))
        XCTAssertNotNil(audit.range(of: Data("org.noctboard/audit:1.0".utf8)))
        XCTAssertNotNil(audit.range(of: Data(poison.id.uuidString.utf8)))
        XCTAssertNotNil(audit.range(of: Data("authorSequenceConflict".utf8)))
        XCTAssertNotNil(audit.range(of: Data("unauthorizedHistoryBootstrap".utf8)))
        XCTAssertNotNil(audit.range(of: Data("invalidAuthorSignature".utf8)))
        XCTAssertNotNil(audit.range(of: Data("historyAttestation".utf8)))
        XCTAssertNotNil(audit.range(of: Data("\"historyAttestationCount\":2".utf8)))

        // A separate red-swarm group can carry a payload that *claims* the
        // green IDs, but it has no green route or group credential. The green
        // board never receives it, and the red product binding quarantines it.
        let redHeadless = try await HeadlessMessagingClient.open(
            stateStore: ClientStateStore(
                fileURL: root.appendingPathComponent("red.json"),
                protection: .insecurePlaintextForTesting
            ),
            displayName: "red swarm"
        )
        try await redHeadless.upsertRelayPreference(
            endpoint: endpoint,
            name: "test relay",
            accessPassword: nil
        )
        let red = NoctBoardClient(
            messagingClient: redHeadless,
            relay: endpoint,
            relayAccessPassword: nil,
            board: nil
        )
        let redBase = NoctweaveRendezvousV2.canonicalTimestamp(Date())
        let redCreated = try await red.createBoard(
            name: "Unrelated red swarm",
            createdAt: redBase
        )
        trace("red-board-created")
        let redSnapshot = try await red.snapshot()
        let greenEventIDs = Set(ownerSnapshot.events.map(\.id))
        XCTAssertTrue(redSnapshot.events.allSatisfy { !greenEventIDs.contains($0.id) })
        XCTAssertTrue(redSnapshot.projection.messages.allSatisfy {
            !$0.body.contains(marker)
        })
        let foreignHistoryDate = redBase.addingTimeInterval(1)
        let foreignHistory = GroupConversationEventV2(
            groupID: redCreated.board.groupID,
            authorMemberHandle: redSnapshot.localMemberHandle,
            authorCredentialHandle: redSnapshot.localCredentialHandle,
            createdAt: foreignHistoryDate,
            kind: .application,
            content: EncodedContent(
                type: NoctBoardClient.historyContentType,
                payload: try NoctweaveCoder.encode(
                    NoctBoardHistoryRecord(
                        boardID: created.board.boardID,
                        groupID: created.board.groupID,
                        signedEventRecordBytes: initialSignedRecordBytes
                    ),
                    sortedKeys: true
                ),
                disposition: .silent
            )
        )
        try await sendRawGroupEvent(
            foreignHistory,
            with: redHeadless,
            at: foreignHistoryDate
        )
        let attackDate = redBase.addingTimeInterval(2)
        let claimedGreen = NoctBoardEvent(
            boardID: created.board.boardID,
            groupID: created.board.groupID,
            authorMemberHandle: redSnapshot.localMemberHandle,
            authorCredentialHandle: redSnapshot.localCredentialHandle,
            logicalClock: 1,
            authorSequence: 1,
            previousAuthorEventDigest: try NoctBoardCodec.digest(redSnapshot.events[0]),
            createdAtUnixMilliseconds: Int64(attackDate.timeIntervalSince1970 * 1_000),
            operation: .postMessage(NoctBoardPostMessage(
                threadID: created.initialThreadID,
                body: "cross-bind \(marker)"
            ))
        )
        let redRuntime = try await redHeadless.openGroupRuntime(
            groupID: redCreated.board.groupID
        )
        let redGroupState = await redRuntime.snapshot()
        let attackGroupEvent = GroupConversationEventV2(
            id: claimedGreen.id,
            clientTransactionID: claimedGreen.clientTransactionID,
            groupID: redCreated.board.groupID,
            authorMemberHandle: claimedGreen.authorMemberHandle,
            authorCredentialHandle: claimedGreen.authorCredentialHandle,
            createdAt: attackDate,
            kind: .application,
            content: try signedEventContent(
                claimedGreen,
                signingKey: redGroupState.localCredential.signingKey
            )
        )
        let preparedAttack = try await redHeadless.prepareGroupApplication(
            attackGroupEvent,
            at: attackDate
        )
        XCTAssertTrue(preparedAttack.complete)
        let quarantinedRed = try await red.snapshot()
        XCTAssertEqual(
            quarantinedRed.containerRejections.last?.reason,
            .envelopeBindingMismatch
        )
        let redAudit = try await red.auditJSONL()
        XCTAssertNil(redAudit.range(of: Data(marker.utf8)))
        XCTAssertNotNil(redAudit.range(of: Data("containerRejection".utf8)))
        XCTAssertNotNil(redAudit.range(of: Data("envelopeBindingMismatch".utf8)))
        XCTAssertNotNil(redAudit.range(of: Data("\"containerRejectedCount\":2".utf8)))

        let greenSynchronization = try await owner.synchronize()
        let greenAfterAttack = greenSynchronization.snapshot
        XCTAssertFalse(greenAfterAttack.events.contains { $0.id == claimedGreen.id })
        XCTAssertEqual(greenAfterAttack.projectionDigest, ownerSnapshot.projectionDigest)
        trace("cross-bind-rejected")
    }

    private func makeClient(
        named name: String,
        file: URL,
        relay: RelayEndpoint
    ) async throws -> NoctBoardClient {
        try await NoctBoardClient.open(configuration: NoctBoardClientOpenConfiguration(
            stateFileURL: file,
            displayName: name,
            relay: relay,
            stateProtection: .insecurePlaintextForTesting
        ))
    }

    private func makeClientWithHeadless(
        named name: String,
        file: URL,
        relay: RelayEndpoint
    ) async throws -> (NoctBoardClient, HeadlessMessagingClient) {
        let headless = try await HeadlessMessagingClient.open(
            stateStore: ClientStateStore(
                fileURL: file,
                protection: .insecurePlaintextForTesting
            ),
            displayName: name
        )
        try await headless.upsertRelayPreference(
            endpoint: relay,
            name: "test relay",
            accessPassword: nil
        )
        return (
            NoctBoardClient(
                messagingClient: headless,
                relay: relay,
                relayAccessPassword: nil,
                board: nil
            ),
            headless
        )
    }

    private func trace(_ value: String) {
        FileHandle.standardError.write(Data("NoctBoardTransportTests: \(value)\n".utf8))
    }

    private func requireRelayIntegration() throws {
        guard ProcessInfo.processInfo.environment["NOCTBOARD_RUN_RELAY_INTEGRATION"] == "1" else {
            throw XCTSkip(
                "Set NOCTBOARD_RUN_RELAY_INTEGRATION=1 for the real PQ loopback relay tests"
            )
        }
    }

    private func replacing(
        _ state: SignedGroupStateV2,
        members: [GroupMemberV2]? = nil,
        credentials: [GroupMemberCredentialV2]? = nil,
        permissions: GroupPermissionPolicy? = nil,
        metadataDigest: Data? = nil
    ) -> SignedGroupStateV2 {
        SignedGroupStateV2(
            version: state.version,
            profile: state.profile,
            cipherSuite: state.cipherSuite,
            groupId: state.groupId,
            epoch: state.epoch,
            previousTranscriptHash: state.previousTranscriptHash,
            members: members ?? state.members,
            memberCredentials: credentials ?? state.memberCredentials,
            permissions: permissions ?? state.permissions,
            metadataDigest: metadataDigest ?? state.metadataDigest,
            authorCredentialHandle: state.authorCredentialHandle,
            commitDigest: state.commitDigest,
            confirmedTranscriptHash: state.confirmedTranscriptHash,
            signedAt: state.signedAt,
            signature: state.signature
        )
    }

    private func copyCredential(
        _ credential: GroupMemberCredentialV2,
        contentTypes: [ContentTypeCapabilityV2]? = nil,
        removedEpoch: UInt64? = nil
    ) -> GroupMemberCredentialV2 {
        GroupMemberCredentialV2(
            memberHandle: credential.memberHandle,
            credentialHandle: credential.credentialHandle,
            admissionDigest: credential.admissionDigest,
            signingPublicKey: credential.signingPublicKey,
            agreementPublicKey: credential.agreementPublicKey,
            contentTypes: contentTypes ?? credential.contentTypes,
            addedEpoch: credential.addedEpoch,
            removedEpoch: removedEpoch ?? credential.removedEpoch
        )
    }

    private func requireComplete(
        _ publication: NoctBoardPublishResult,
        client: NoctBoardClient,
        at date: Date
    ) async throws {
        guard !publication.complete else { return }
        guard let operationID = publication.operationID else {
            throw NoctBoardTransportError.publicationIncomplete(publication.disposition)
        }
        var lastDisposition = publication.disposition
        for _ in 0 ..< 3 {
            let resumed = try await client.resumePublication(
                operationID: operationID,
                at: date
            )
            lastDisposition = resumed.disposition
            if resumed.complete { return }
        }
        throw NoctBoardTransportError.publicationIncomplete(lastDisposition)
    }

    private func sendRawGroupEvent(
        _ event: GroupConversationEventV2,
        with client: HeadlessMessagingClient,
        at date: Date
    ) async throws {
        let prepared = try await client.prepareGroupApplication(event, at: date)
        guard let operation = prepared.transportOperation else {
            guard prepared.complete else {
                XCTFail("raw group event prepared without resumable transport")
                throw NoctBoardTransportError.publicationIncomplete(.pendingRetry)
            }
            return
        }
        for _ in 0 ..< 4 {
            let resumed = try await client.resumeGroupTransport(
                groupID: event.groupID,
                operationID: operation.id,
                at: date
            )
            if resumed.complete { return }
        }
        XCTFail("raw group event fanout did not complete after exact retries")
        throw NoctBoardTransportError.publicationIncomplete(.pendingRetry)
    }

    private func signedEventContent(
        _ event: NoctBoardEvent,
        signingKey: SigningKeyPair
    ) throws -> EncodedContent {
        let eventBytes = try NoctBoardCodec.encode(event)
        let record = NoctBoardSignedEventRecord(
            eventBytes: eventBytes,
            authorSignature: try signingKey.sign(
                NoctBoardClient.eventSignaturePayload(eventBytes)
            )
        )
        return EncodedContent(
            type: NoctBoardClient.contentType,
            payload: try NoctweaveCoder.encode(record, sortedKeys: true),
            disposition: .silent
        )
    }

    private func assertStrictAdmissionArtifactRejectsUnknownAndDuplicateKeys<T>(
        _ canonical: Data,
        decode: (Data) throws -> T
    ) throws {
        XCTAssertEqual(canonical.last, UInt8(ascii: "}"))
        var unknown = Data(canonical.dropLast())
        unknown.append(Data(",\"zzNoctBoardUnknown\":true}".utf8))
        XCTAssertTrue(NoctweaveCanonicalJSON.isCanonical(unknown))
        XCTAssertThrowsError(try decode(unknown))

        var duplicate = Data(canonical.dropLast())
        duplicate.append(Data(",\"zzDuplicate\":true,\"zzDuplicate\":false}".utf8))
        XCTAssertFalse(NoctweaveCanonicalJSON.isCanonical(duplicate))
        XCTAssertThrowsError(try decode(duplicate))
    }

    private func admit(
        _ member: NoctBoardClient,
        to owner: NoctBoardClient,
        board: NoctBoardReference,
        bindingByte: UInt8,
        at date: Date
    ) async throws {
        trace("admission-\(bindingByte)-prepare")
        let request = try await member.prepareAdmission(
            to: board,
            invitationBindingDigest: Data(repeating: bindingByte, count: 32),
            expiresAt: date.addingTimeInterval(3_600),
            createdAt: date
        )
        trace("admission-\(bindingByte)-owner-add")
        let package = try await owner.admit(request, createdAt: date.addingTimeInterval(1))
        XCTAssertLessThanOrEqual(package.expiresAt, request.initialRouteSet.expiresAt)
        XCTAssertEqual(package.anchor.expiresAt, package.expiresAt)
        XCTAssertFalse(package.historyManifest.isEmpty)
        XCTAssertTrue(package.existingMemberRouteAnnouncements.allSatisfy {
            $0.stateEpoch <= package.anchor.baseState.epoch
        })
        if package.anchor.baseState.epoch > 1 {
            XCTAssertTrue(
                package.existingMemberRouteAnnouncements.contains {
                    $0.stateEpoch < package.anchor.baseState.epoch
                },
                "a still-valid pre-transition route must remain admissible"
            )
        }
        trace("admission-\(bindingByte)-member-complete")
        try await member.completeAdmission(
            request: request,
            package: package,
            observedAt: date.addingTimeInterval(1)
        )
        trace("admission-\(bindingByte)-done")
    }
}

private struct MaximumPackageField: Codable {
    let packageBytes: Data
}
