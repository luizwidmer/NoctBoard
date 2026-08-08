// SPDX-FileCopyrightText: 2026 Luiz Widmer
// SPDX-License-Identifier: AGPL-3.0-or-later

import NoctBoardCore
import NoctBoardTransport
import NoctweaveCore
import SwiftUI
import UniformTypeIdentifiers

public enum NoctBoardAuditSource: Equatable, Sendable {
    case deterministicFixture
    case liveLocal(
        boardID: UUID,
        groupEpoch: UInt64,
        eventCount: Int,
        containerRejectionCount: Int
    )

    public var isLiveLocal: Bool {
        if case .liveLocal = self { return true }
        return false
    }
}

@MainActor
public final class NoctBoardAuditConsoleModel: ObservableObject {
    @Published public private(set) var result: NoctBoardProjectionResult?
    @Published public private(set) var importedAudit: NoctBoardImportedAudit?
    @Published public private(set) var errorMessage: String?
    @Published public private(set) var isImportingAudit = false
    @Published public private(set) var isLoadingLiveBoard = false
    @Published public private(set) var source: NoctBoardAuditSource = .deterministicFixture
    @Published public private(set) var containerRejections: [NoctBoardContainerRejection] = []
    @Published public private(set) var historyBootstrapProvenance: [
        NoctBoardHistoryBootstrapProvenance
    ] = []

    private var liveClient: NoctBoardClient?
    private var securityScopedStateURL: URL?

    public init() {
        // The standalone evaluation app intentionally does not open live client state.
        loadDeterministicDemo()
    }

    public func loadDeterministicDemo() {
        do {
            result = try NoctBoardDemoFixture.make()
            source = .deterministicFixture
            containerRejections = []
            historyBootstrapProvenance = []
            liveClient = nil
            stopAccessingStateFile()
            errorMessage = nil
        } catch {
            result = nil
            errorMessage = "Unable to construct the local audit projection: \(error.localizedDescription)"
        }
    }

    public func openLiveBoard(
        stateFileURL: URL,
        boardID: String,
        displayName: String,
        relayEndpoint: String,
        storageScopeIdentifier: String?,
        relayAccessPassword: String?,
        plaintextTesting: Bool
    ) {
        isLoadingLiveBoard = true
        errorMessage = nil
        Task { [weak self] in
            guard let self else { return }
            do {
                guard let boardUUID = UUID(uuidString: boardID) else {
                    throw NoctBoardAuditConsoleError.invalidBoardID
                }
                let board = try NoctBoardReference(id: boardUUID)
                let relay = try RelayEndpointParser.parse(relayEndpoint)
                let normalizedScope = storageScopeIdentifier?
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                let normalizedPassword = relayAccessPassword?.isEmpty == false
                    ? relayAccessPassword
                    : nil
                let startedAccess = stateFileURL.startAccessingSecurityScopedResource()
                do {
                    let client = try await NoctBoardClient.open(
                        configuration: NoctBoardClientOpenConfiguration(
                            stateFileURL: stateFileURL.standardizedFileURL,
                            storageScopeIdentifier: normalizedScope?.isEmpty == false
                                ? normalizedScope
                                : nil,
                            displayName: displayName,
                            relay: relay,
                            relayAccessPassword: normalizedPassword,
                            stateProtection: plaintextTesting
                                ? .insecurePlaintextForTesting
                                : .encrypted
                        ),
                        board: board
                    )
                    let snapshot = try await client.snapshot()
                    self.replaceLiveClient(
                        client,
                        securityScopedStateURL: startedAccess ? stateFileURL : nil
                    )
                    self.apply(snapshot)
                    self.errorMessage = nil
                } catch {
                    if startedAccess { stateFileURL.stopAccessingSecurityScopedResource() }
                    throw error
                }
            } catch {
                self.errorMessage = "Unable to open live board state: \(error.localizedDescription)"
            }
            self.isLoadingLiveBoard = false
        }
    }

    /// Explicitly performs network synchronization. Synchronization can also
    /// rotate and announce a receive route when its six-hour lease is near
    /// expiry, so opening the retained local snapshot remains a separate step.
    public func synchronizeLiveBoard() {
        guard let liveClient else {
            errorMessage = "Open a live local board before synchronizing."
            return
        }
        isLoadingLiveBoard = true
        errorMessage = nil
        Task { [weak self] in
            guard let self else { return }
            do {
                let synchronized = try await liveClient.synchronize()
                self.apply(synchronized.snapshot)
            } catch {
                self.errorMessage = "Unable to synchronize live board: \(error.localizedDescription)"
            }
            self.isLoadingLiveBoard = false
        }
    }

    func apply(_ snapshot: NoctBoardClientSnapshot) {
        result = snapshot.result
        containerRejections = snapshot.containerRejections
        historyBootstrapProvenance = snapshot.historyBootstrapProvenance
        source = .liveLocal(
            boardID: snapshot.board.boardID,
            groupEpoch: snapshot.groupEpoch,
            eventCount: snapshot.events.count,
            containerRejectionCount: snapshot.containerRejections.count
        )
    }

    private func replaceLiveClient(
        _ client: NoctBoardClient,
        securityScopedStateURL: URL?
    ) {
        stopAccessingStateFile()
        liveClient = client
        self.securityScopedStateURL = securityScopedStateURL
    }

    private func stopAccessingStateFile() {
        securityScopedStateURL?.stopAccessingSecurityScopedResource()
        securityScopedStateURL = nil
    }

    public func importAudit(from url: URL) {
        let hasAccess = url.startAccessingSecurityScopedResource()
        isImportingAudit = true
        errorMessage = nil
        Task { [weak self] in
            defer {
                if hasAccess { url.stopAccessingSecurityScopedResource() }
                self?.isImportingAudit = false
            }
            do {
                let audit = try await Task.detached(priority: .userInitiated) {
                    try NoctBoardImportedAudit.load(from: url)
                }.value
                self?.importedAudit = audit
            } catch {
                self?.errorMessage = "Unable to open audit file: \(error.localizedDescription)"
            }
        }
    }
}

private enum NoctBoardAuditConsoleError: LocalizedError {
    case invalidBoardID

    var errorDescription: String? {
        "Board ID must be a valid nonzero UUID."
    }
}

public struct NoctBoardAuditConsole: View {
    private enum Section: String, CaseIterable, Identifiable {
        case overview = "Security Overview"
        case threads = "Threads & Messages"
        case tasks = "Tasks"
        case members = "Member Roles"
        case ledger = "Decision Ledger"
        case importedAudit = "Imported Audit"

        var id: Self { self }
        var icon: String {
            switch self {
            case .overview: "checkmark.shield"
            case .threads: "text.bubble"
            case .tasks: "checklist"
            case .members: "person.3"
            case .ledger: "list.bullet.rectangle"
            case .importedAudit: "doc.text.magnifyingglass"
            }
        }
    }

    @StateObject private var model: NoctBoardAuditConsoleModel
    @State private var selection: Section? = .overview
    @State private var showingImporter = false
    @State private var showingLiveBoardOpen = false

    public init() {
        _model = StateObject(wrappedValue: NoctBoardAuditConsoleModel())
    }

    public var body: some View {
        NavigationSplitView {
            List(Section.allCases, selection: $selection) { section in
                Label(section.rawValue, systemImage: section.icon).tag(section)
            }
            .navigationTitle("NoctBoard Eval")
            .safeAreaInset(edge: .bottom) {
                VStack(alignment: .leading, spacing: 10) {
                    Button {
                        showingLiveBoardOpen = true
                    } label: {
                        Label("Open Live Board", systemImage: "lock.open.display")
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    Button {
                        showingImporter = true
                    } label: {
                        Label("Open Audit JSONL", systemImage: "folder")
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
                .buttonStyle(.plain)
                .padding()
            }
        } detail: {
            detail
                .navigationTitle(selection?.rawValue ?? "NoctBoard")
                .toolbar {
                    Button {
                        showingLiveBoardOpen = true
                    } label: {
                        Label("Open Live Board", systemImage: "lock.open.display")
                    }
                    Button {
                        model.synchronizeLiveBoard()
                    } label: {
                        Label("Sync Encrypted Board", systemImage: "arrow.triangle.2.circlepath")
                    }
                    .disabled(!model.source.isLiveLocal || model.isLoadingLiveBoard)
                    Button {
                        showingImporter = true
                    } label: {
                        Label("Open Audit", systemImage: "doc.badge.plus")
                    }
                }
        }
        .sheet(isPresented: $showingLiveBoardOpen) {
            LiveBoardOpenSheet { request in
                model.openLiveBoard(
                    stateFileURL: request.stateFileURL,
                    boardID: request.boardID,
                    displayName: request.displayName,
                    relayEndpoint: request.relayEndpoint,
                    storageScopeIdentifier: request.storageScopeIdentifier,
                    relayAccessPassword: request.relayAccessPassword,
                    plaintextTesting: request.plaintextTesting
                )
                selection = .overview
            }
        }
        .fileImporter(
            isPresented: $showingImporter,
            allowedContentTypes: [.data],
            allowsMultipleSelection: false
        ) { response in
            switch response {
            case .success(let urls):
                if let url = urls.first {
                    model.importAudit(from: url)
                    selection = .importedAudit
                }
            case .failure(let error):
                // Cancellation is intentionally quiet; other importer errors are surfaced by macOS.
                if (error as NSError).code != NSUserCancelledError {
                    selection = .importedAudit
                }
            }
        }
        .overlay {
            if model.isLoadingLiveBoard {
                ZStack {
                    Color.black.opacity(0.12).ignoresSafeArea()
                    ProgressView("Verifying local board state…")
                        .padding(22)
                        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))
                }
            }
        }
        .frame(minWidth: 960, minHeight: 640)
    }

    @ViewBuilder
    private var detail: some View {
        if let error = model.errorMessage {
            ContentUnavailableView(
                "Audit Console Unavailable",
                systemImage: "exclamationmark.triangle",
                description: Text(error)
            )
        } else if let result = model.result {
            VStack(spacing: 0) {
                if !model.historyBootstrapProvenance.isEmpty {
                    HistoryAttestationBanner(
                        count: model.historyBootstrapProvenance.count
                    )
                }
                switch selection ?? .overview {
                case .overview: OverviewView(
                    result: result,
                    source: model.source,
                    containerRejections: model.containerRejections,
                    historyBootstrapProvenance: model.historyBootstrapProvenance
                )
                case .threads: ThreadsView(projection: result.projection)
                case .tasks: TasksView(tasks: result.projection.tasks)
                case .members: MembersView(members: result.projection.members)
                case .ledger: LedgerView(
                    entries: result.ledger.entries,
                    historyBootstrapProvenance: model.historyBootstrapProvenance
                )
                case .importedAudit:
                    if model.isImportingAudit {
                        ProgressView("Reading bounded audit file…")
                    } else {
                        ImportedAuditView(audit: model.importedAudit)
                    }
                }
            }
        } else {
            ProgressView("Building local projection…")
        }
    }
}

private struct LiveBoardOpenRequest: @unchecked Sendable {
    let stateFileURL: URL
    let boardID: String
    let displayName: String
    let relayEndpoint: String
    let storageScopeIdentifier: String?
    let relayAccessPassword: String?
    let plaintextTesting: Bool
}

private struct LiveBoardOpenSheet: View {
    @Environment(\.dismiss) private var dismiss
    let onOpen: (LiveBoardOpenRequest) -> Void

    @State private var stateFilePath = ""
    @State private var selectedStateFileURL: URL?
    @State private var boardID = ""
    @State private var displayName = "Human auditor"
    @State private var relayEndpoint = "http://127.0.0.1:9340"
    @State private var storageScopeIdentifier = ""
    @State private var relayAccessPassword = ""
    @State private var plaintextTesting = false
    @State private var showingStateFileImporter = false

    var body: some View {
        NavigationStack {
            Form {
                Section("Authorized local state") {
                    HStack {
                        TextField("Absolute encrypted state-file path", text: $stateFilePath)
                            .textFieldStyle(.roundedBorder)
                            .onChange(of: stateFilePath) { _, newValue in
                                if selectedStateFileURL?.path != newValue {
                                    selectedStateFileURL = nil
                                }
                            }
                        Button("Choose…") { showingStateFileImporter = true }
                    }
                    TextField("Board UUID", text: $boardID)
                        .textFieldStyle(.roundedBorder)
                    TextField("Local display label", text: $displayName)
                        .textFieldStyle(.roundedBorder)
                    TextField("Rollback-anchor scope (optional)", text: $storageScopeIdentifier)
                        .textFieldStyle(.roundedBorder)
                }

                Section("Relay configuration") {
                    TextField("Explicit relay endpoint", text: $relayEndpoint)
                        .textFieldStyle(.roundedBorder)
                    SecureField("Relay access password (optional)", text: $relayAccessPassword)
                        .textFieldStyle(.roundedBorder)
                    Text("A non-empty password requires tls://, https://, or wss://. Plaintext tcp://, http://, and ws:// accept no password and are evaluation-only. Noctweave persists the password in the selected client-state store: encrypted by default, but plaintext if testing mode is selected. It is never written to app logs.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                Section("State protection") {
                    Toggle("Insecure plaintext state for isolated testing", isOn: $plaintextTesting)
                    if plaintextTesting {
                        Label(
                            "Never select this for a real board; state and any persisted relay password will be plaintext.",
                            systemImage: "exclamationmark.triangle.fill"
                        )
                        .foregroundStyle(.red)
                    }
                }

                Section("Audit semantics") {
                    Text("Open verifies the retained local group state and reconstructs its deterministic projection without fetching new events. Opening may persist normal encrypted-store migrations, rollback anchors, and the selected relay preference. Sync is a separate network action and may rotate/announce a receive route. An app-level auditor is not a cryptographic receive-only credential.")
                        .font(.callout)
                }
            }
            .formStyle(.grouped)
            .navigationTitle("Open Live NoctBoard")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        relayAccessPassword.removeAll(keepingCapacity: false)
                        dismiss()
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Open Retained Snapshot") {
                        let request = LiveBoardOpenRequest(
                            stateFileURL: selectedStateFileURL
                                ?? URL(fileURLWithPath: stateFilePath).standardizedFileURL,
                            boardID: boardID,
                            displayName: displayName,
                            relayEndpoint: relayEndpoint,
                            storageScopeIdentifier: storageScopeIdentifier.isEmpty
                                ? nil
                                : storageScopeIdentifier,
                            relayAccessPassword: relayAccessPassword.isEmpty
                                ? nil
                                : relayAccessPassword,
                            plaintextTesting: plaintextTesting
                        )
                        onOpen(request)
                        relayAccessPassword.removeAll(keepingCapacity: false)
                        dismiss()
                    }
                    .disabled(!isReady)
                }
            }
        }
        .fileImporter(
            isPresented: $showingStateFileImporter,
            allowedContentTypes: [.data],
            allowsMultipleSelection: false
        ) { response in
            if case .success(let urls) = response, let url = urls.first {
                selectedStateFileURL = url
                stateFilePath = url.path
            }
        }
        .frame(minWidth: 680, minHeight: 570)
    }

    private var isReady: Bool {
        let trimmedPath = stateFilePath.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmedPath.hasPrefix("/")
            && UUID(uuidString: boardID) != nil
            && !displayName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && !relayEndpoint.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }
}

private struct OverviewView: View {
    let result: NoctBoardProjectionResult
    let source: NoctBoardAuditSource
    let containerRejections: [NoctBoardContainerRejection]
    let historyBootstrapProvenance: [NoctBoardHistoryBootstrapProvenance]

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                HStack(alignment: .firstTextBaseline) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(sourceTitle)
                            .font(.largeTitle.bold())
                        Text(sourceSubtitle)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Label(sourceBadge, systemImage: "checkmark.shield.fill")
                        .foregroundStyle(.green)
                }

                LazyVGrid(columns: [GridItem(.adaptive(minimum: 210), spacing: 12)], spacing: 12) {
                    StatusCard(
                        title: source.isLiveLocal
                            ? "Live board/group bound"
                            : "Fixture board/group bound",
                        detail: sourceBindingDetail,
                        icon: "lock.shield",
                        color: .green
                    )
                    StatusCard(
                        title: "Role authorization",
                        detail: "Roles are honest-client/advisory policy. A malicious admitted raw endpoint may backdate a signed write around a downgrade; credential removal plus epoch rotation is the future-write cutoff and ends the usable v1 segment.",
                        icon: "person.badge.key",
                        color: .blue
                    )
                    StatusCard(
                        title: "Foreign swarm rejected",
                        detail: "\(foreignBoundaryRejections) group-binding ledger rejection(s); \(containerRejections.count) malformed or mismatched container rejection(s).",
                        icon: "shield.slash",
                        color: foreignBoundaryRejections + containerRejections.count > 0
                            ? Color.green
                            : Color.orange
                    )
                    StatusCard(
                        title: source.isLiveLocal ? "Local verified view" : "Local fixture only",
                        detail: sourceAuditDetail,
                        icon: "eye.trianglebadge.exclamationmark",
                        color: .orange
                    )
                }

                HStack(spacing: 12) {
                    Metric(title: "Accepted", value: result.ledger.accepted.count, color: .green)
                    Metric(title: "Rejected", value: result.ledger.rejected.count, color: .red)
                    Metric(title: "Threads", value: result.projection.threads.count, color: .blue)
                    Metric(title: "Tasks", value: result.projection.tasks.count, color: .purple)
                }

                GroupBox("Projection digest") {
                    VStack(alignment: .leading, spacing: 8) {
                        Text(result.projectionDigest)
                            .font(.system(.body, design: .monospaced))
                            .textSelection(.enabled)
                        Label(sourceDigestDetail, systemImage: "number")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.vertical, 4)
                }

                GroupBox("Security boundary") {
                    Text(sourceSecurityDetail)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.vertical, 4)
                }

                GroupBox("License and source") {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Noct Board — Copyright © 2026 Luiz Widmer")
                            .font(.headline)
                        Text("Free software under AGPL-3.0-or-later. This program comes with absolutely no warranty. Full license terms and dependency notices are in LICENSE and NOTICE; source is available at https://github.com/luizwidmer/NoctBoard.")
                            .foregroundStyle(.secondary)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.vertical, 4)
                }
            }
            .padding(24)
        }
    }

    private var foreignBoundaryRejections: Int {
        result.ledger.rejected.filter { $0.rejectionReason == .groupBindingMismatch }.count
    }

    private var sourceTitle: String {
        switch source {
        case .deterministicFixture: "Deterministic evaluation fixture"
        case .liveLocal: "Locally verified retained group state"
        }
    }

    private var sourceSubtitle: String {
        switch source {
        case .deterministicFixture:
            "Fixed demo data, not live encrypted Noctweave state"
        case .liveLocal(let boardID, let epoch, let eventCount, _):
            "Board \(boardID.uuidString.lowercased()) · epoch \(epoch) · \(eventCount) retained event(s)"
        }
    }

    private var sourceBadge: String {
        source.isLiveLocal ? "Local state verified" : "Fixture checks passed"
    }

    private var sourceBindingDetail: String {
        switch source {
        case .deterministicFixture:
            "The v1 fixture uses one UUID for both board and Noctweave group."
        case .liveLocal(let boardID, _, _, _):
            "Strict v1 binding verified for board/group \(boardID.uuidString.lowercased())."
        }
    }

    private var sourceAuditDetail: String {
        if source.isLiveLocal {
            return "Projection and ledger were reconstructed from this authorized endpoint's retained group events; \(historyBootstrapProvenance.count) event(s) arrived through signed owner re-encryption for late join. This is not global non-equivocation proof."
        }
        return "The fixture exercises projection policy locally; it is not evidence from a live board."
    }

    private var sourceDigestDetail: String {
        source.isLiveLocal
            ? "Digest covers the full projection reconstructed from retained local group state."
            : "Digest covers this full deterministic fixture projection."
    }

    private var sourceSecurityDetail: String {
        if source.isLiveLocal {
            return "This view accepted authority from the board's locally retained Noctweave group state, then applied NoctBoard's strict deterministic policy. It proves this authorized endpoint's processing, not relay completeness, consensus, independent historical-envelope provenance for owner-backfilled late-join history, or cryptographic receive-only status. Board text below is rendered literally and never treated as executable instruction or bearer authority."
        }
        return "This fixture demonstrates deterministic projection and rejection policy only. Imported redacted JSONL is structurally inspected in a separate view and is never promoted to live-verified status. Messages below are fixture text rendered literally."
    }
}

private struct StatusCard: View {
    let title: String
    let detail: String
    let icon: String
    let color: Color

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Image(systemName: icon).font(.title2).foregroundStyle(color)
            Text(title).font(.headline)
            Text(detail).font(.caption).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, minHeight: 112, alignment: .topLeading)
        .padding()
        .background(.quaternary.opacity(0.55), in: RoundedRectangle(cornerRadius: 12))
    }
}

private struct HistoryAttestationBanner: View {
    let count: Int

    var body: some View {
        Label(
            "\(count) event(s) were independently author-signed, then re-encrypted and reasserted by the genesis owner for this late-joining endpoint. The original board-credential signature and attribution are verified; original outer-envelope delivery and completeness are not.",
            systemImage: "person.badge.shield.checkmark"
        )
        .font(.caption)
        .foregroundStyle(.orange)
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 18)
        .padding(.vertical, 10)
        .background(Color.orange.opacity(0.10))
    }
}

private struct Metric: View {
    let title: String
    let value: Int
    let color: Color

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(value, format: .number).font(.title.bold()).foregroundStyle(color)
            Text(title).font(.caption).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding()
        .background(.quaternary.opacity(0.35), in: RoundedRectangle(cornerRadius: 10))
    }
}

private struct ThreadsView: View {
    let projection: NoctBoardProjection

    var body: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 16) {
                ForEach(0 ..< projection.threads.count, id: \.self) { threadIndex in
                    let thread = projection.threads[threadIndex]
                    GroupBox {
                        VStack(alignment: .leading, spacing: 12) {
                            HStack {
                                Text(thread.title).font(.title2.bold())
                                Spacer()
                                Label(thread.isClosed ? "Closed" : "Open", systemImage: thread.isClosed ? "lock" : "bubble.left.and.bubble.right")
                                    .foregroundStyle(thread.isClosed ? Color.secondary : Color.green)
                            }
                            let messages = projection.messages.filter { $0.threadID == thread.id }
                            ForEach(0 ..< messages.count, id: \.self) { messageIndex in
                                let message = messages[messageIndex]
                                VStack(alignment: .leading, spacing: 5) {
                                    HStack {
                                        Text(shortHandle(message.authorMemberHandle.rawValue))
                                            .font(.caption.monospaced().bold())
                                        Spacer()
                                        Text(timestamp(message.createdAtUnixMilliseconds))
                                            .font(.caption)
                                            .foregroundStyle(.secondary)
                                    }
                                    Text(message.body)
                                        .textSelection(.enabled)
                                        .frame(maxWidth: .infinity, alignment: .leading)
                                }
                                .padding(10)
                                .background(.quaternary.opacity(0.35), in: RoundedRectangle(cornerRadius: 8))
                            }
                        }
                        .padding(.vertical, 4)
                    }
                }
            }
            .padding(24)
        }
    }
}

private struct TasksView: View {
    let tasks: [NoctBoardTask]

    var body: some View {
        List(tasks) { task in
            HStack(spacing: 14) {
                Image(systemName: task.state == .completed ? "checkmark.circle.fill" : "circle.dashed")
                    .font(.title2)
                    .foregroundStyle(taskColor(task.state))
                VStack(alignment: .leading, spacing: 4) {
                    Text(task.title).font(.headline)
                    if let details = task.details { Text(details).font(.caption).foregroundStyle(.secondary) }
                    if let assignee = task.assigneeMemberHandle {
                        Text("Assignee \(shortHandle(assignee.rawValue))").font(.caption.monospaced())
                    } else {
                        Text("Unassigned").font(.caption).foregroundStyle(.secondary)
                    }
                }
                Spacer()
                Text(task.state.rawValue.capitalized)
                    .font(.caption.bold())
                    .padding(.horizontal, 9).padding(.vertical, 5)
                    .background(taskColor(task.state).opacity(0.14), in: Capsule())
                    .foregroundStyle(taskColor(task.state))
            }
            .padding(.vertical, 5)
        }
    }
}

private struct MembersView: View {
    let members: [NoctBoardMemberAuthorization]

    var body: some View {
        List(members, id: \.memberHandle) { member in
            HStack(spacing: 14) {
                Image(systemName: roleIcon(member.role)).font(.title2).foregroundStyle(roleColor(member.role))
                VStack(alignment: .leading, spacing: 4) {
                    Text(member.role.rawValue.capitalized).font(.headline)
                    Text(member.memberHandle.rawValue).font(.caption.monospaced()).textSelection(.enabled)
                    Text("Credential \(shortHandle(member.credentialHandle.rawValue))")
                        .font(.caption.monospaced()).foregroundStyle(.secondary)
                }
                Spacer()
                Text(roleDescription(member.role)).font(.caption).foregroundStyle(.secondary)
            }
            .padding(.vertical, 5)
        }
    }
}

private struct LedgerView: View {
    private enum Filter: String, CaseIterable { case all = "All", accepted = "Accepted", rejected = "Rejected" }
    let entries: [NoctBoardLedgerEntry]
    let historyBootstrapProvenance: [NoctBoardHistoryBootstrapProvenance]
    @State private var filter: Filter = .all

    var body: some View {
        VStack(spacing: 0) {
            Picker("Outcome", selection: $filter) {
                ForEach(Filter.allCases, id: \.self) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented)
            .padding()
            List(filtered.indices, id: \.self) { index in
                let entry = filtered[index]
                HStack(alignment: .top, spacing: 12) {
                    Image(systemName: entry.outcome == .accepted ? "checkmark.circle.fill" : entry.outcome == .rejected ? "xmark.octagon.fill" : "arrow.clockwise.circle.fill")
                        .foregroundStyle(
                            entry.outcome == .accepted
                                ? Color.green
                                : entry.outcome == .rejected ? Color.red : Color.blue
                        )
                    VStack(alignment: .leading, spacing: 5) {
                        HStack {
                            Text("#\(entry.order) \(entry.operationType)").font(.headline.monospaced())
                            Text(entry.outcome.rawValue.uppercased()).font(.caption.bold())
                        }
                        if let reason = entry.rejectionReason {
                            Text("Reason: \(reason.rawValue)").foregroundStyle(.red)
                        }
                        Text("Author \(shortHandle(entry.authorMemberHandle.rawValue)) · sequence \(entry.authorSequence) · clock \(entry.logicalClock)")
                            .font(.caption.monospaced()).foregroundStyle(.secondary)
                        if historyEventIDs.contains(entry.eventID) {
                            Label(
                                "Author-signed event delivered through genesis-owner late-join attestation",
                                systemImage: "signature"
                            )
                            .font(.caption)
                            .foregroundStyle(.orange)
                        }
                        Text(entry.eventDigest).font(.caption2.monospaced()).textSelection(.enabled)
                    }
                }
                .padding(.vertical, 5)
            }
        }
    }

    private var filtered: [NoctBoardLedgerEntry] {
        switch filter {
        case .all: entries
        case .accepted: entries.filter { $0.outcome == .accepted }
        case .rejected: entries.filter { $0.outcome == .rejected }
        }
    }


    private var historyEventIDs: Set<UUID> {
        Set(historyBootstrapProvenance.map(\.reassertedEventID))
    }
}

private struct ImportedAuditView: View {
    let audit: NoctBoardImportedAudit?

    var body: some View {
        if let audit {
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    HStack {
                        Label(
                            audit.isStructurallyConsistent ? "Structure and counts consistent" : "Audit inconsistencies found",
                            systemImage: audit.isStructurallyConsistent ? "checkmark.seal.fill" : "exclamationmark.triangle.fill"
                        )
                        .font(.title2.bold())
                        .foregroundStyle(
                            audit.isStructurallyConsistent ? Color.green : Color.red
                        )
                        Spacer()
                    }
                    Text(audit.sourceURL.path).font(.caption.monospaced()).textSelection(.enabled)
                    Text("This inspection does not cryptographically replay the redacted file or recover the plaintext projection.")
                        .padding()
                        .background(Color.orange.opacity(0.12), in: RoundedRectangle(cornerRadius: 10))
                    HStack(spacing: 12) {
                        Metric(title: "Accepted", value: audit.acceptedCount, color: .green)
                        Metric(title: "Replayed", value: audit.replayedCount, color: .blue)
                        Metric(title: "Rejected", value: audit.rejectedCount, color: .red)
                        Metric(
                            title: "Container rejected",
                            value: audit.containerRejectedCount,
                            color: .orange
                        )
                        Metric(
                            title: "Owner attestations",
                            value: audit.historyAttestationCount,
                            color: .orange
                        )
                    }
                    GroupBox("Projection digest recorded by exporter") {
                        Text(audit.projectionDigest ?? "Missing")
                            .font(.body.monospaced()).textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading).padding(.vertical, 4)
                    }
                    if !audit.containerRejections.isEmpty {
                        GroupBox("Rejected Noctweave containers") {
                            VStack(alignment: .leading, spacing: 8) {
                                ForEach(
                                    0 ..< audit.containerRejections.count,
                                    id: \.self
                                ) { index in
                                    let rejection = audit.containerRejections[index]
                                    HStack {
                                        Text(rejection.groupEventID.uuidString.lowercased())
                                            .font(.caption.monospaced())
                                            .textSelection(.enabled)
                                        Spacer()
                                        Text(rejection.reason)
                                            .font(.caption.bold())
                                            .foregroundStyle(.orange)
                                    }
                                }
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(.vertical, 4)
                        }
                    }
                    if !audit.historyAttestations.isEmpty {
                        GroupBox("Late-join history attestations") {
                            VStack(alignment: .leading, spacing: 8) {
                                Text("Each row says a separately author-signed event was re-encrypted by the genesis owner. It does not prove original outer-envelope delivery or completeness.")
                                    .font(.caption)
                                    .foregroundStyle(.orange)
                                ForEach(
                                    0 ..< audit.historyAttestations.count,
                                    id: \.self
                                ) { index in
                                    let attestation = audit.historyAttestations[index]
                                    VStack(alignment: .leading, spacing: 3) {
                                        Text("Event \(attestation.reassertedEventID.uuidString.lowercased())")
                                            .font(.caption.monospaced())
                                            .textSelection(.enabled)
                                        Text("Wrapper \(attestation.groupEventID.uuidString.lowercased()) · owner \(shortHandle(attestation.assertedByMemberHandle.rawValue))")
                                            .font(.caption2.monospaced())
                                            .foregroundStyle(.secondary)
                                    }
                                }
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(.vertical, 4)
                        }
                    }
                    if !audit.errors.isEmpty {
                        GroupBox("Inspection findings") {
                            VStack(alignment: .leading, spacing: 6) {
                                ForEach(audit.errors, id: \.self) { Label($0, systemImage: "xmark.circle") }
                            }
                            .frame(maxWidth: .infinity, alignment: .leading).padding(.vertical, 4)
                        }
                    }
                }
                .padding(24)
            }
        } else {
            ContentUnavailableView(
                "No audit file open",
                systemImage: "doc.text.magnifyingglass",
                description: Text("Open a NoctBoard JSONL export to inspect its schema, ledger order, and summary counts.")
            )
        }
    }
}

private func shortHandle(_ value: String) -> String {
    guard value.count > 18 else { return value }
    return "\(value.prefix(10))…\(value.suffix(6))"
}

private func timestamp(_ milliseconds: Int64) -> String {
    Date(timeIntervalSince1970: Double(milliseconds) / 1_000)
        .formatted(date: .abbreviated, time: .standard)
}

private func taskColor(_ state: NoctBoardTaskState) -> Color {
    switch state {
    case .pending: .secondary
    case .active: .blue
    case .blocked: .orange
    case .completed: .green
    case .cancelled: .red
    }
}

private func roleIcon(_ role: NoctBoardRole) -> String {
    switch role {
    case .coordinator: "crown.fill"
    case .worker: "hammer.fill"
    case .auditor: "eye.fill"
    }
}

private func roleColor(_ role: NoctBoardRole) -> Color {
    switch role {
    case .coordinator: .purple
    case .worker: .blue
    case .auditor: .orange
    }
}

private func roleDescription(_ role: NoctBoardRole) -> String {
    switch role {
    case .coordinator: "Creates threads and tasks"
    case .worker: "Posts and advances assigned work"
    case .auditor: "Advisory audit policy for honest clients"
    }
}
