// SPDX-FileCopyrightText: 2026 Luiz Widmer
// SPDX-License-Identifier: AGPL-3.0-or-later

import Foundation
import NoctBoardUI
import SwiftUI

@main
struct NoctBoardApp: App {
    @StateObject private var support = AppSupportStore.shared

    @StateObject private var model: NoctBoardAuditConsoleModel

    init() {
        #if DEBUG
        let usesFixture = ProcessInfo.processInfo.arguments.contains("NOCTBOARD_UI_TEST_DEMO")
        _model = StateObject(wrappedValue: NoctBoardAuditConsoleModel(loadEvaluationFixture: usesFixture))
        #else
        _model = StateObject(wrappedValue: NoctBoardAuditConsoleModel())
        #endif
    }

    var body: some Scene {
        WindowGroup("NoctBoard Audit Console") {
            NoctBoardAuditConsole(model: model)
        }
        .defaultSize(width: 1_120, height: 760)
        Settings {
            AppSupportCard().padding(24).frame(width: 540)
        }
    }
}
