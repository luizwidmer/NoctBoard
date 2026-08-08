// SPDX-FileCopyrightText: 2026 Luiz Widmer
// SPDX-License-Identifier: AGPL-3.0-or-later

import NoctBoardUI
import SwiftUI

@main
struct NoctBoardApp: App {
    var body: some Scene {
        WindowGroup("NoctBoard Audit Console — Evaluation") {
            NoctBoardAuditConsole()
        }
        .defaultSize(width: 1_120, height: 760)
    }
}
