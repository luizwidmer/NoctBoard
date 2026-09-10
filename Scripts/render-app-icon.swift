import AppKit
import Foundation

let output = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)
for (points, scale) in [(16,1),(16,2),(32,1),(32,2),(128,1),(128,2),(256,1),(256,2),(512,1),(512,2)] {
    let size = points * scale
    let bitmap = NSBitmapImageRep(
        bitmapDataPlanes: nil, pixelsWide: size, pixelsHigh: size,
        bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true,
        isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0
    )!
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: bitmap)!
    let factor = CGFloat(size) / 1024
    let transform = NSAffineTransform(); transform.scale(by: factor); transform.concat()
    NSColor(calibratedRed: 0.08, green: 0.09, blue: 0.12, alpha: 1).setFill()
    NSBezierPath(roundedRect: NSRect(x: 16, y: 16, width: 992, height: 992), xRadius: 220, yRadius: 220).fill()
    let colors: [NSColor] = [NSColor(calibratedRed: 0.83, green: 0.42, blue: 0.40, alpha: 1),NSColor(calibratedRed: 0.94, green: 0.73, blue: 0.62, alpha: 1)]
    for column in 0..<3 {
        for row in 0..<3 {
            colors[(column + row) % 2].setFill()
            let x = 206 + column * 216, y = 206 + row * 216
            NSBezierPath(roundedRect: NSRect(x: x, y: y, width: 180, height: 180), xRadius: 42, yRadius: 42).fill()
        }
    }
    NSGraphicsContext.restoreGraphicsState()
    let suffix = scale == 2 ? "@2x" : ""
    let url = output.appendingPathComponent("icon_\(points)x\(points)\(suffix).png")
    try bitmap.representation(using: .png, properties: [:])!.write(to: url)
}
