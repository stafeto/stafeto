// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

import Foundation
import Virtualization

// --window-reports: the guest's console is served by the terminal service,
// which takes the size of the window of the runner's terminal as a report.
let windowReports = CommandLine.arguments.contains("--window-reports")
var arguments = CommandLine.arguments.filter { $0 != "--window-reports" }
// --cpus N: the machine has N processors (one by default).
var cpuCount = 1
if let at = arguments.firstIndex(of: "--cpus") {
    guard at + 1 < arguments.count, let n = Int(arguments[at + 1]), n >= 1 else {
        fputs("usage: vz-run [--window-reports] [--cpus N] [--time SECONDS] KERNEL_IMAGE BOOT_IMAGE\n", stderr)
        exit(2)
    }
    cpuCount = n
    arguments.removeSubrange(at...(at + 1))
}
// --time SECONDS: the time the guest's clock starts at, in seconds since
// the epoch (the host's time by default).
var startTime = UInt64(Date().timeIntervalSince1970)
if let at = arguments.firstIndex(of: "--time") {
    guard at + 1 < arguments.count, let t = UInt64(arguments[at + 1]) else {
        fputs("usage: vz-run [--window-reports] [--cpus N] [--time SECONDS] KERNEL_IMAGE BOOT_IMAGE\n", stderr)
        exit(2)
    }
    startTime = t
    arguments.removeSubrange(at...(at + 1))
}
guard arguments.count == 3 else {
    fputs("usage: vz-run [--window-reports] [--cpus N] [--time SECONDS] KERNEL_IMAGE BOOT_IMAGE\n", stderr)
    exit(2)
}

// VZ has no PL031, so the guest's clock service starts at the time the
// boot image carries in its file `boot-time` (lib/rtc): 16 bytes, the
// signature STAFTIME and the seconds as a little-endian u64. The boot
// image is the signature STAFBOOT, the version and the number of files
// (u32 each), then 48 bytes for each file: its name (32 bytes, padded with
// zeros), its offset and its size (u64 each; lib/bootimg). The runner writes
// the seconds into a copy of the image, which the guest boots, and removes
// the copy when it ends. An image without the file boots as it is.
var stampedImage: String? = nil
func stamped(_ path: String, _ seconds: UInt64) -> String {
    guard var image = FileManager.default.contents(atPath: path), image.count >= 16,
        image.prefix(8) == Data("STAFBOOT".utf8)
    else {
        return path
    }
    func u64(_ at: Int) -> Int {
        var value: UInt64 = 0
        for i in 0..<8 {
            value |= UInt64(image[at + i]) << (8 * UInt64(i))
        }
        return Int(truncatingIfNeeded: value)
    }
    let count = Int(image[12]) | Int(image[13]) << 8 | Int(image[14]) << 16 | Int(image[15]) << 24
    for n in 0..<count {
        let entry = 16 + 48 * n
        guard entry + 48 <= image.count else { break }
        let name = image[entry..<(entry + 32)].prefix { $0 != 0 }
        guard name == Data("boot-time".utf8) else { continue }
        let offset = u64(entry + 32)
        guard u64(entry + 40) >= 16, offset + 16 <= image.count,
            image[offset..<(offset + 8)] == Data("STAFTIME".utf8)
        else {
            return path
        }
        for i in 0..<8 {
            image[offset + 8 + i] = UInt8((seconds >> (8 * UInt64(i))) & 0xff)
        }
        let copy = NSTemporaryDirectory() + "vz-run-\(getpid()).img"
        guard FileManager.default.createFile(atPath: copy, contents: image) else { return path }
        stampedImage = copy
        atexit { if let copy = stampedImage { unlink(copy) } }
        return copy
    }
    return path
}

let configuration = VZVirtualMachineConfiguration()
configuration.cpuCount = cpuCount
configuration.memorySize = 512 * 1024 * 1024
let boot = VZLinuxBootLoader(kernelURL: URL(fileURLWithPath: arguments[1]))
boot.initialRamdiskURL = URL(fileURLWithPath: stamped(arguments[2], startTime))
boot.commandLine = "console=hvc0"
configuration.bootLoader = boot
// The guest reads a pipe of the runner's, which the runner fills from its
// stdin and never closes: the end of stdin (a closed pipe, Ctrl-D) reaches
// VZ as nothing, since VZ gives the guest an empty receive at the end of
// its input.
let input = Pipe()
let serial = VZVirtioConsoleDeviceSerialPortConfiguration()
serial.attachment = VZFileHandleSerialPortAttachment(
    fileHandleForReading: input.fileHandleForReading,
    fileHandleForWriting: .standardOutput
)
Thread.detachNewThread {
    while true {
        let data = FileHandle.standardInput.availableData
        if data.isEmpty {
            return
        }
        input.fileHandleForWriting.write(data)
    }
}
configuration.serialPorts = [serial]
// The size of the window of the runner's terminal goes into the guest's
// input as a report (services/tty/src/window.rs): GS, "W", the rows, ";",
// the columns, GS. VZ has no side channel for it, and the guest's terminal
// service takes the report out of the input and sends SIGWINCH to its
// foreground group where the size changed. The first report goes at the
// start and one more with every SIGWINCH of the runner. A stdin that is no
// terminal has no size and no report, and so has a runner that was not
// started with --window-reports (a guest with no terminal service takes
// the report for input).
func windowReport() -> Data? {
    var size = winsize()
    guard ioctl(STDIN_FILENO, TIOCGWINSZ, &size) == 0, size.ws_row > 0, size.ws_col > 0 else {
        return nil
    }
    return Data([0x1d]) + "W\(size.ws_row);\(size.ws_col)".data(using: .utf8)! + Data([0x1d])
}
func sendWindowReport() {
    if let report = windowReport() {
        input.fileHandleForWriting.write(report)
    }
}
signal(SIGWINCH, SIG_IGN)
let windowChanged = DispatchSource.makeSignalSource(signal: SIGWINCH, queue: .main)
windowChanged.setEventHandler { sendWindowReport() }
if windowReports {
    windowChanged.resume()
    sendWindowReport()
}
// A Virtio entropy device: the driver of services/virtio-rng finds it at
// device 6 of bus 0, after the console.
configuration.entropyDevices = [VZVirtioEntropyDeviceConfiguration()]

do {
    try configuration.validate()
} catch {
    fputs("Virtualization.framework configuration: \(error)\n", stderr)
    exit(1)
}

let machine = VZVirtualMachine(configuration: configuration)
final class Delegate: NSObject, VZVirtualMachineDelegate {
    func guestDidStop(_ virtualMachine: VZVirtualMachine) {
        // The kernel powers off at the end of its run and after a panic,
        // whose report has no port on VZ: the same kernel shows it under
        // HVF (docs/debugging.md).
        // On stdout, after the console's last bytes, where xtask reads it.
        FileHandle.standardOutput.write(
            "\nguest stopped: the kernel powered off (end of run or panic)\n".data(using: .utf8)!)
        exit(0)
    }
    func virtualMachine(_ virtualMachine: VZVirtualMachine, didStopWithError error: Error) {
        fputs("guest error: \(error)\n", stderr)
        exit(1)
    }
}
let delegate = Delegate()
machine.delegate = delegate
machine.start { result in
    switch result {
    case .success:
        fputs("VM started\n", stderr)
    case .failure(let error):
        fputs("VM start: \(error)\n", stderr)
        exit(1)
    }
}
RunLoop.main.run()
