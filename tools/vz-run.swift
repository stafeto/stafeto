// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

import Foundation
import Virtualization

guard CommandLine.arguments.count == 3 else {
    fputs("usage: vz-run KERNEL_IMAGE BOOT_IMAGE\n", stderr)
    exit(2)
}

let configuration = VZVirtualMachineConfiguration()
configuration.cpuCount = 1
configuration.memorySize = 512 * 1024 * 1024
let boot = VZLinuxBootLoader(kernelURL: URL(fileURLWithPath: CommandLine.arguments[1]))
boot.initialRamdiskURL = URL(fileURLWithPath: CommandLine.arguments[2])
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
// start and one more with every SIGWINCH of the runner. A stdin that is
// no terminal has no size and no report.
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
windowChanged.resume()
sendWindowReport()
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
