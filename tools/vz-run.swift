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
let serial = VZVirtioConsoleDeviceSerialPortConfiguration()
serial.attachment = VZFileHandleSerialPortAttachment(
    fileHandleForReading: .standardInput,
    fileHandleForWriting: .standardOutput
)
configuration.serialPorts = [serial]

do {
    try configuration.validate()
} catch {
    fputs("Virtualization.framework configuration: \(error)\n", stderr)
    exit(1)
}

let machine = VZVirtualMachine(configuration: configuration)
final class Delegate: NSObject, VZVirtualMachineDelegate {
    func guestDidStop(_ virtualMachine: VZVirtualMachine) {
        fputs("guest stopped\n", stderr)
        exit(0)
    }
    func virtualMachine(_ virtualMachine: VZVirtualMachine, didStopWithError error: Error) {
        fputs("guest error: \(error)\n", stderr)
        exit(1)
    }
}
let delegate = Delegate()
machine.delegate = delegate
DispatchQueue.main.asyncAfter(deadline: .now() + 15) {
    fputs("platform probe timed out\n", stderr)
    exit(2)
}
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
