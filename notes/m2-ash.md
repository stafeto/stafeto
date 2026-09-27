# First BusyBox ash script

`cargo xtask ash` builds the pinned BusyBox 1.37.0 with its `ash` applet,
links it with Picolibc, and boots `ash -c 'echo shell-ready; exit 0'` in
QEMU. The check requires both `shell-ready` and exit code 0 from the
client. BusyBox runs as a separate program loaded by `init`; the RAM file
service is present in the same image. The original `cargo xtask busybox`
check still exercises `cat /etc/motd`.

The build adds two small compatibility headers and replaces BusyBox's
`fflush(NULL)` call with a flush of stdout and stderr. This is needed
because the selected Picolibc build faults on `fflush(NULL)` after the
script has already run.

`tests/busybox/ash_os.c` supplies the limited single-process environment
for this probe. The root directory and process credentials are fixed.
Process creation, waiting, pipes, descriptor duplication, signals,
terminal controls, globbing, and resource limits return an explicit
unsupported error. The first image verifies parsing and execution of
builtins; it does not offer external commands yet.

`cargo xtask ash-dialog` adds the UART driver to a separate boot image.
The POSIX bridge connects standard descriptors to its service, echoes
typed bytes, and converts carriage return to newline. The QEMU test
waits for the `ash` prompt, types `echo interactive-ready` and `exit`,
then checks the command's output and exit code 0. Terminal editing and
job control are not implemented. The next slice is program spawn and
wait for external commands.

For a manual session, use `cargo xtask ash-shell`. Type `exit` to leave
`ash`, then press Ctrl-A followed by X to quit QEMU.
