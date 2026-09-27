# Task 6: panic symbols and final checks

The QEMU wrappers for `cargo xtask test` and `cargo xtask hvf` now send
kernel panic frame addresses to `llvm-symbolizer` with the ELF copied
for that exact kernel variant. The interactive `run` command streams
QEMU output to the terminal, retains it, and resolves any panic frames
when QEMU exits. Console dialog runs also inspect their captured output.
If the tool is missing, xtask leaves the original addresses in place and
prints a clear installation hint. This Mac's Rust LLVM component does
not provide `llvm-symbolizer`, so the fallback was exercised here.

The parser test distinguishes frame lines from other hex addresses. The
full `cargo xtask ci` run covers panic probes, normal boots, the trace
dialog, init and kernel tests, and the shipping disassembly check.
`cargo xtask hvf` covers both GIC versions and the paired measurements.
The shipping image remains below the 200 KiB limit, and the shell dialog
checks its prompt and the UART crash/restart path.
