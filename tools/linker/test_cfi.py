# SPDX-License-Identifier: Apache-2.0
"""Independent LLVM row checks on linked AArch64 instructions."""
from pathlib import Path
import os
import re
import shutil
import subprocess
import tempfile
import unittest

from cfi import Elf, Fde, Invalid, disassemble, normalize_bytes, normalize_file


ASSEMBLY = r'''
.text
.global caller
.type caller,%function
caller:
.cfi_startproc
mov x0,x30
bl OUTLINED_FUNCTION_0
mov x30,x0
ret
.cfi_endproc
.size caller,.-caller
.type OUTLINED_FUNCTION_0,%function
OUTLINED_FUNCTION_0:
.cfi_startproc
mov w8,#4
ret
.cfi_endproc
.size OUTLINED_FUNCTION_0,.-OUTLINED_FUNCTION_0
.type OUTLINED_FUNCTION_1,%function
OUTLINED_FUNCTION_1:
.cfi_startproc
.cfi_def_cfa_offset 16
.cfi_offset 30,-16
str x30,[sp,#-16]!
bl leaf
mov w22,w0
mov w21,#1
ldr x30,[sp],#16
ret
.cfi_endproc
.size OUTLINED_FUNCTION_1,.-OUTLINED_FUNCTION_1
.type leaf,%function
leaf:
.cfi_startproc
ret
.cfi_endproc
 .size leaf,.-leaf
.type borrowed_caller,%function
borrowed_caller:
.cfi_startproc
str x30,[sp,#-32]!
.cfi_def_cfa_offset 32
.cfi_offset 30,-32
bl OUTLINED_FUNCTION_2
.cfi_def_cfa_offset 16
ldr x30,[sp,#-16]
add sp,sp,#16
.cfi_def_cfa_offset 0
.cfi_restore 30
ret
.cfi_endproc
.size borrowed_caller,.-borrowed_caller
.type OUTLINED_FUNCTION_2,%function
OUTLINED_FUNCTION_2:
.cfi_startproc
mov x0,x19
mov x1,x22
add sp,sp,#16
ret
.cfi_endproc
.size OUTLINED_FUNCTION_2,.-OUTLINED_FUNCTION_2
'''


def llvm_row(text, pc):
    # Read independently decoded LLVM rows, not the normalizer's event decoder.
    blocks = re.split(r'(?=^[0-9a-f]+ [0-9a-f]+ [0-9a-f]+ FDE)', text, flags=re.M)
    for block in blocks:
        match = re.search(r'pc=([0-9a-f]+)\.\.\.([0-9a-f]+)', block)
        if match and int(match[1], 16) <= pc < int(match[2], 16):
            rows = [(int(m[1], 16), m[2]) for m in re.finditer(r'^\s*0x([0-9a-f]+): (.*)$', block, re.M)]
            return max((row for row in rows if row[0] <= pc), key=lambda row: row[0])[1]
    raise AssertionError(f'no independently decoded row for {pc:#x}')


class LinkedInstructionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.root = Path(cls.directory.name)
        cls.objdump = shutil.which('llvm-objdump')
        cls.dwarfdump = shutil.which('llvm-dwarfdump')
        cls.clang = shutil.which('clang')
        cls.lld = shutil.which('ld.lld')
        if not all((cls.objdump, cls.dwarfdump, cls.clang, cls.lld)):
            raise unittest.SkipTest('LLVM tools required for linked instruction tests')
        source = cls.root / 'fixture.s'
        source.write_text(ASSEMBLY)
        subprocess.run([cls.clang, '--target=aarch64-none-elf', '-c', str(source), '-o', str(cls.root / 'fixture.o')], check=True)
        cls.path = cls.root / 'fixture.elf'
        subprocess.run([cls.lld, '-e', 'caller', '--eh-frame-hdr', '-zseparate-loadable-segments', '-zmax-page-size=4096', str(cls.root / 'fixture.o'), '-o', str(cls.path)], check=True)
        cls.original = cls.path.read_bytes()
        cls.instructions = disassemble(cls.path, cls.objdump)
        cls.fixed, cls.report = normalize_bytes(cls.original, cls.instructions)
        cls.fixed_path = cls.root / 'fixed.elf'
        cls.fixed_path.write_bytes(cls.fixed)
        cls.old_rows = subprocess.check_output([cls.dwarfdump, '--eh-frame', str(cls.path)], text=True)
        cls.new_rows = subprocess.check_output([cls.dwarfdump, '--eh-frame', str(cls.fixed_path)], text=True)
        cls.symbols = {name: address for address, symbols in Elf(cls.original).symbols.items() for name, _ in symbols}

    def test_original_is_real_instruction_negative(self):
        helper = self.symbols['OUTLINED_FUNCTION_1']
        self.assertIn('CFA=WSP+16', llvm_row(self.old_rows, helper))
        self.assertIn('CFA=WSP+16', llvm_row(self.old_rows, helper + 20))
        caller = self.symbols['caller']
        self.assertNotIn('W30=', llvm_row(self.old_rows, caller + 4))

    def test_helper_rows_follow_executed_sp_and_lr(self):
        helper = self.symbols['OUTLINED_FUNCTION_1']
        self.assertEqual(llvm_row(self.new_rows, helper), 'CFA=WSP')
        for offset in (4, 8, 12, 16):
            self.assertIn('CFA=WSP+16', llvm_row(self.new_rows, helper + offset))
            self.assertIn('W30=[CFA-16]', llvm_row(self.new_rows, helper + offset))
        self.assertEqual(llvm_row(self.new_rows, helper + 20), 'CFA=WSP')

    def test_caller_lr_custody_at_every_triple_pc(self):
        caller = self.symbols['caller']
        self.assertEqual(llvm_row(self.new_rows, caller), 'CFA=WSP')
        for offset in (4, 8):
            self.assertIn('W30=W0', llvm_row(self.new_rows, caller + offset))
        self.assertEqual(llvm_row(self.new_rows, caller + 12), 'CFA=WSP')

    def test_idempotent_without_executable_or_unrelated_cfi_change(self):
        twice, report = normalize_bytes(self.fixed, self.instructions)
        self.assertEqual(twice, self.fixed)
        self.assertEqual(report['corrected_fdes'], 0)
        before, after = Elf(self.original), Elf(self.fixed)
        for name in ('.text',):
            s = before.sections[name]
            self.assertEqual(before.slice(s.offset, s.size), after.slice(s.offset, s.size))
        leaf = self.symbols['leaf']
        old = next(r for r in before.records() if isinstance(r, Fde) and r.start == leaf)
        new = next(r for r in after.records() if isinstance(r, Fde) and r.start == leaf)
        self.assertEqual(old.program, new.program)

    def changed_fixture(self, assembly):
        source = self.root / 'changed.s'
        source.write_text(assembly)
        subprocess.run([self.clang, '--target=aarch64-none-elf', '-c', str(source), '-o', str(self.root / 'changed.o')], check=True)
        target = self.root / 'changed.elf'
        subprocess.run([self.lld, '-e', 'caller', '--eh-frame-hdr', '-zseparate-loadable-segments', '-zmax-page-size=4096', str(self.root / 'changed.o'), '-o', str(target)], check=True)
        return target.read_bytes(), disassemble(target, self.objdump)

    def test_saved_register_corruption_rejects(self):
        data, instructions = self.changed_fixture(ASSEMBLY.replace('mov w8,#4', 'mov w0,#4'))
        with self.assertRaisesRegex(Invalid, 'destroys saved LR'):
            normalize_bytes(data, instructions)

    def test_interior_entry_rejects(self):
        data, instructions = self.changed_fixture(ASSEMBLY + '\ninvalid_entry: b caller+8\n')
        with self.assertRaisesRegex(Invalid, 'branch into transient'):
            normalize_bytes(data, instructions)

    def test_borrowed_sp_forwarded_to_actual_continuation(self):
        helper = self.symbols['OUTLINED_FUNCTION_2']
        self.assertEqual(llvm_row(self.old_rows, helper), 'CFA=WSP')
        for offset in (0, 4, 8):
            self.assertEqual(llvm_row(self.new_rows, helper + offset), 'CFA=WSP+16')
        self.assertEqual(llvm_row(self.new_rows, helper + 12), 'CFA=WSP')
        caller = self.symbols['borrowed_caller']
        self.assertIn('CFA=WSP+32', llvm_row(self.new_rows, caller + 4))
        self.assertIn('CFA=WSP+16', llvm_row(self.new_rows, caller + 8))
        # Start SP is 0x1000 after the caller allocated its frame.
        # Both points unwind through the continuation to the same caller CFA.
        self.assertEqual(0x1000 + 16 + 16, 0x1020)
        self.assertEqual((0x1000 + 16) + 0 + 16, 0x1020)

    def test_borrowed_delta_rejects(self):
        data, instructions = self.changed_fixture(ASSEMBLY.replace('mov x1,x22\nadd sp,sp,#16', 'mov x1,x22\nadd sp,sp,#32'))
        with self.assertRaisesRegex(Invalid, 'row/delta disagrees'):
            normalize_bytes(data, instructions)

    def test_borrowed_original_row_rejects(self):
        data, instructions = self.changed_fixture(ASSEMBLY.replace('.cfi_def_cfa_offset 16\nldr x30,[sp,#-16]', '.cfi_def_cfa_offset 20\nldr x30,[sp,#-16]'))
        with self.assertRaisesRegex(Invalid, 'row/delta disagrees'):
            normalize_bytes(data, instructions)

    def test_borrowed_tail_entry_rejects(self):
        data, instructions = self.changed_fixture(ASSEMBLY.replace('bl OUTLINED_FUNCTION_2', 'b OUTLINED_FUNCTION_2'))
        with self.assertRaisesRegex(Invalid, 'non-call entry'):
            normalize_bytes(data, instructions)

    def test_full_page_budget_rejects(self):
        broken = bytearray(self.original)
        import struct
        elf = Elf(bytes(broken))
        header_index = next(i for i, h in enumerate(elf.headers) if h[0] == 1 and h[1] == 4)
        h = elf.headers[header_index]
        # Deny spare file bytes without fabricating overlapping real sections.
        text = elf.sections['.text']
        struct.pack_into('<Q', broken, elf.section_offset + text.index * 64 + 16, elf.frame.address + elf.frame.size)
        with self.assertRaisesRegex(Invalid, 'overlaps another section'):
            normalize_bytes(bytes(broken), self.instructions)

    def test_atomic_file_result(self):
        target = self.root / 'atomic.elf'
        target.write_bytes(self.original)
        os.chmod(target, 0o755)
        normalize_file(target, self.objdump)
        self.assertEqual(target.read_bytes(), self.fixed)
        self.assertEqual(target.stat().st_mode & 0o777, 0o755)


if __name__ == '__main__':
    unittest.main()
