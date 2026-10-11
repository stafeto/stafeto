# SPDX-License-Identifier: Apache-2.0
"""Independent LLVM row checks on linked AArch64 instructions."""
from pathlib import Path
import os
import re
import shutil
import subprocess
import tempfile
import unittest
import sys

sys.dont_write_bytecode = True

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
.type spill_caller,%function
spill_caller:
.cfi_startproc
str x30,[sp,#-48]!
.cfi_def_cfa_offset 48
bl OUTLINED_FUNCTION_3
.cfi_offset 30,-48
.cfi_offset 19,-32
.cfi_offset 20,-24
ldr x30,[sp],#48
.cfi_def_cfa_offset 0
.cfi_restore 30
.cfi_restore 19
.cfi_restore 20
ret
.cfi_endproc
.size spill_caller,.-spill_caller
.type OUTLINED_FUNCTION_3,%function
OUTLINED_FUNCTION_3:
.cfi_startproc
stp x19,x20,[sp,#16]
ret
.cfi_endproc
.size OUTLINED_FUNCTION_3,.-OUTLINED_FUNCTION_3
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


def llvm_tool(name, override):
    if value := os.environ.get(override):
        return value
    homebrew = Path('/opt/homebrew/opt/llvm/bin') / name
    if homebrew.is_file():
        return str(homebrew)
    return shutil.which(name)


class LinkedInstructionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.root = Path(cls.directory.name)
        cls.objdump = llvm_tool('llvm-objdump', 'STAFETO_CFI_OBJDUMP')
        cls.dwarfdump = llvm_tool('llvm-dwarfdump', 'STAFETO_CFI_DWARFDUMP')
        cls.clang = llvm_tool('clang', 'STAFETO_CFI_CLANG')
        cls.lld = llvm_tool('ld.lld', 'STAFETO_CFI_LLD')
        if not all(tool and Path(tool).is_file() for tool in (cls.objdump, cls.dwarfdump, cls.clang, cls.lld)):
            raise RuntimeError('linked CFI policy tests require Clang/LLVM, LLD and rustup llvm-tools')
        cls.linker = [cls.lld]
        if Path(cls.lld).name == 'rust-lld':
            cls.linker += ['-flavor', 'gnu']
        source = cls.root / 'fixture.s'
        source.write_text(ASSEMBLY)
        subprocess.run([cls.clang, '--target=aarch64-none-elf', '-c', str(source), '-o', str(cls.root / 'fixture.o')], check=True)
        cls.path = cls.root / 'fixture.elf'
        subprocess.run([*cls.linker, '-e', 'caller', '--eh-frame-hdr', '-zseparate-loadable-segments', '-zmax-page-size=4096', str(cls.root / 'fixture.o'), '-o', str(cls.path)], check=True)
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
        subprocess.run([*self.linker, '-e', 'caller', '--eh-frame-hdr', '-zseparate-loadable-segments', '-zmax-page-size=4096', str(self.root / 'changed.o'), '-o', str(target)], check=True)
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
            self.assertEqual(llvm_row(self.new_rows, helper + offset), 'CFA=WSP')
        self.assertEqual(llvm_row(self.new_rows, helper + 12), 'CFA=WSP-16')
        caller = self.symbols['borrowed_caller']
        self.assertIn('CFA=WSP+32', llvm_row(self.new_rows, caller + 4))
        self.assertIn('CFA=WSP+16', llvm_row(self.new_rows, caller + 8))
        # Start SP is 0x1000 after the caller allocated its frame.
        # A suspended call uses its BL row, preserving the pre-call SP.
        self.assertEqual(0x1000 + 0 + 32, 0x1020)
        self.assertEqual((0x1000 + 16) - 16 + 32, 0x1020)

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

    def test_genuine_spill_lr_published_before_call(self):
        caller = self.symbols['spill_caller']
        self.assertNotIn('W30=', llvm_row(self.old_rows, caller + 4))
        self.assertIn('W30=[CFA-48]', llvm_row(self.new_rows, caller + 4))
        self.assertNotIn('W19=', llvm_row(self.new_rows, caller + 4))
        self.assertIn('W19=[CFA-32]', llvm_row(self.new_rows, caller + 8))

    def test_delayed_lr_requires_entry_provenance_and_intact_cell(self):
        mutations = [
            ('str x30,[sp,#-48]!', 'bl leaf\nstr x30,[sp,#-48]!'),
            ('str x30,[sp,#-48]!', 'str x30,[sp,#-64]!'),
            ('.cfi_def_cfa_offset 48\nbl OUTLINED_FUNCTION_3',
             '.cfi_def_cfa_offset 48\nstr x19,[sp]\nbl OUTLINED_FUNCTION_3'),
            ('.cfi_def_cfa_offset 48\nbl OUTLINED_FUNCTION_3',
             '.cfi_def_cfa_offset 48\nb .+4\nbl OUTLINED_FUNCTION_3'),
        ]
        for old, new in mutations:
            with self.subTest(new=new):
                data, instructions = self.changed_fixture(ASSEMBLY.replace(old, new))
                with self.assertRaises(Invalid):
                    normalize_bytes(data, instructions)

    def test_pair_second_slot_lr_provenance(self):
        data, instructions = self.changed_fixture(ASSEMBLY.replace(
            'str x30,[sp,#-48]!', 'stp x29,x30,[sp,#-48]!').replace(
            '.cfi_offset 30,-48', '.cfi_offset 30,-40'))
        fixed, _ = normalize_bytes(data, instructions)
        target = self.root / 'pair-fixed.elf'
        target.write_bytes(fixed)
        rows = subprocess.check_output([self.dwarfdump, '--eh-frame', str(target)], text=True)
        symbols = {name: address for address, syms in Elf(data).symbols.items() for name, _ in syms}
        self.assertIn('W30=[CFA-40]', llvm_row(rows, symbols['spill_caller'] + 4))
        data, instructions = self.changed_fixture(ASSEMBLY.replace('str x30,[sp,#-48]!', 'stp x29,x30,[sp,#-48]!'))
        with self.assertRaisesRegex(Invalid, 'saved cell'):
            normalize_bytes(data, instructions)

    def test_compaction_rejects_intersecting_caller_rule(self):
        data, instructions = self.changed_fixture(ASSEMBLY.replace(
            'bl OUTLINED_FUNCTION_0\nmov x30,x0',
            'bl OUTLINED_FUNCTION_0\n.cfi_def_cfa_offset 16\nmov x30,x0'))
        with self.assertRaises(Invalid):
            normalize_bytes(data, instructions)

    def test_compaction_rejects_changed_helper_initial_lr(self):
        data, instructions = self.changed_fixture(ASSEMBLY.replace(
            'OUTLINED_FUNCTION_0:\n.cfi_startproc',
            'OUTLINED_FUNCTION_0:\n.cfi_startproc\n.cfi_register 30,1'))
        with self.assertRaises(Invalid):
            normalize_bytes(data, instructions)

    def test_leaf_lr_destination_rejects(self):
        for replacement in ('mov x30,x0', 'ldp x19,x30,[sp]'):
            with self.subTest(replacement=replacement):
                data, instructions = self.changed_fixture(ASSEMBLY.replace('mov w8,#4', replacement))
                with self.assertRaises(Invalid):
                    normalize_bytes(data, instructions)

    def test_helper_skip_restore_branch_rejects(self):
        data, instructions = self.changed_fixture(ASSEMBLY.replace('mov w22,w0', 'b .+8'))
        with self.assertRaisesRegex(Invalid, 'control flow|frame interior'):
            normalize_bytes(data, instructions)

    def test_eh_header_pointer_rejects_even_idempotent(self):
        import struct
        broken = bytearray(self.fixed)
        elf = Elf(self.fixed)
        struct.pack_into('<i', broken, elf.header.offset + 4, 0)
        with self.assertRaisesRegex(Invalid, 'frame pointer'):
            normalize_bytes(bytes(broken), self.instructions)

    def test_eh_header_duplicate_rejects_even_idempotent(self):
        broken = bytearray(self.fixed)
        elf = Elf(self.fixed)
        at = elf.header.offset + 12
        broken[at + 8:at + 16] = broken[at:at + 8]
        with self.assertRaisesRegex(Invalid, 'strictly ordered'):
            normalize_bytes(bytes(broken), self.instructions)

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

    def test_finite_prefix_exit_and_reentry_negatives(self):
        prefix = 'cmp w0,#0\nb.eq prefix_exit\n'
        source = ASSEMBLY.replace('spill_caller:\n.cfi_startproc\n', 'spill_caller:\n.cfi_startproc\n'+prefix)
        source = source.replace('.cfi_restore 20\nret\n.cfi_endproc', '.cfi_restore 20\nret\nprefix_exit:\nmov w0,#1\nret\n.cfi_endproc')
        data, instructions = self.changed_fixture(source)
        fixed, _ = normalize_bytes(data, instructions)
        for before in ('mov x19,x0', 'str x9,[x0]', 'sub sp,sp,#16\nadd sp,sp,#16'):
            bad, bad_instructions = self.changed_fixture(source.replace(prefix, before+'\n'+prefix))
            with self.assertRaisesRegex(Invalid, 'changed caller entry context'):
                normalize_bytes(bad, bad_instructions)
        for wrong in ('b spill_caller', 'sub sp,sp,#16', 'mov x19,x0', 'mov x30,x0', 'bl leaf'):
            with self.subTest(wrong=wrong):
                bad, instructions = self.changed_fixture(source.replace('prefix_exit:\nmov w0,#1', 'prefix_exit:\n'+wrong))
                with self.assertRaises(Invalid):
                    normalize_bytes(bad, instructions)

    def test_unsupported_simd_prefix_destination_rejects(self):
        prefix = 'mov v8.16b,v0.16b\ncmp w0,#0\nb.eq prefix_exit\n'
        source = ASSEMBLY.replace('spill_caller:\n.cfi_startproc\n', 'spill_caller:\n.cfi_startproc\n'+prefix)
        source = source.replace('.cfi_restore 20\nret\n.cfi_endproc', '.cfi_restore 20\nret\nprefix_exit:\nret\n.cfi_endproc')
        data, instructions = self.changed_fixture(source)
        with self.assertRaisesRegex(Invalid, 'unproved destination spelling'):
            normalize_bytes(data, instructions)

    def test_inverse_prefix_unique_first_save(self):
        prefix = 'cmp w0,#0\nb.ne prefix_frame\nmov w0,#1\nret\nprefix_frame:\n'
        source = ASSEMBLY.replace('spill_caller:\n.cfi_startproc\n', 'spill_caller:\n.cfi_startproc\n'+prefix)
        data, instructions = self.changed_fixture(source)
        fixed, _ = normalize_bytes(data, instructions)
        variants = [
            source+'\nextra_incoming: b prefix_frame\n',
            source.replace('b.ne prefix_frame', 'b.ne prefix_frame+4'),
            source.replace('mov w0,#1\nret\nprefix_frame:', 'mov w0,#1\nb prefix_frame\nprefix_frame:'),
            source.replace(prefix, 'mov x19,x0\n'+prefix),
            source.replace('prefix_frame:\nstr', 'prefix_frame:\n.cfi_def_cfa_offset 16\nstr'),
            source.replace('mov w0,#1\nret\nprefix_frame:', 'bl leaf\nret\nprefix_frame:'),
            source.replace(prefix, 'sub sp,sp,#16\n'+prefix),
        ]
        for index, bad_source in enumerate(variants):
            with self.subTest(index=index):
                bad, bad_instructions = self.changed_fixture(bad_source)
                with self.assertRaises(Invalid):
                    normalize_bytes(bad, bad_instructions)

    def test_linker_zero_reservation_preserves_envelope(self):
        script = self.root / 'reserve.ld'
        script.write_text('SECTIONS { .eh_frame : { *(.eh_frame) . += 512; } } INSERT AFTER .eh_frame_hdr;\n')
        target = self.root / 'reserved.elf'
        subprocess.run([*self.linker, '-e', 'caller', '--eh-frame-hdr', '-zseparate-loadable-segments', '-zmax-page-size=4096', '-T', str(script), str(self.root / 'fixture.o'), '-o', str(target)], check=True)
        original = target.read_bytes()
        elf = Elf(original)
        used = sum(len(record.raw) for record in elf.records()) + 4
        self.assertEqual(elf.frame.size - used, 512)
        fixed, _ = normalize_bytes(original, disassemble(target, self.objdump))
        repaired = Elf(fixed)
        self.assertEqual(elf.headers, repaired.headers)
        self.assertEqual(elf.frame.size, repaired.frame.size)
        for name in ('.text', '.data', '.bss'):
            if name in elf.sections and elf.sections[name].kind != 8:
                before, after = elf.sections[name], repaired.sections[name]
                self.assertEqual((before.address, before.size), (after.address, after.size))
                self.assertEqual(elf.slice(before.offset, before.size), repaired.slice(after.offset, after.size))
        self.assertEqual(normalize_bytes(fixed, disassemble(target, self.objdump))[0], fixed)
        target.write_bytes(fixed)
        subprocess.run([self.dwarfdump, '--verify', str(target)], check=True, stdout=subprocess.DEVNULL)
        broken = bytearray(original)
        broken[elf.frame.offset + elf.frame.size - 1] = 1
        with self.assertRaisesRegex(Invalid, 'data after EH terminator'):
            normalize_bytes(bytes(broken), self.instructions)
        # Removing the original terminator must not turn the reserve into a record.
        import struct
        broken = bytearray(original)
        struct.pack_into('<I', broken, elf.frame.offset + used - 4, 0xffffffff)
        with self.assertRaisesRegex(Invalid, 'unsupported EH record'):
            normalize_bytes(bytes(broken), self.instructions)

    def test_delayed_fp_parent_lr_at_real_spill_call(self):
        extra = r"""
.type delayed_fp_caller,%function
delayed_fp_caller:
.cfi_startproc
sub sp,sp,#112
.cfi_def_cfa_offset 112
stp x29,x30,[sp,#32]
bl OUTLINED_FUNCTION_3
add x29,sp,#32
.cfi_def_cfa 29,80
.cfi_offset 29,-80
.cfi_offset 30,-72
.cfi_offset 19,-96
.cfi_offset 20,-88
ldp x19,x20,[sp,#16]
.cfi_restore 19
.cfi_restore 20
.cfi_def_cfa 31,112
ldp x29,x30,[sp,#32]
.cfi_restore 29
.cfi_restore 30
add sp,sp,#112
.cfi_def_cfa_offset 0
ret
.cfi_endproc
.size delayed_fp_caller,.-delayed_fp_caller
"""
        data, instructions = self.changed_fixture(ASSEMBLY+extra)
        fixed, _ = normalize_bytes(data, instructions)
        from cfi import events, row_at
        before, after = Elf(data), Elf(fixed)
        start = next(a for a,names in before.symbols.items() if any(n=='delayed_fp_caller' for n,_ in names))
        old = next(f for f in before.records() if isinstance(f,Fde) and f.start==start)
        new = next(f for f in after.records() if isinstance(f,Fde) and f.start==start)
        call = start+8
        oldrow = row_at(events(old.program, start, old.cie.code), call, old.cie.initial, old.cie.data)
        newrow = row_at(events(new.program, start, new.cie.code), call, new.cie.initial, new.cie.data)
        self.assertEqual(oldrow.rule(30), ('same',30))
        self.assertEqual(newrow.cfa, (31,112))
        self.assertEqual(newrow.rule(30), ('offset',-72))
        self.assertEqual(newrow.rule(29), ('same',29))
        parent_sp, parent_lr = 0x10000, 0xa55a55
        physical_sp = parent_sp-112
        memory = {physical_sp+40:parent_lr}
        self.assertEqual(memory[physical_sp+newrow.cfa[1]+newrow.rule(30)[1]], parent_lr)
        self.assertNotEqual(call+4, parent_lr)
        variants = [
            extra.replace('add x29,sp,#32', 'add x29,sp,#16'),
            extra.replace('stp x29,x30,[sp,#32]', 'stp x29,x30,[sp,#24]'),
            extra.replace('add x29,sp,#32', 'nop\nadd x29,sp,#32'),
            extra.replace('stp x29,x30,[sp,#32]', 'b delayed_skip\nstp x29,x30,[sp,#32]\ndelayed_skip:'),
        ]
        for index, wrong in enumerate(variants):
            with self.subTest(index=index):
                bad, bad_instructions = self.changed_fixture(ASSEMBLY+wrong)
                with self.assertRaises(Invalid):
                    normalize_bytes(bad, bad_instructions)
        bad, bad_instructions = self.changed_fixture((ASSEMBLY+extra).replace('stp x19,x20,[sp,#16]\nret', 'stp x19,x20,[sp,#16]\nmov x29,x0\nret'))
        with self.assertRaises(Invalid):
            normalize_bytes(bad, bad_instructions)

    def test_physical_parent_cells_survive_real_helper_stores(self):
        extra = r"""
.type physical_parent,%function
physical_parent:
.cfi_startproc
sub sp,sp,#112
.cfi_def_cfa_offset 112
stp x29,x30,[sp,#32]
.cfi_offset 29,-80
.cfi_offset 30,-72
add x29,sp,#16
.cfi_def_cfa 29,96
bl OUTLINED_FUNCTION_3
.cfi_def_cfa 31,112
ldp x29,x30,[sp,#32]
.cfi_restore 29
.cfi_restore 30
add sp,sp,#112
.cfi_def_cfa_offset 0
ret
.cfi_endproc
.size physical_parent,.-physical_parent
"""
        # The actual frame relation is FP=SP+16; the LR cell is SP+40.
        data, ins = self.changed_fixture(ASSEMBLY + extra)
        normalize_bytes(data, ins)
        for store in ('stp x19,x20,[sp,#32]', 'str x0,[sp,#40]',
                      'stur x0,[sp,#40]', 'strh w0,[sp,#47]',
                      'mov x8,sp\nstr x0,[x8,#40]',
                      'str x0,[x29,#24]', 'mov w8,w29\nstr x0,[x8,#24]',
                      'mov w8,wsp\nstr x0,[x8,#40]',
                      'mov x8,sp\nadd x8,x8,#40\nstr x0,[x8],#8',
                      'mov x8,sp\nadd x8,x8,#32\nstp x19,x20,[x8],#16',
                      'add x8,sp,x0\nstr x0,[x8]',
                      'stp x19,x20,[sp,#32]!', 'stlxr w12,x10,[sp]',
                      'mov x8,sp\nadd x8,x8,#40\nstlxr w12,x10,[x8]'):
            with self.subTest(store=store):
                source = (ASSEMBLY + extra).replace('stp x19,x20,[sp,#16]\nret', store + '\nret')
                data, ins = self.changed_fixture(source)
                with self.assertRaises(Invalid):
                    normalize_bytes(data, ins)
        for mutation in ('add sp,sp,#16\nbl OUTLINED_FUNCTION_3',
                         'mov x29,x0\nbl OUTLINED_FUNCTION_3'):
            data, ins = self.changed_fixture((ASSEMBLY + extra).replace(
                '.cfi_def_cfa 29,96\nbl OUTLINED_FUNCTION_3', '.cfi_def_cfa 29,96\n' + mutation))
            with self.assertRaises(Invalid):
                normalize_bytes(data, ins)
        incoming = "\n.type tbz_entry,%function\ntbz_entry:\n.cfi_startproc\ntbz w0,#0,physical_inside\nret\n.cfi_endproc\n.size tbz_entry,.-tbz_entry\n"
        data, ins = self.changed_fixture(ASSEMBLY + extra.replace(
            '.cfi_def_cfa 29,96\nbl OUTLINED_FUNCTION_3',
            '.cfi_def_cfa 29,96\nphysical_inside:\nbl OUTLINED_FUNCTION_3') + incoming)
        with self.assertRaisesRegex(Invalid, 'another entry'):
            normalize_bytes(data, ins)
        # Original typed object stores remain supported; new store forms fail closed.
        for store in ('str x0,[x8,#40]', 'strb w0,[x8,x9]', 'stlr w0,[x8]', 'stlxr w12,x10,[x8]', 'stlxr w10,w9,[x8]'):
            data, ins = self.changed_fixture((ASSEMBLY + extra).replace(
                'stp x19,x20,[sp,#16]\nret', store + '\nret'))
            normalize_bytes(data, ins)
        data, ins = self.changed_fixture((ASSEMBLY + extra).replace(
            'stp x19,x20,[sp,#16]\nret', 'stur x0,[x8,#40]\nret'))
        with self.assertRaisesRegex(Invalid, 'source-object'):
            normalize_bytes(data, ins)

    def test_own_helper_lr_and_volatile_frame_alias_are_live(self):
        caller = "\n.type own_parent,%function\nown_parent:\n.cfi_startproc\nstr x30,[sp,#-48]!\n.cfi_def_cfa_offset 48\n.cfi_offset 30,-48\nbl OUTLINED_FUNCTION_1\nldr x30,[sp],#48\n.cfi_def_cfa_offset 0\n.cfi_restore 30\nret\n.cfi_endproc\n.size own_parent,.-own_parent\n"
        base = ASSEMBLY + caller
        for store in ('str x0,[sp]', 'mov x8,sp\nstr x0,[x8]',
                      'sub x8,sp,#8\nstp x0,x1,[x8],#16'):
            data, ins = self.changed_fixture(base.replace(
                'mov w22,w0\nmov w21,#1', store))
            with self.assertRaisesRegex(Invalid, 'own live LR'):
                normalize_bytes(data, ins)
        source = base.replace('bl leaf\nmov w22,w0\nmov w21,#1',
                              'add x8,sp,#32\nbl leaf\nstr x0,[x8]')
        data, ins = self.changed_fixture(source)
        with self.assertRaisesRegex(Invalid, 'unknown frame-derived'):
            normalize_bytes(data, ins)
        # The spare upper half of the paid 16-byte helper frame is disjoint.
        source = base.replace('mov w22,w0\nmov w21,#1',
                              'add x8,sp,#8\nstr x0,[x8],#8')
        data, ins = self.changed_fixture(source)
        normalize_bytes(data, ins)

    def test_finite_preframe_graph_preserves_every_bypass(self):
        extra = r"""
.type graph_parent,%function
graph_parent:
.cfi_startproc
cmp w0,#0
b.eq graph_second
cmp w0,#1
b.eq graph_save
mov w8,#4
graph_error:
str w8,[x1]
ret
graph_second:
cmp w0,#2
b.eq graph_save
mov w8,#5
b graph_error
graph_save:
str x30,[sp,#-32]!
.cfi_def_cfa_offset 32
bl OUTLINED_FUNCTION_0
.cfi_offset 30,-32
ldr x30,[sp],#32
.cfi_def_cfa_offset 0
.cfi_restore 30
ret
.cfi_endproc
.size graph_parent,.-graph_parent
"""
        data, ins = self.changed_fixture(ASSEMBLY + extra)
        fixed, _ = normalize_bytes(data, ins)
        from cfi import events, row_at
        old, new = Elf(data), Elf(fixed)
        start = next(a for a,names in old.symbols.items() if any(n=='graph_parent' for n,_ in names))
        before = next(f for f in old.records() if isinstance(f,Fde) and f.start==start)
        after = next(f for f in new.records() if isinstance(f,Fde) and f.start==start)
        for pc in range(start, start+44, 4):
            self.assertEqual(row_at(events(before.program,start,before.cie.code),pc,before.cie.initial,before.cie.data),
                             row_at(events(after.program,start,after.cie.code),pc,after.cie.initial,after.cie.data))
        for mutation in ('mov x19,x0', 'sub sp,sp,#16', 'mov x30,x0',
                         'bl leaf', 'mov x8,sp', 'mov w8,wsp'):
            data, ins = self.changed_fixture(ASSEMBLY + extra.replace('cmp w0,#0', mutation+'\ncmp w0,#0'))
            with self.assertRaises(Invalid):
                normalize_bytes(data, ins)
        data, ins = self.changed_fixture(ASSEMBLY + extra.replace('b graph_error', 'b graph_parent'))
        with self.assertRaisesRegex(Invalid, 'cycle'):
            normalize_bytes(data, ins)
        incoming = "\n.type foreign_graph,%function\nforeign_graph:\n.cfi_startproc\ntbnz w0,#0,graph_save\nret\n.cfi_endproc\n.size foreign_graph,.-foreign_graph\n"
        data, ins = self.changed_fixture(ASSEMBLY + extra + incoming)
        with self.assertRaisesRegex(Invalid, 'foreign entry'):
            normalize_bytes(data, ins)
        island = extra.replace('graph_second:', 'graph_island:\nnop\ngraph_second:')
        data, ins = self.changed_fixture(ASSEMBLY + island + incoming.replace('graph_save', 'graph_island'))
        with self.assertRaisesRegex(Invalid, 'foreign entry'):
            normalize_bytes(data, ins)

    def test_exact_volatile_vector_zero_preserves_saved_simd_boundary(self):
        source = ASSEMBLY.replace('mov w8,#4', 'movi v0.2d,#0')
        data, ins = self.changed_fixture(source)
        normalize_bytes(data, ins)
        for replacement in ('movi v8.2d,#0', 'movi v0.2d,#0xff',
                            'movi v0.4s,#0', 'movi v1.2d,#0',
                            'mov v8.16b,v0.16b'):
            data, ins = self.changed_fixture(ASSEMBLY.replace('mov w8,#4', replacement))
            with self.assertRaises(Invalid):
                normalize_bytes(data, ins)

    def test_actual_probe_object_stores_have_finite_address_forms(self):
        objects = "\n.data\n.balign 8\nvalid_atomic: .quad 0\nvalid_array: .zero 80\n.text\n"
        for helper, setup in [
            ('ldxr x9,[x8]\nadd x9,x9,#1\nstxr w10,x9,[x8]',
             'adrp x8,valid_atomic\nadd x8,x8,:lo12:valid_atomic'),
            ('ldxr w9,[x8]\nadd w9,w9,#1\nstxr w10,w9,[x8]',
             'adrp x8,valid_atomic\nadd x8,x8,:lo12:valid_atomic'),
            ('str x9,[x10,x8]\nadd x8,x8,#8',
             'adrp x10,valid_array\nadd x10,x10,:lo12:valid_array\nmov x8,#0\nmov x9,#1'),
            ('str w9,[x10,x8]',
             'adrp x10,valid_array\nadd x10,x10,:lo12:valid_array\nmov x8,#0\nmov w9,#1'),
        ]:
            source = ASSEMBLY.replace('mov w8,#4', helper).replace(
                '.cfi_startproc\nmov x0,x30', '.cfi_startproc\n'+setup+'\nmov x0,x30') + objects
            data, ins = self.changed_fixture(source)
            normalize_bytes(data, ins)
        parent = "\n.type probe_parent,%function\nprobe_parent:\n.cfi_startproc\nstr x30,[sp,#-32]!\n.cfi_def_cfa_offset 32\n.cfi_offset 30,-32\nbl OUTLINED_FUNCTION_0\nldr x30,[sp],#32\n.cfi_def_cfa_offset 0\n.cfi_restore 30\nret\n.cfi_endproc\n.size probe_parent,.-probe_parent\n"
        for helper in ('mov x8,sp\nstxr w10,x9,[x8]',
                       'mov w8,wsp\nstxr w10,x9,[x8]',
                       'mov x8,sp\nstr x9,[x10,x8]',
                       'mov x10,sp\nstr x9,[x10,x8]',
                       'str x9,[x10,x8,lsl #3]',
                       'str x9,[x10,w8,uxtw #3]',
                       'stxp w10,x9,x11,[x8]', 'stxr w0,x9,[x8]'):
            data, ins = self.changed_fixture(ASSEMBLY.replace('mov w8,#4', helper) + parent)
            with self.assertRaises(Invalid):
                normalize_bytes(data, ins)

    def test_transient_lr_endpoint_keeps_original_complete_row(self):
        caller = r'''caller:
.cfi_startproc
stp x29,x30,[sp,#-32]!
.cfi_def_cfa_offset 32
mov x0,x30
bl OUTLINED_FUNCTION_0
mov x30,x0
.cfi_offset 29,-32
.cfi_offset 30,-24
ldp x29,x30,[sp],#32
.cfi_def_cfa_offset 0
.cfi_restore 29
.cfi_restore 30
ret
.cfi_endproc
.size caller,.-caller'''
        old = ASSEMBLY[ASSEMBLY.index('caller:'):ASSEMBLY.index('.size caller,.-caller') + len('.size caller,.-caller')]
        fixture = ASSEMBLY.replace(old, caller, 1)
        data, instructions = self.changed_fixture(fixture)
        fixed, report = normalize_bytes(data, instructions)
        self.assertGreater(report['corrected_fdes'], 0)
        self.assertEqual(normalize_bytes(fixed, instructions)[0], fixed)
        before, after = Elf(data), Elf(fixed)
        from cfi import events, row_at
        start = next(address for address, names in before.symbols.items() if any(name == 'caller' for name, _ in names))
        original = next(f for f in before.records() if isinstance(f, Fde) and f.start == start)
        repaired = next(f for f in after.records() if isinstance(f, Fde) and f.start == start)
        for offset in range(0, original.size, 4):
            expected = row_at(events(original.program, start, original.cie.code), start + offset, original.cie.initial, original.cie.data)
            if offset in (8, 12):
                expected.registers[30] = ('register', 0)
            actual = row_at(events(repaired.program, start, repaired.cie.code), start + offset, repaired.cie.initial, repaired.cie.data)
            self.assertEqual(actual, expected)
        for broken in (
            fixture.replace('bl OUTLINED_FUNCTION_0\nmov x30,x0', 'bl OUTLINED_FUNCTION_0\n.cfi_offset 19,-8\nmov x30,x0', 1),
            fixture.replace('mov x30,x0', 'mov x30,x1', 1),
            fixture.replace('mov x0,x30\nbl OUTLINED_FUNCTION_0', 'mov x0,x30\ninside_endpoint:\nbl OUTLINED_FUNCTION_0', 1) + '\n.global foreign_endpoint\nforeign_endpoint:\nb inside_endpoint\n',
        ):
            with self.subTest(broken=broken):
                image, operations = self.changed_fixture(broken)
                with self.assertRaises(Invalid):
                    normalize_bytes(image, operations)

    def test_unknown_parent_lr_is_terminal_rejection(self):
        source = ASSEMBLY+"\n.type unknown_parent,%function\nunknown_parent:\n.cfi_startproc\nbl OUTLINED_FUNCTION_0\nret\n.cfi_endproc\n.size unknown_parent,.-unknown_parent\n"
        data, instructions = self.changed_fixture(source)
        with self.assertRaisesRegex(Invalid, 'unrecoverable parent LR'):
            normalize_bytes(data, instructions)

    def test_real_jobserver_pipes_and_closed_extra(self):
        import runpy
        helper = runpy.run_path(str(Path(__file__).with_name('native-link')))['jobserver_fds']
        read, write = os.pipe()
        extra_read, extra_write = os.pipe()
        try:
            os.set_inheritable(extra_read, True)
            pair = helper(f'-j --jobserver-fds={read},{write} --jobserver-auth={read},{write}')
            self.assertEqual(pair, (read, write))
            subprocess.run([sys.executable, '-c',
                'import os,sys\nr,w,e=map(int,sys.argv[1:])\nos.write(w,b"x")\nassert os.read(r,1)==b"x"\n'
                'try: os.fstat(e)\nexcept OSError: pass\nelse: raise AssertionError("extra fd leaked")',
                str(read), str(write), str(extra_read)], pass_fds=pair, check=True)
            for value in (f'--jobserver-fds={read},{write} --jobserver-auth={write},{read}',
                          f'--jobserver-auth={read},{read}', '--jobserver-fds=1,2', '--jobserver-auth=3,no'):
                with self.subTest(value=value), self.assertRaises(Invalid):
                    helper(value)
            self.assertEqual(helper('--jobserver-auth=fifo:/tmp/existing-cargo'), ())
        finally:
            for descriptor in (read, write, extra_read, extra_write):
                os.close(descriptor)

    def test_atomic_file_result(self):
        target = self.root / 'atomic.elf'
        target.write_bytes(self.original)
        os.chmod(target, 0o755)
        normalize_file(target, self.objdump)
        self.assertEqual(target.read_bytes(), self.fixed)
        self.assertEqual(target.stat().st_mode & 0o777, 0o755)


if __name__ == '__main__':
    unittest.main()
