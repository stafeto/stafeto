# SPDX-License-Identifier: Apache-2.0
"""Fail-closed AArch64 outliner CFI repair; executable bytes never change."""
from dataclasses import dataclass, field
from pathlib import Path
import copy
import os
import re
import struct
import subprocess
import tempfile


class Invalid(ValueError):
    pass


class SpaceShortage(Invalid):
    """Validated CFI cannot fit the original read-only envelope."""

    pass


def require(condition, message):
    if not condition:
        raise Invalid(message)


def uleb(data, at, signed=False):
    value = shift = 0
    while True:
        require(at < len(data) and shift < 70, "invalid LEB128")
        byte = data[at]
        at += 1
        value |= (byte & 127) << shift
        shift += 7
        if byte < 128:
            if signed and byte & 64:
                value -= 1 << shift
            return value, at


def leb(value):
    require(value >= 0, "negative ULEB128")
    result = bytearray()
    while True:
        byte = value & 127
        value >>= 7
        result.append(byte | (128 if value else 0))
        if not value:
            return bytes(result)


def sleb(value):
    result = bytearray()
    while True:
        byte = value & 127
        value >>= 7
        done = (value == 0 and not byte & 64) or (value == -1 and byte & 64)
        result.append(byte if done else byte | 128)
        if done:
            return bytes(result)


@dataclass(eq=True)
class Row:
    cfa: tuple = (31, 0)
    registers: dict = field(default_factory=dict)

    def rule(self, register):
        return self.registers.get(register, ("same", register))


def events(program, start, code_alignment):
    """Keep non-location operations verbatim, indexed by their instruction PC."""
    at = 0
    pc = start
    result = []
    while at < len(program):
        begin = at
        opcode = program[at]
        at += 1
        if opcode & 0xc0 == 0x40:
            pc += (opcode & 63) * code_alignment
            continue
        if opcode in (2, 3, 4):
            size = {2: 1, 3: 2, 4: 4}[opcode]
            require(at + size <= len(program), "truncated CFI location")
            pc += int.from_bytes(program[at:at + size], "little") * code_alignment
            at += size
            continue
        if opcode & 0xc0 == 0x80:
            _, at = uleb(program, at)
        elif opcode & 0xc0 == 0xc0 or opcode in (0, 10, 11):
            pass
        elif opcode in (5, 9, 12):
            _, at = uleb(program, at)
            _, at = uleb(program, at)
        elif opcode in (6, 7, 8, 13, 14, 19):
            _, at = uleb(program, at, signed=opcode == 19)
        else:
            raise Invalid(f"unsupported targeted CFI opcode {opcode:#x}")
        if opcode:
            result.append((pc, bytes(program[begin:at])))
    return result


def apply(row, operation, initial, saved, data_alignment):
    row = copy.deepcopy(row)
    opcode = operation[0]
    at = 1
    if opcode & 0xc0 == 0x80:
        offset, _ = uleb(operation, at)
        row.registers[opcode & 63] = ("offset", offset * data_alignment)
    elif opcode & 0xc0 == 0xc0:
        register = opcode & 63
        if register in initial.registers:
            row.registers[register] = initial.registers[register]
        else:
            row.registers.pop(register, None)
    elif opcode == 10:
        saved.append(copy.deepcopy(row))
    elif opcode == 11:
        require(saved, "unbalanced CFI restore_state")
        row = saved.pop()
    elif opcode in (5, 9, 12):
        first, at = uleb(operation, at)
        second, _ = uleb(operation, at)
        if opcode == 5:
            row.registers[first] = ("offset", second * data_alignment)
        elif opcode == 9:
            row.registers[first] = ("register", second)
        else:
            row.cfa = (first, second)
    elif opcode in (6, 7, 8, 13, 14, 19):
        value, _ = uleb(operation, at, signed=opcode == 19)
        if opcode == 6:
            if value in initial.registers:
                row.registers[value] = initial.registers[value]
            else:
                row.registers.pop(value, None)
        elif opcode == 7:
            row.registers[value] = ("undefined",)
        elif opcode == 8:
            row.registers[value] = ("same", value)
        elif opcode == 13:
            row.cfa = (value, row.cfa[1])
        elif opcode == 19:
            row.cfa = (row.cfa[0], value * data_alignment)
        else:
            row.cfa = (row.cfa[0], value)
    else:
        raise Invalid("unsupported CFI state operation")
    return row


def rows(event_list, initial, data_alignment):
    row = copy.deepcopy(initial)
    saved = []
    result = []
    for pc, operation in event_list:
        row = apply(row, operation, initial, saved, data_alignment)
        result.append((pc, copy.deepcopy(row)))
    require(not saved, "unbalanced CFI remembered row")
    return result


def row_at(event_list, pc, initial, data_alignment):
    result = copy.deepcopy(initial)
    for at, row in rows(event_list, initial, data_alignment):
        if at > pc:
            break
        result = row
    return result


def encode_events(event_list, start, alignment):
    pc = start
    result = bytearray()
    for at, operation in event_list:
        require(at >= pc and (at - pc) % alignment == 0, "invalid CFI PC order")
        delta = (at - pc) // alignment
        if delta:
            if delta < 64:
                result.append(0x40 | delta)
            elif delta < 256:
                result.extend(bytes([2, delta]))
            elif delta < 65536:
                result.extend(bytes([3]) + struct.pack('<H', delta))
            else:
                require(delta < 2 ** 32, "CFI PC advance overflows")
                result.extend(bytes([4]) + struct.pack('<I', delta))
        pc = at
        result.extend(operation)
    return bytes(result)


@dataclass
class Section:
    index: int
    name: str
    address: int
    offset: int
    size: int
    flags: int
    kind: int
    link: int
    entry_size: int


@dataclass
class Cie:
    offset: int
    raw: bytes
    code: int
    data: int
    initial: Row


@dataclass
class Fde:
    offset: int
    raw: bytes
    cie: Cie
    start: int
    size: int
    program: bytes


class Elf:
    def __init__(self, data):
        self.data = data
        require(len(data) >= 64 and data[:7] == b'\x7fELF\x02\x01\x01', "not ELF64 little-endian")
        require(struct.unpack_from('<HH', data, 16) == (2, 183), "not an AArch64 executable")
        self.program_offset, self.section_offset = struct.unpack_from('<QQ', data, 32)
        self.program_size, self.program_count, self.section_size, count, names_index = struct.unpack_from('<HHHHH', data, 54)
        require(self.program_size == 56 and self.section_size == 64 and names_index < count, "unsupported ELF tables")
        require(self.section_offset + count * 64 <= len(data), "section table outside ELF")
        require(self.program_offset + self.program_count * 56 <= len(data), "program table outside ELF")
        raw = [struct.unpack_from('<IIQQQQIIQQ', data, self.section_offset + i * 64) for i in range(count)]
        names_header = raw[names_index]
        names = self.slice(names_header[4], names_header[5])
        self.sections = {}
        for i, item in enumerate(raw):
            require(item[0] < len(names), "invalid section name")
            end = names.find(b'\0', item[0])
            require(end >= 0, "unterminated section name")
            name = names[item[0]:end].decode('ascii')
            require(name not in self.sections or not name, "duplicate ELF section")
            section = Section(i, name, item[3], item[4], item[5], item[2], item[1], item[6], item[9])
            if section.kind != 8:
                self.slice(section.offset, section.size)
            self.sections[name] = section
        self.headers = [struct.unpack_from('<IIQQQQQQ', data, self.program_offset + i * 56) for i in range(self.program_count)]
        self.symbols = {}
        sym = self.sections.get('.symtab')
        require(sym is not None and sym.entry_size == 24, "native CFI verification needs symbols")
        require(sym.link < count and sym.size % 24 == 0, "invalid symbol table extent/link")
        strings_header = raw[sym.link]
        strings = self.slice(strings_header[4], strings_header[5])
        for at in range(sym.offset, sym.offset + sym.size, 24):
            name, info, _, _, value, size = struct.unpack_from('<IBBHQQ', data, at)
            require(name < len(strings), "invalid symbol name")
            end = strings.find(b'\0', name)
            require(end >= 0, "unterminated symbol name")
            symbol = strings[name:end].decode('utf8')
            if info & 15 == 2 and size:
                self.symbols.setdefault(value, []).append((symbol, size))
        self.frame = self.sections.get('.eh_frame')
        self.header = self.sections.get('.eh_frame_hdr')

    def slice(self, offset, size):
        require(0 <= offset <= len(self.data) and 0 <= size <= len(self.data) - offset, "ELF range outside file")
        return self.data[offset:offset + size]

    def address_bytes(self, address, size):
        matches = [s for s in self.sections.values() if s.flags & 2 and s.kind != 8 and s.address <= address and address + size <= s.address + s.size]
        require(len(matches) == 1, "ambiguous executable address")
        section = matches[0]
        return self.slice(section.offset + address - section.address, size)

    def records(self):
        require(self.frame and self.header, "outlined native ELF needs EH metadata")
        frame = self.slice(self.frame.offset, self.frame.size)
        at = 0
        cies = {}
        result = []
        terminated = False
        while at < len(frame):
            require(at + 4 <= len(frame), "truncated EH frame")
            size = struct.unpack_from('<I', frame, at)[0]
            if not size:
                require(not any(frame[at:]), "data after EH terminator")
                terminated = True
                break
            require(size != 0xffffffff and size >= 4 and at + size + 4 <= len(frame), "unsupported EH record")
            raw = frame[at:at + size + 4]
            reference = struct.unpack_from('<I', raw, 4)[0]
            if reference == 0:
                require(raw[8] == 1, "unsupported CIE version")
                end = raw.find(b'\0', 9)
                require(end >= 0 and raw[9:end] == b'zR', "unsupported CIE augmentation")
                code, cursor = uleb(raw, end + 1)
                data, cursor = uleb(raw, cursor, signed=True)
                register, cursor = uleb(raw, cursor)
                length, cursor = uleb(raw, cursor)
                require(code > 0 and data < 0 and register == 30 and length == 1 and raw[cursor] == 0x1b, "unsupported CIE encoding")
                cursor += length
                initial = row_at(events(raw[cursor:], 0, code), 0, Row(), data)
                cie = Cie(at, raw, code, data, initial)
                cies[at] = cie
                result.append(cie)
            else:
                cie = cies.get(at + 4 - reference)
                require(cie is not None and len(raw) >= 17, "invalid FDE CIE reference")
                start = self.frame.address + at + 8 + struct.unpack_from('<i', raw, 8)[0]
                span = struct.unpack_from('<I', raw, 12)[0]
                augmentation, cursor = uleb(raw, 16)
                require(augmentation == 0 and span > 0, "unsupported FDE augmentation/range")
                result.append(Fde(at, raw, cie, start, span, raw[cursor:]))
            at += size + 4
        require(terminated, "missing EH terminator")
        return result


def disassemble(path, objdump):
    text = subprocess.check_output([str(objdump), '-d', '--no-show-raw-insn', str(path)], text=True)
    instructions = {}
    for line in text.splitlines():
        match = re.match(r'^\s*([0-9a-f]+):\s+([a-z0-9.]+)\s*(.*)$', line)
        if match:
            address = int(match[1], 16)
            instructions[address] = (match[2], match[3].split('//', 1)[0].strip())
    return instructions


def branch_targets(instructions):
    result = set()
    for mnemonic, operands in instructions.values():
        if mnemonic in ('b', 'bl', 'cbz', 'cbnz', 'tbz', 'tbnz') or mnemonic.startswith('b.'):
            match = re.search(r'0x([0-9a-f]+)', operands)
            require(match is not None, "unrecognized direct branch")
            result.add(int(match[1], 16))
    return result


def written_registers(mnemonic, operands):
    """Explicit destinations, including paired loads and memory writeback."""
    no_write = {'nop', 'cmp', 'cmn', 'tst', 'ret', 'b', 'br', 'cbz', 'cbnz',
                'tbz', 'tbnz', 'dmb', 'dsb', 'isb', 'clrex'}
    one_write = {'add', 'adds', 'sub', 'subs', 'bics', 'and', 'ands', 'orr', 'eor', 'bic', 'mov', 'movk',
                 'movz', 'movn', 'adr', 'adrp', 'lsl', 'lsr', 'asr', 'ubfx', 'bfxil',
                 'sbfiz', 'ubfiz', 'extr', 'csel', 'cset', 'cinc', 'csinc', 'csinv',
                 'cneg', 'madd', 'umaddl', 'smaddl', 'mul', 'mvn', 'neg', 'negs',
                 'ldr', 'ldrb', 'ldrh', 'ldrsw', 'ldur', 'ldurb', 'ldurh', 'ldar',
                 'ldarb', 'ldarh', 'ldaxr', 'ldxr', 'stlxr', 'stxr', 'mrs'}
    stores = {'str', 'strb', 'strh', 'stur', 'sturb', 'sturh', 'stp', 'stlr', 'stlrb'}
    paired = {'ldp', 'ldpsw', 'ldxp', 'ldaxp'}
    destinations = []
    if mnemonic == 'bl':
        destinations = ['x30']
    elif mnemonic in one_write:
        destinations = operands.split(',', 1)[:1]
    elif mnemonic in paired:
        destinations = operands.split(',')[:2]
    else:
        require(mnemonic in no_write or mnemonic in stores or mnemonic.startswith('b.'),
                f"unproved instruction destinations: {mnemonic}")
    if '!' in operands or re.search(r'\],\s*#', operands):
        match = re.search(r'\[(x\d+|sp)', operands)
        require(match is not None, "unrecognized memory writeback")
        destinations.append(match[1])
    result = set()
    for destination in destinations:
        destination = destination.strip()
        if destination == 'sp':
            result.add(31)
        elif match := re.fullmatch(r'[xw](\d+)', destination):
            result.add(int(match[1]))
    return result


def preserved_register(body, register):
    """Only audited straight-line leaf operations may carry a volatile LR copy."""
    for mnemonic, operands in body:
        require(mnemonic not in ('b', 'bl', 'br', 'blr', 'cbz', 'cbnz', 'tbz', 'tbnz')
                and not mnemonic.startswith('b.'), "saved LR helper is not straight-line leaf")
        require(not ({register, 31} & written_registers(mnemonic, operands)),
                "outlined helper destroys saved LR register or SP")


def compact_changed_events(event_list, fde):
    """Remove only proved redundant LR rules in an already repaired FDE."""
    kept = []
    row = copy.deepcopy(fde.cie.initial)
    saved = []
    for pc, operation in event_list:
        following = apply(row, operation, fde.cie.initial, saved, fde.cie.data)
        if not (operation[0] == 0x9e and following == row):
            kept.append((pc, operation))
        row = following
    require(not saved, 'compaction encountered unbalanced remembered row')
    result = []
    index = 0
    while index < len(kept):
        if (index + 2 < len(kept) and kept[index][1] == b'\x0a' and
                kept[index + 1][0] == kept[index][0] and
                kept[index + 1][1][:2] == b'\x09\x1e' and kept[index + 2][1] == b'\x0b'):
            begin, end = kept[index][0], kept[index + 2][0]
            before = row_at(kept, begin - 1, fde.cie.initial, fde.cie.data)
            if 30 not in before.registers and 30 not in fde.cie.initial.registers:
                result.extend([kept[index + 1], (end, b'\xde')])
                index += 3
                continue
        result.append(kept[index])
        index += 1
    points = set(range(fde.start, fde.start + fde.size, 4))
    points.update(pc for pc, _ in event_list)
    points.update(pc for pc, _ in result)
    for pc in points:
        require(row_at(event_list, pc, fde.cie.initial, fde.cie.data) ==
                row_at(result, pc, fde.cie.initial, fde.cie.data),
                'compaction changed a complete CFI row')
    return result


def prove_lr_store(fde, call_pc, after, instructions, targets):
    """Track the exact straight-line entry frame and all overlapping stores."""
    require(after.cfa[0] == 31 and after.rule(30)[0] == 'offset',
            'unsupported delayed LR row')
    sp = 0
    saved = None
    for pc in range(fde.start, call_pc, 4):
        require(pc in instructions, 'missing caller prologue instruction')
        mnemonic, operands = instructions[pc]
        require(mnemonic not in ('b', 'bl', 'br', 'blr', 'ret', 'cbz', 'cbnz', 'tbz', 'tbnz', 'svc')
                and not mnemonic.startswith('b.'), f'caller LR provenance crosses control flow at {pc:#x}, entry {fde.start:#x}, call {call_pc:#x}')
        require(pc == fde.start or pc not in targets, 'branch into caller LR prologue')
        destinations = written_registers(mnemonic, operands)
        require(30 not in destinations, 'caller entry LR was overwritten before save')
        adjustment = re.fullmatch(r'sp, sp, #0x([0-9a-f]+)', operands)
        if mnemonic in ('add', 'sub') and adjustment:
            sp += int(adjustment[1], 16) * (1 if mnemonic == 'add' else -1)
            require(saved is None, 'SP changed after proved LR store')
            continue
        stores = {'str', 'strb', 'strh', 'stur', 'sturb', 'sturh', 'stp', 'stlr', 'stlrb'}
        if mnemonic not in stores:
            require(31 not in destinations, 'unproved caller SP change')
            continue
        memory = re.fullmatch(r'(.*), \[sp(?:, #(-?0x[0-9a-f]+))?\](!)?(?:, #(-?0x[0-9a-f]+))?', operands)
        if memory is None:
            require(saved is None, 'unknown store may alias saved LR cell')
            require(31 not in destinations, 'unknown caller store writeback')
            continue
        names = [name.strip() for name in memory[1].split(',')]
        require(len(names) == (2 if mnemonic == 'stp' else 1), 'invalid caller store operands')
        offset = int(memory[2] or '0', 0)
        address = sp + offset
        if memory[3]:
            sp += offset
            require(saved is None, 'SP changed after proved LR store')
        widths = []
        for name in names:
            if mnemonic.endswith('b'):
                width = 1
            elif mnemonic.endswith('h'):
                width = 2
            else:
                match = re.fullmatch(r'([xwdqsbh])(?:\d+|zr)', name)
                require(match is not None, 'unproved caller store width')
                width = {'x': 8, 'w': 4, 'd': 8, 'q': 16, 's': 4, 'b': 1, 'h': 2}[match[1]]
            widths.append(width)
        for name, width in zip(names, widths):
            if saved is not None:
                require(address + width <= saved[1] or address >= saved[1] + 8,
                        'intervening store overlaps saved LR cell')
            if name == 'x30':
                saved = (pc + 4, address)
            address += width
        if memory[4]:
            sp += int(memory[4], 0)
            require(saved is None, 'post-index SP change after proved LR store')
    require(fde.cie.initial.cfa == (31, 0) and sp + after.cfa[1] == 0,
            'caller actual SP disagrees with original CFA')
    require(saved is not None and saved[1] == sp + after.cfa[1] + after.rule(30)[1],
            'genuine LR store disagrees with original saved cell')
    original = events(fde.program, fde.start, fde.cie.code)
    publish_row = row_at(original, saved[0], fde.cie.initial, fde.cie.data)
    require(publish_row.cfa == after.cfa and publish_row.rule(30) == ('same', 30),
            'caller LR publication has unsupported CFA or existing LR rule')
    return saved[0]


def repair_programs(elf, records, instructions):
    fdes = {record.start: record for record in records if isinstance(record, Fde)}
    helpers = {}
    for address, symbols in elf.symbols.items():
        outlined = [(name, size) for name, size in symbols if name.startswith('OUTLINED_FUNCTION_')]
        if outlined:
            require(len(set(size for _, size in outlined)) == 1, "ambiguous helper extent")
            size = outlined[0][1]
            require(size % 4 == 0 and address in fdes and fdes[address].size == size,
                    "helper lacks exact FDE extent")
            helpers[address] = [(pc, instructions.get(pc)) for pc in range(address, address + size, 4)]
            require(all(item is not None for _, item in helpers[address]), "helper instruction missing")
    changed = {}
    verification = []
    targets = branch_targets(instructions)
    for address, body in helpers.items():
        fde = fdes[address]
        initial = fde.cie.initial
        require(initial.cfa == (31, 0) and initial.rule(30) == ('same', 30),
                "unsupported initial helper CFA/LR")
        original = events(fde.program, address, fde.cie.code)
        stack = [(pc, op) for pc, op in body if 'sp' in op[1] and
                 ((op[0] in ('sub', 'add', 'mov', 'and') and op[1].startswith('sp,')) or
                  '!' in op[1] or re.search(r'\],\s*#', op[1]))]
        if len(stack) == 1 and stack[0][1][0] == 'add':
            # A helper may release a portion of the caller frame before returning.
            addition_pc, (_, operands) = stack[0]
            addition = re.fullmatch(r'sp, sp, #0x([0-9a-f]+)', operands)
            require(addition and addition_pc == address + fde.size - 8 and
                    body[-1][1] == ('ret', ''), "unsupported borrowed-SP epilogue")
            delta = int(addition[1], 16)
            require(delta > 0 and delta % 16 == 0, "invalid borrowed-SP delta")
            for _, (mnemonic, operands) in body[:-2]:
                require(mnemonic == 'mov' and
                        re.fullmatch(r'x[0-7], x(?:19|2[0-8])', operands),
                        "unproved borrowed-SP argument move")
            require(not any(pc in targets for pc, _ in body[1:]), "branch into borrowed-SP interior")
            incoming = []
            for pc, (mnemonic, operands) in instructions.items():
                if mnemonic not in ('b', 'bl', 'cbz', 'cbnz', 'tbz', 'tbnz') and not mnemonic.startswith('b.'):
                    continue
                target = re.search(r'0x([0-9a-f]+)', operands)
                if target is None or int(target[1], 16) != address:
                    continue
                require(mnemonic == 'bl', "borrowed-SP helper has a non-call entry")
                matching = [r for r in fdes.values() if r.start <= pc and pc + 4 < r.start + r.size]
                require(len(matching) == 1, "borrowed-SP caller lacks exact continuation FDE")
                caller = matching[0]
                caller_events = events(caller.program, caller.start, caller.cie.code)
                before = row_at(caller_events, pc, caller.cie.initial, caller.cie.data)
                after = row_at(caller_events, pc + 4, caller.cie.initial, caller.cie.data)
                require(before.cfa[0] == 31 and after.cfa[0] == 31 and
                        before.cfa[1] - after.cfa[1] == delta and
                        before.registers == after.registers and before.rule(30)[0] == 'offset',
                        "borrowed-SP caller row/delta disagrees")
                incoming.append(pc)
            require(incoming, "borrowed-SP helper has no proved call entry")
            after_add = copy.deepcopy(initial)
            after_add.cfa = (31, -delta)
            require(-delta % fde.cie.data == 0, 'borrowed-SP delta does not match CIE factor')
            desired = [(addition_pc + 4, b'\x13' + sleb(-delta // fde.cie.data))]
            expected = [initial if pc <= addition_pc else after_add for pc, _ in body]
            current = [row_at(original, pc, initial, fde.cie.data) for pc, _ in body]
            if current != expected:
                require(all(row == initial for row in current), "unknown borrowed-SP CFI mismatch")
                changed[fde.offset] = desired
        elif stack:
            require(len(stack) == 2 and stack[0][0] == address and
                    stack[0][1] == ('str', 'x30, [sp, #-0x10]!') and
                    stack[1][0] == address + fde.size - 8 and
                    stack[1][1] == ('ldr', 'x30, [sp], #0x10') and
                    body[-1][1] == ('ret', ''), "unsupported outlined stack frame")
            require(not any(pc in targets for pc, _ in body[1:]), "branch into helper frame interior")
            require(not any(op[0] in ('b', 'br', 'blr', 'cbz', 'cbnz', 'tbz', 'tbnz', 'svc', 'paciasp', 'autiasp') or
                            op[0].startswith('b.') for _, op in body), "unsupported helper control flow")
            require(not any(op[0] != 'bl' and 30 in written_registers(*op)
                            for _, op in body[1:-2]), "unexpected helper LR write")
            require((-16) % fde.cie.data == 0, "helper LR offset not representable")
            middle = copy.deepcopy(initial)
            middle.cfa = (31, 16)
            middle.registers[30] = ('offset', -16)
            begin = address + 4
            end = stack[1][0] + 4
            desired = [(begin, b'\x0a'), (begin, b'\x0e' + leb(16)),
                       (begin, bytes([0x80 | 30]) + leb(-16 // fde.cie.data)),
                       (end, b'\x0b')]
            current = [row_at(original, pc, initial, fde.cie.data) for pc, _ in body]
            expected = [middle if begin <= pc < end else initial for pc, _ in body]
            if current != expected:
                # Only the known LLVM22 bad rows or a previously repaired program are accepted.
                require(all(row == middle for row in current), "unknown helper CFI mismatch")
                changed[fde.offset] = desired
            verification.append((fde, desired, body))
        else:
            require(not any(op[0] in ('bl', 'blr', 'br', 'svc', 'paciasp', 'autiasp')
                            for _, op in body), "unproved leaf helper unwind")
            require(not any({30, 31} & written_registers(*op) for _, op in body),
                    "leaf helper changes LR or SP")
            require(all(row_at(original, pc, initial, fde.cie.data) == initial for pc, _ in body),
                    "unexpected leaf helper CFI")
    # Publish a genuine caller LR store before entering a spill helper.
    for call_pc, (mnemonic, operands) in instructions.items():
        if mnemonic != 'bl':
            continue
        target = re.search(r'0x([0-9a-f]+)', operands)
        if target is None or int(target[1], 16) not in helpers:
            continue
        matching = [fde for fde in fdes.values() if fde.start <= call_pc and call_pc + 4 <= fde.start + fde.size]
        require(len(matching) == 1, 'outlined caller lacks exact FDE')
        caller = matching[0]
        original = events(caller.program, caller.start, caller.cie.code)
        before = row_at(original, call_pc, caller.cie.initial, caller.cie.data)
        after = row_at(original, call_pc + 4, caller.cie.initial, caller.cie.data)
        if before.rule(30) != ('same', 30) or after.rule(30)[0] != 'offset':
            continue
        publish = prove_lr_store(caller, call_pc, after, instructions, targets)
        offset = after.rule(30)[1]
        require(offset % caller.cie.data == 0 and offset // caller.cie.data >= 0,
                'caller LR offset does not match CIE factor')
        operation = b'\x9e' + leb(offset // caller.cie.data)
        repaired = sorted(original + [(publish, operation)], key=lambda event: event[0])
        for pc in range(caller.start, caller.start + caller.size, 4):
            expected = row_at(original, pc, caller.cie.initial, caller.cie.data)
            if publish <= pc <= call_pc:
                expected.registers[30] = after.rule(30)
            require(row_at(repaired, pc, caller.cie.initial, caller.cie.data) == expected,
                    'caller non-target row changed during LR publication')
        require(caller.offset not in changed, 'overlapping caller CFI repairs')
        changed[caller.offset] = repaired

    # A helper's same-value rules must preserve the caller registers they feed.
    for call_pc, (mnemonic, operands) in instructions.items():
        if mnemonic != 'bl':
            continue
        target = re.search(r'0x([0-9a-f]+)', operands)
        if target is None or int(target[1], 16) not in helpers:
            continue
        address = int(target[1], 16)
        matching = [fde for fde in fdes.values() if fde.start <= call_pc < fde.start + fde.size]
        require(len(matching) == 1, 'helper register custody lacks caller FDE')
        caller = matching[0]
        caller_events = changed.get(caller.offset, events(caller.program, caller.start, caller.cie.code))
        row = row_at(caller_events, call_pc, caller.cie.initial, caller.cie.data)
        writes = set().union(*(written_registers(*operation) for _, operation in helpers[address]))
        for register in range(19, 30):
            require(register not in writes or
                    (row.rule(register)[0] == 'offset' and row.cfa[0] != register),
                    'helper overwrites an unrecoverable caller callee-saved register')

    # Every actual call, rather than every symbol spelling, is audited.
    site_ranges = {}
    for pc, (mnemonic, operands) in instructions.items():
        if mnemonic != 'bl':
            continue
        target = re.search(r'0x([0-9a-f]+)', operands)
        if target is None or int(target[1], 16) not in helpers:
            continue
        before = instructions.get(pc - 4)
        after = instructions.get(pc + 4)
        save = re.fullmatch(r'x(\d+), x30', before[1]) if before and before[0] == 'mov' else None
        restore = re.fullmatch(r'x30, x(\d+)', after[1]) if after and after[0] == 'mov' else None
        if not save:
            require(not (before and before[0] == 'str' and before[1] == 'x30, [sp, #-0x10]!'
                         and after and after[0] == 'ldr' and after[1] == 'x30, [sp], #0x10'),
                    "unsupported transient caller SP frame")
            continue
        require(restore and save[1] == restore[1], "mismatched caller LR save/restore")
        register = int(save[1])
        require(register < 30 and pc not in targets and pc + 4 not in targets,
                "branch into transient LR save or invalid register")
        matching = [record for record in fdes.values() if record.start <= pc - 4 and pc + 8 <= record.start + record.size]
        require(len(matching) == 1, "caller lacks unambiguous FDE")
        fde = matching[0]
        original = changed.get(fde.offset, events(fde.program, fde.start, fde.cie.code))
        start_row = row_at(original, pc - 4, fde.cie.initial, fde.cie.data)
        at_call = row_at(original, pc, fde.cie.initial, fde.cie.data)
        at_restore = row_at(original, pc + 4, fde.cie.initial, fde.cie.data)
        if start_row.rule(30)[0] == 'offset':
            require(at_call == start_row and at_restore == start_row, "changed existing stack LR row")
            continue
        require(start_row.rule(30) == ('same', 30) and register != start_row.cfa[0],
                "unsupported transient caller LR/CFA row")
        helper_fde = fdes[int(target[1], 16)]
        require(helper_fde.cie.initial.rule(register) == ('same', register),
                "saved LR register has no recoverable helper rule")
        preserved_register([operation for _, operation in helpers[int(target[1], 16)]], register)
        expected = copy.deepcopy(start_row)
        expected.registers[30] = ('register', register)
        require(at_call in (start_row, expected) and at_restore in (start_row, expected),
                "unknown caller CFI overlay")
        require(row_at(original, pc + 8, fde.cie.initial, fde.cie.data) == start_row,
                "original caller row changes at restoration")
        if at_call == expected and at_restore == expected:
            continue
        require(not any(pc <= at < pc + 8 for at, _ in original),
                "existing CFI operations overlap LR interval")
        site_ranges.setdefault(fde.offset, []).append((pc, pc + 8, register, start_row))
    for offset, intervals in site_ranges.items():
        fde = next(record for record in fdes.values() if record.offset == offset)
        original = changed.get(fde.offset, events(fde.program, fde.start, fde.cie.code))
        extra = []
        intervals.sort()
        require(all(a[1] <= b[0] for a, b in zip(intervals, intervals[1:])), "overlapping LR intervals")
        for begin, end, register, row in intervals:
            extra.extend([(begin, b'\x0a'), (begin, b'\x09' + leb(30) + leb(register)), (end, b'\x0b')])
        # Restore overlays before original operations at the same final PC.
        combined = sorted([(pc, 1, i, op) for i, (pc, op) in enumerate(original)] +
                          [(pc, 0 if op == b'\x0b' else 2, i, op) for i, (pc, op) in enumerate(extra)])
        repaired = [(pc, op) for pc, _, _, op in combined]
        for pc in range(fde.start, fde.start + fde.size, 4):
            expected = row_at(original, pc, fde.cie.initial, fde.cie.data)
            for begin, end, register, _ in intervals:
                if begin <= pc < end:
                    expected.registers[30] = ('register', register)
            require(row_at(repaired, pc, fde.cie.initial, fde.cie.data) == expected,
                    "caller complete CFI row was not preserved")
        changed[offset] = repaired
    for fde in fdes.values():
        if fde.offset in changed:
            changed[fde.offset] = compact_changed_events(changed[fde.offset], fde)
    return changed, helpers



def validate_header(elf, records):
    require(elf.header is not None and elf.frame is not None, "missing EH header/frame")
    header = elf.slice(elf.header.offset, elf.header.size)
    require(len(header) >= 12 and header[:4] == b'\x01\x1b\x03\x3b',
            "unsupported EH header encoding")
    pointer = elf.header.address + 4 + struct.unpack_from('<i', header, 4)[0]
    require(pointer == elf.frame.address, "EH header frame pointer disagrees")
    fdes = [record for record in records if isinstance(record, Fde)]
    starts = [record.start for record in fdes]
    require(len(set(starts)) == len(starts), "duplicate FDE start")
    by_start = {record.start: record for record in fdes}
    count = struct.unpack_from('<I', header, 8)[0]
    require(12 + count * 8 == len(header) and count == len(fdes),
            "EH header count disagrees with FDEs")
    previous = -1
    for i in range(count):
        pc, reference = struct.unpack_from('<ii', header, 12 + i * 8)
        start = elf.header.address + pc
        require(start > previous, "EH header PC entries not strictly ordered")
        require(start in by_start and
                elf.header.address + reference == elf.frame.address + by_start[start].offset,
                "EH header disagrees with FDE identity")
        previous = start
    return header


def repack(elf, records, changed):
    rebuilt = bytearray()
    positions = {}
    cies = {}
    fdes = {}
    for record in records:
        position = len(rebuilt)
        positions[record.offset] = position
        if isinstance(record, Cie):
            cies[record.offset] = position
            rebuilt.extend(record.raw)
        else:
            raw = bytearray(record.raw)
            if record.offset in changed:
                program = encode_events(changed[record.offset], record.start, record.cie.code)
                raw = bytearray(record.raw[:17] + program)
                while len(raw) % 4:
                    raw.append(0)
                struct.pack_into('<I', raw, 0, len(raw) - 4)
            struct.pack_into('<I', raw, 4, position + 4 - cies[record.cie.offset])
            displacement = record.start - (elf.frame.address + position + 8)
            require(-(2 ** 31) <= displacement < 2 ** 31, "FDE PC reference overflow")
            struct.pack_into('<i', raw, 8, displacement)
            rebuilt.extend(raw)
            fdes[record.start] = (record, position)
    rebuilt.extend(b'\0' * 4)
    used = sum(len(record.raw) for record in records) + 4
    reserved = elf.frame.size - used
    require(0 <= reserved <= 512, 'unsupported EH zero reservation')
    # A linker-reserved envelope remains allocated in its entirety.
    if reserved and len(rebuilt) <= elf.frame.size:
        rebuilt.extend(b'\0' * (elf.frame.size - len(rebuilt)))
    # No allocated address, text byte, writable byte or page allocation may move.
    old_end = elf.frame.address + elf.frame.size
    new_end = elf.frame.address + len(rebuilt)
    require(new_end >= old_end, "unexpected EH shrink")
    following = [s.address for s in elf.sections.values() if s.flags & 2 and s.address >= old_end and s.index != elf.frame.index]
    require(following and old_end <= min(following), "EH input overlaps another section")
    matching = [(i, h) for i, h in enumerate(elf.headers) if h[0] == 1 and h[1] == 4 and h[3] <= elf.frame.address and old_end == h[3] + h[6]]
    require(len(matching) == 1, "EH section is not final read-only segment data")
    index, header = matching[0]
    require(header[5] == header[6], "EH read-only file/memory sizes disagree")
    if (new_end + 4095) // 4096 != (old_end + 4095) // 4096:
        require(0 < new_end - old_end <= 512, "EH repair exceeds bounded reservation")
        raise SpaceShortage("EH repair changes read-only page budget")
    require(new_end <= min(following), "EH repair overlaps another section")
    destination_end = elf.frame.offset + len(rebuilt)
    require(destination_end <= len(elf.data) and not any(elf.data[elf.frame.offset + elf.frame.size:destination_end]),
            "EH repair needs unavailable zero padding")
    result = bytearray(elf.data)
    result[elf.frame.offset:destination_end] = rebuilt
    struct.pack_into('<Q', result, elf.section_offset + elf.frame.index * 64 + 32, len(rebuilt))
    growth = len(rebuilt) - elf.frame.size
    struct.pack_into('<QQ', result, elf.program_offset + index * 56 + 32, header[5] + growth, header[6] + growth)
    eh_header = validate_header(elf, records)
    require(eh_header[:4] == b'\x01\x1b\x03\x3b' and len(eh_header) >= 12, "unsupported EH header encoding")
    count = struct.unpack_from('<I', eh_header, 8)[0]
    require(12 + count * 8 == len(eh_header) and count == len(fdes), "EH header count disagrees with FDEs")
    old_by_start = {record.start: record for record in records if isinstance(record, Fde)}
    for i in range(count):
        pc, reference = struct.unpack_from('<ii', eh_header, 12 + i * 8)
        start = elf.header.address + pc
        require(start in fdes and elf.header.address + reference == elf.frame.address + old_by_start[start].offset,
                "EH header disagrees with FDE identity")
        displacement = elf.frame.address + fdes[start][1] - elf.header.address
        require(-(2 ** 31) <= displacement < 2 ** 31, "EH header reference overflow")
        struct.pack_into('<i', result, elf.header.offset + 16 + i * 8, displacement)
    repaired = Elf(bytes(result))
    check = repaired.records()
    validate_header(repaired, check)
    require(len(check) == len(records), "EH record count changed")
    for before, after in zip(records, check):
        require(type(before) is type(after), "EH record kinds changed")
        if isinstance(before, Cie):
            require(before.raw == after.raw, "CIE bytes changed")
        else:
            require(before.start == after.start and before.size == after.size and
                    before.cie.raw == after.cie.raw, "FDE identity changed")
            if before.offset not in changed:
                require(before.program == after.program, "unaffected CFI program changed")
    for name, section in elf.sections.items():
        if name in ('.eh_frame', '.eh_frame_hdr') or section.kind == 8:
            continue
        require(elf.slice(section.offset, section.size) == repaired.slice(section.offset, section.size),
                f"section bytes changed: {name}")
    return bytes(result)


def normalize_bytes(data, instructions):
    elf = Elf(data)
    if not any(name.startswith('OUTLINED_FUNCTION_') for symbols in elf.symbols.values() for name, _ in symbols):
        return data, {'helpers': 0, 'corrected_fdes': 0, 'growth': 0}
    records = elf.records()
    validate_header(elf, records)
    changed, helpers = repair_programs(elf, records, instructions)
    if not changed:
        return data, {'helpers': len(helpers), 'corrected_fdes': 0, 'growth': 0}
    result = repack(elf, records, changed)
    # Verify the finished program independently of whether it looked initially bad.
    repaired = Elf(result)
    again, _ = repair_programs(repaired, repaired.records(), instructions)
    require(not again, "CFI repair is not idempotent")
    return result, {'helpers': len(helpers), 'corrected_fdes': len(changed),
                    'growth': repaired.frame.size - elf.frame.size}


def normalize_file(path, objdump):
    path = Path(path)
    original = path.read_bytes()
    repaired, report = normalize_bytes(original, disassemble(path, objdump))
    if repaired != original:
        descriptor, temporary = tempfile.mkstemp(prefix=path.name + '.cfi-', dir=path.parent)
        try:
            with os.fdopen(descriptor, 'wb') as output:
                output.write(repaired)
                output.flush()
                os.fsync(output.fileno())
            os.chmod(temporary, path.stat().st_mode & 0o777)
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    return report
