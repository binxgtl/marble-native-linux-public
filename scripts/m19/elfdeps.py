#!/usr/bin/env python3
"""DT_NEEDED closure over an in-memory file set. Reads ELF64 little-endian only."""
import struct

SHT_DYNAMIC, DT_NEEDED = 6, 1
SECTION = '<IIQQQQIIQQ'


class ElfError(ValueError):
    pass


def needed(data):
    if data[:6] != b'\x7fELF\x02\x01':
        raise ElfError('not ELF64 little-endian')
    section_offset = struct.unpack_from('<Q', data, 40)[0]
    entry_size, count = struct.unpack_from('<HH', data, 58)
    if entry_size != struct.calcsize(SECTION) or section_offset + entry_size * count > len(data):
        raise ElfError('bad section table')
    sections = [struct.unpack_from(SECTION, data, section_offset + i * entry_size) for i in range(count)]
    names = []
    for section in sections:
        if section[1] != SHT_DYNAMIC:
            continue
        if section[6] >= count:
            raise ElfError('bad dynamic string link')
        strings = sections[section[6]][4]
        for i in range(section[5] // 16):
            tag, value = struct.unpack_from('<qQ', data, section[4] + i * 16)
            if tag == DT_NEEDED:
                end = data.find(b'\0', strings + value)
                if end < 0:
                    raise ElfError('unterminated DT_NEEDED')
                names.append(data[strings + value:end].decode())
    return names


def closure(seeds, files, library_dirs):
    """Return (resolved paths, unresolved sonames) for seeds inside files."""
    by_name = {}
    for directory in library_dirs:
        prefix = directory.rstrip('/') + '/'
        for path in files:
            if path.startswith(prefix) and '/' not in path[len(prefix):]:
                by_name.setdefault(path[len(prefix):], path)
    done, missing, pending = set(), set(), list(seeds)
    while pending:
        path = pending.pop()
        if path in done:
            continue
        if path not in files:
            missing.add(path)
            continue
        done.add(path)
        for name in needed(files[path]):
            if name in by_name:
                pending.append(by_name[name])
            else:
                missing.add(name)
    return sorted(done), sorted(missing)
