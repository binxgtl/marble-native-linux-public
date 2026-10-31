#!/usr/bin/env python3
"""Android boot image v3/v4 header, legacy-LZ4 ramdisk and newc CPIO readers.

Host-side and read-only. Real recovery images stay local; tests use synthetic images.
"""
import gzip
import struct
from dataclasses import dataclass

MAGIC = b'ANDROID!'
PAGE = 4096
LZ4_LEGACY = b'\x02\x21\x4c\x18'
LZ4_BLOCK_MAX = 8 << 20
NEWC_HEADER = 110
S_IFMT, S_IFREG, S_IFLNK = 0o170000, 0o100000, 0o120000


class ImageError(ValueError):
    pass


@dataclass(frozen=True)
class BootHeader:
    version: int
    kernel_size: int
    ramdisk_size: int
    os_version: str
    os_patch: str

    @property
    def ramdisk_offset(self):
        return PAGE + (self.kernel_size + PAGE - 1) // PAGE * PAGE


def decode_os_version(raw):
    version, level = raw >> 11, raw & 0x7ff
    a, b, c = (version >> 14) & 0x7f, (version >> 7) & 0x7f, version & 0x7f
    return f'{a}.{b}.{c}', f'{2000 + ((level >> 4) & 0x7f):04d}-{level & 0xf:02d}'


def encode_os_version(version, patch):
    a, b, c = (int(x) for x in version.split('.'))
    year, month = (int(x) for x in patch.split('-'))
    return ((a << 14 | b << 7 | c) << 11) | ((year - 2000) << 4 | month)


def parse_header(data):
    if len(data) < 48 or data[:8] != MAGIC:
        raise ImageError('not an Android boot image')
    version = struct.unpack_from('<I', data, 40)[0]
    if version not in (3, 4):
        raise ImageError(f'unsupported header version {version}')
    kernel, ramdisk, raw = struct.unpack_from('<3I', data, 8)
    os_version, os_patch = decode_os_version(raw)
    return BootHeader(version, kernel, ramdisk, os_version, os_patch)


def _lz4_block(src, limit):
    try:
        import lz4.block
    except ImportError:
        return _lz4_block_python(src, limit)
    try:
        return lz4.block.decompress(src, uncompressed_size=limit)
    except lz4.block.LZ4BlockError as error:
        raise ImageError(f'bad LZ4 block: {error}') from error


def _lz4_block_python(src, limit):
    out = bytearray()
    i, n = 0, len(src)
    while i < n:
        token = src[i]
        i += 1
        length = token >> 4
        if length == 15:
            while True:
                if i >= n:
                    raise ImageError('truncated LZ4 literal length')
                more = src[i]
                i += 1
                length += more
                if more != 255:
                    break
        if i + length > n:
            raise ImageError('truncated LZ4 literals')
        out += src[i:i + length]
        i += length
        if i == n:
            break
        if i + 2 > n:
            raise ImageError('truncated LZ4 offset')
        offset = src[i] | src[i + 1] << 8
        i += 2
        if offset == 0 or offset > len(out):
            raise ImageError('bad LZ4 offset')
        match = token & 15
        if match == 15:
            while True:
                if i >= n:
                    raise ImageError('truncated LZ4 match length')
                more = src[i]
                i += 1
                match += more
                if more != 255:
                    break
        match += 4
        for _ in range(match):
            out.append(out[-offset])
        if len(out) > limit:
            raise ImageError('LZ4 block too large')
    return bytes(out)


def decompress(data):
    if data[:2] == b'\x1f\x8b':
        return gzip.decompress(data)
    if data[:4] != LZ4_LEGACY:
        raise ImageError('unknown ramdisk compression')
    out, position = [], 4
    while position + 4 <= len(data):
        size = struct.unpack_from('<I', data, position)[0]
        if size == 0x184c2102:
            position += 4
            continue
        if size == 0:
            break
        if size > LZ4_BLOCK_MAX * 2 or position + 4 + size > len(data):
            raise ImageError('truncated LZ4 frame')
        out.append(_lz4_block(data[position + 4:position + 4 + size], LZ4_BLOCK_MAX))
        position += 4 + size
    return b''.join(out)


def ramdisk(image):
    header = parse_header(image)
    start, size = header.ramdisk_offset, header.ramdisk_size
    if size == 0 or start + size > len(image):
        raise ImageError('ramdisk outside the image')
    return decompress(image[start:start + size])


def newc(data):
    """Yield (name, mode, payload). Refuses unsafe names and truncated records."""
    position = 0
    while True:
        if position + NEWC_HEADER > len(data):
            raise ImageError('CPIO ended without a trailer')
        if data[position:position + 6] not in (b'070701', b'070702'):
            raise ImageError('bad CPIO magic')
        fields = [int(data[position + 6 + 8 * i:position + 14 + 8 * i], 16) for i in range(13)]
        mode, size, name_size = fields[1], fields[6], fields[11]
        name_start = position + NEWC_HEADER
        if name_size == 0 or name_start + name_size > len(data):
            raise ImageError('truncated CPIO name')
        name = data[name_start:name_start + name_size - 1].decode('utf-8', 'surrogateescape')
        body = (name_start + name_size + 3) & ~3
        if body + size > len(data):
            raise ImageError('truncated CPIO body')
        if name == 'TRAILER!!!':
            return
        if name.startswith('/') or '..' in name.split('/'):
            raise ImageError(f'unsafe CPIO name {name!r}')
        yield name, mode, data[body:body + size]
        position = (body + size + 3) & ~3
