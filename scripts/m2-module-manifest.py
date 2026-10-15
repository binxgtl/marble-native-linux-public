#!/usr/bin/env python3
"""Extract a sanitized CONFIG_MODVERSIONS manifest from kernel modules."""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import errno
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile


SCHEMA = "marble-stock-module-versions-v1"
PROVIDER_SCHEMA = "marble-stock-module-providers-v1"
CRC_RE = re.compile(r"^(?:0x)?([0-9a-fA-F]{1,16})\s+(\S+)$")


class ExtractError(RuntimeError):
    pass


def normalize_crc(value: int) -> str:
    return f"0x{value & 0xFFFFFFFF:08x}"


def parse_elf_sections(path: Path) -> tuple[int, str, dict[str, tuple[bytes, int]]]:
    data = path.read_bytes()
    if data[:4] != b"\x7fELF":
        raise ExtractError(f"{path.name}: not an ELF file")
    elf_class, encoding = data[4], data[5]
    if elf_class not in (1, 2) or encoding not in (1, 2):
        raise ExtractError(f"{path.name}: unsupported ELF class/encoding")
    endian = "<" if encoding == 1 else ">"
    if elf_class == 2:
        shoff = struct.unpack_from(endian + "Q", data, 0x28)[0]
        shentsize, shnum, shstrndx = struct.unpack_from(endian + "HHH", data, 0x3A)
        shfmt = endian + "IIQQQQIIQQ"
        word_size = 8
    else:
        shoff = struct.unpack_from(endian + "I", data, 0x20)[0]
        shentsize, shnum, shstrndx = struct.unpack_from(endian + "HHH", data, 0x2E)
        shfmt = endian + "IIIIIIIIII"
        word_size = 4
    if not shoff or not shnum or shstrndx >= shnum:
        raise ExtractError(f"{path.name}: unsupported extended or absent section table")
    expected_size = struct.calcsize(shfmt)
    if shentsize < expected_size or shoff + shentsize * shnum > len(data):
        raise ExtractError(f"{path.name}: invalid section table")

    headers = []
    for index in range(shnum):
        fields = struct.unpack_from(shfmt, data, shoff + index * shentsize)
        headers.append((fields[0], fields[1], fields[4], fields[5], fields[9]))
    _, _, names_offset, names_size, _ = headers[shstrndx]
    names = data[names_offset : names_offset + names_size]

    sections: dict[str, tuple[bytes, int]] = {}
    for name_offset, section_type, offset, size, entsize in headers:
        if (section_type != 8 and offset + size > len(data)) or name_offset >= len(names):
            raise ExtractError(f"{path.name}: section exceeds file bounds")
        end = names.find(b"\0", name_offset)
        if end < 0:
            raise ExtractError(f"{path.name}: invalid section name table")
        name = names[name_offset:end].decode("ascii", "strict")
        section_data = b"" if section_type == 8 else data[offset : offset + size]
        sections[name] = (section_data, entsize)
    return word_size, endian, sections


def extract_elf(path: Path) -> tuple[dict[str, str], str, list[str]]:
    word_size, endian, sections = parse_elf_sections(path)
    if "__versions" not in sections:
        raise ExtractError(f"{path.name}: __versions section is missing")
    version_data, entsize = sections["__versions"]
    record_size = entsize or 64
    if record_size < word_size + 2 or len(version_data) % record_size:
        raise ExtractError(f"{path.name}: invalid __versions record size")

    symbols: dict[str, str] = {}
    word_format = "Q" if word_size == 8 else "I"
    for offset in range(0, len(version_data), record_size):
        record = version_data[offset : offset + record_size]
        crc = struct.unpack_from(endian + word_format, record)[0]
        raw_name = record[word_size:].split(b"\0", 1)[0]
        if not raw_name:
            continue
        name = raw_name.decode("ascii", "strict")
        normalized = normalize_crc(crc)
        if name in symbols and symbols[name] != normalized:
            raise ExtractError(f"{path.name}: conflicting CRCs for {name}")
        symbols[name] = normalized

    modinfo_data = sections.get(".modinfo", (b"", 0))[0]
    modinfo: dict[str, list[str]] = {}
    for item in modinfo_data.split(b"\0"):
        if not item or b"=" not in item:
            continue
        key, value = item.split(b"=", 1)
        modinfo.setdefault(key.decode("ascii", "strict"), []).append(
            value.decode("utf-8", "replace")
        )
    vermagic = (modinfo.get("vermagic") or [""])[0]
    dependencies = sorted(
        {item for value in modinfo.get("depends", []) for item in value.split(",") if item}
    )
    return symbols, vermagic, dependencies


def extract_elf_exports(path: Path) -> dict[str, str]:
    """Independently derive exported symbol CRCs from the ELF symbol table."""
    nm = shutil.which("nm")
    if not nm:
        raise ExtractError("nm is required for independent export validation")
    process = subprocess.run(
        [nm, "-P", str(path)],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if process.returncode:
        detail = process.stderr.strip().splitlines()[-1:] or ["unknown error"]
        raise ExtractError(f"{path.name}: nm failed: {detail[0]}")

    crc_symbols: dict[str, str] = {}
    exported_names: set[str] = set()
    for raw_line in process.stdout.splitlines():
        fields = raw_line.split()
        if len(fields) < 3:
            continue
        name, symbol_type, value = fields[:3]
        if name.startswith("__crc_") and symbol_type.upper() == "A":
            export_name = name[len("__crc_") :]
            try:
                crc = normalize_crc(int(value, 16))
            except ValueError as error:
                raise ExtractError(
                    f"{path.name}: invalid ELF export CRC for {export_name}"
                ) from error
            previous = crc_symbols.setdefault(export_name, crc)
            if previous != crc:
                raise ExtractError(
                    f"{path.name}: conflicting ELF export CRCs for {export_name}"
                )
        elif name.startswith("__ksymtab_"):
            exported_names.add(name[len("__ksymtab_") :])

    result: dict[str, str] = {}
    for name in sorted(exported_names):
        crc = crc_symbols.get(name)
        if crc is None:
            raise ExtractError(f"{path.name}: exported symbol {name} has no CRC")
        if crc == "0x00000000":
            raise ExtractError(f"{path.name}: exported symbol {name} has a zero CRC")
        result[name] = crc
    return result


def parse_modprobe_output(path: Path, output: str) -> dict[str, str]:
    symbols: dict[str, str] = {}
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        match = CRC_RE.match(line)
        if not match:
            raise ExtractError(f"{path.name}: unexpected modprobe output: {line!r}")
        crc, name = match.groups()
        normalized = normalize_crc(int(crc, 16))
        if name in symbols and symbols[name] != normalized:
            raise ExtractError(f"{path.name}: conflicting modprobe CRCs for {name}")
        symbols[name] = normalized
    return symbols


class LibKmod:
    def __init__(self) -> None:
        library = ctypes.util.find_library("kmod")
        if not library:
            raise ExtractError("neither modprobe nor libkmod is available")
        self.lib = ctypes.CDLL(library)
        self.lib.kmod_new.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_char_p)]
        self.lib.kmod_new.restype = ctypes.c_void_p
        self.lib.kmod_unref.argtypes = [ctypes.c_void_p]
        self.lib.kmod_unref.restype = ctypes.c_void_p
        self.lib.kmod_module_new_from_path.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        self.lib.kmod_module_new_from_path.restype = ctypes.c_int
        self.lib.kmod_module_unref.argtypes = [ctypes.c_void_p]
        self.lib.kmod_module_unref.restype = ctypes.c_void_p
        self.lib.kmod_module_get_versions.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
        self.lib.kmod_module_get_versions.restype = ctypes.c_int
        self.lib.kmod_module_version_get_crc.argtypes = [ctypes.c_void_p]
        self.lib.kmod_module_version_get_crc.restype = ctypes.c_uint64
        self.lib.kmod_module_version_get_symbol.argtypes = [ctypes.c_void_p]
        self.lib.kmod_module_version_get_symbol.restype = ctypes.c_char_p
        self.lib.kmod_list_next.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        self.lib.kmod_list_next.restype = ctypes.c_void_p
        self.lib.kmod_module_versions_free_list.argtypes = [ctypes.c_void_p]
        self.lib.kmod_module_versions_free_list.restype = None
        self.lib.kmod_module_get_symbols.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
        self.lib.kmod_module_get_symbols.restype = ctypes.c_int
        self.lib.kmod_module_symbol_get_crc.argtypes = [ctypes.c_void_p]
        self.lib.kmod_module_symbol_get_crc.restype = ctypes.c_uint64
        self.lib.kmod_module_symbol_get_symbol.argtypes = [ctypes.c_void_p]
        self.lib.kmod_module_symbol_get_symbol.restype = ctypes.c_char_p
        self.lib.kmod_module_symbols_free_list.argtypes = [ctypes.c_void_p]
        self.lib.kmod_module_symbols_free_list.restype = None
        self.ctx = self.lib.kmod_new(None, None)
        if not self.ctx:
            raise ExtractError("libkmod initialization failed")

    def close(self) -> None:
        if self.ctx:
            self.lib.kmod_unref(self.ctx)
            self.ctx = None

    def versions(self, path: Path) -> dict[str, str]:
        module = ctypes.c_void_p()
        rc = self.lib.kmod_module_new_from_path(
            self.ctx, os.fsencode(path), ctypes.byref(module)
        )
        if rc < 0:
            raise ExtractError(f"{path.name}: libkmod cannot open module ({rc})")
        versions = ctypes.c_void_p()
        try:
            rc = self.lib.kmod_module_get_versions(module, ctypes.byref(versions))
            if rc < 0:
                raise ExtractError(f"{path.name}: libkmod cannot read versions ({rc})")
            result: dict[str, str] = {}
            current = versions.value
            while current:
                symbol = self.lib.kmod_module_version_get_symbol(current)
                if not symbol:
                    raise ExtractError(f"{path.name}: libkmod returned an empty symbol")
                name = symbol.decode("ascii", "strict")
                crc = normalize_crc(self.lib.kmod_module_version_get_crc(current))
                if name in result and result[name] != crc:
                    raise ExtractError(f"{path.name}: conflicting libkmod CRCs for {name}")
                result[name] = crc
                current = self.lib.kmod_list_next(versions, current)
            return result
        finally:
            if versions.value:
                self.lib.kmod_module_versions_free_list(versions)
            self.lib.kmod_module_unref(module)

    def exports(self, path: Path) -> dict[str, str]:
        module = ctypes.c_void_p()
        rc = self.lib.kmod_module_new_from_path(
            self.ctx, os.fsencode(path), ctypes.byref(module)
        )
        if rc < 0:
            raise ExtractError(f"{path.name}: libkmod cannot open module ({rc})")
        symbols = ctypes.c_void_p()
        try:
            rc = self.lib.kmod_module_get_symbols(module, ctypes.byref(symbols))
            if rc == -errno.ENODATA:
                return {}
            if rc < 0:
                raise ExtractError(f"{path.name}: libkmod cannot read exports ({rc})")
            result: dict[str, str] = {}
            current = symbols.value
            while current:
                symbol = self.lib.kmod_module_symbol_get_symbol(current)
                if not symbol:
                    raise ExtractError(f"{path.name}: libkmod returned an empty export")
                name = symbol.decode("ascii", "strict")
                crc = normalize_crc(self.lib.kmod_module_symbol_get_crc(current))
                if name in result and result[name] != crc:
                    raise ExtractError(f"{path.name}: conflicting export CRCs for {name}")
                result[name] = crc
                current = self.lib.kmod_list_next(symbols, current)
            return result
        finally:
            if symbols.value:
                self.lib.kmod_module_symbols_free_list(symbols)
            self.lib.kmod_module_unref(module)


class PrimaryExtractor:
    def __init__(self) -> None:
        self.modprobe = shutil.which("modprobe")
        self.libkmod = None if self.modprobe else LibKmod()

    @property
    def name(self) -> str:
        return "modprobe --show-modversions/--show-exports" if self.modprobe else "libkmod"

    def close(self) -> None:
        if self.libkmod:
            self.libkmod.close()

    def versions(self, path: Path) -> dict[str, str]:
        if self.modprobe:
            process = subprocess.run(
                [self.modprobe, "--show-modversions", str(path)],
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if process.returncode:
                detail = process.stderr.strip().splitlines()[-1:] or ["unknown error"]
                raise ExtractError(f"{path.name}: modprobe failed: {detail[0]}")
            return parse_modprobe_output(path, process.stdout)
        assert self.libkmod is not None
        return self.libkmod.versions(path)

    def exports(self, path: Path) -> dict[str, str]:
        if self.modprobe:
            process = subprocess.run(
                [self.modprobe, "--show-exports", str(path)],
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if process.returncode:
                detail = process.stderr.strip().splitlines()[-1:] or ["unknown error"]
                raise ExtractError(f"{path.name}: modprobe export scan failed: {detail[0]}")
            return parse_modprobe_output(path, process.stdout)
        assert self.libkmod is not None
        return self.libkmod.exports(path)


def module_paths(root: Path) -> list[Path]:
    if not root.is_dir():
        raise ExtractError(f"module directory does not exist: {root}")
    paths = sorted((path for path in root.rglob("*.ko") if path.is_file()), key=lambda p: p.name)
    if not paths:
        raise ExtractError("no .ko files found")
    names = [path.name for path in paths]
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        raise ExtractError(f"duplicate sanitized filenames: {', '.join(duplicates)}")
    return paths


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("module_dir", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--providers-output", type=Path, required=True)
    parser.add_argument("--expected-modules", type=int, default=0)
    parser.add_argument("--validation-count", type=int, default=5)
    args = parser.parse_args()

    try:
        paths = module_paths(args.module_dir)
        if args.expected_modules and len(paths) != args.expected_modules:
            raise ExtractError(
                f"expected {args.expected_modules} modules, found {len(paths)}"
            )
        validation_count = min(args.validation_count, len(paths))
        if validation_count < min(3, len(paths)):
            raise ExtractError("validation-count must cover at least three modules")

        primary = PrimaryExtractor()
        try:
            print(
                f"Validating {validation_count} modules with {primary.name}, "
                "ELF __versions, and exported CRC extraction...",
                file=sys.stderr,
            )
            cached: dict[Path, dict[str, str]] = {}
            cached_exports: dict[Path, dict[str, str]] = {}
            for path in paths[:validation_count]:
                primary_symbols = primary.versions(path)
                elf_symbols, _, _ = extract_elf(path)
                if primary_symbols != elf_symbols:
                    raise ExtractError(f"{path.name}: primary/ELF version data disagree")
                cached[path] = primary_symbols
                primary_exports = primary.exports(path)
                elf_exports = extract_elf_exports(path)
                if primary_exports != elf_exports:
                    raise ExtractError(f"{path.name}: primary/ELF export data disagree")
                cached_exports[path] = primary_exports

            modules = []
            provider_modules = []
            requirement_count = 0
            export_count = 0
            for path in paths:
                symbols, vermagic, dependencies = extract_elf(path)
                primary_symbols = cached.get(path) or primary.versions(path)
                if primary_symbols != symbols:
                    raise ExtractError(f"{path.name}: primary/ELF version data disagree")
                if path in cached_exports:
                    exports = cached_exports[path]
                else:
                    exports = primary.exports(path)
                    elf_exports = extract_elf_exports(path)
                    if exports != elf_exports:
                        raise ExtractError(
                            f"{path.name}: primary/ELF export data disagree"
                        )
                if not vermagic:
                    raise ExtractError(f"{path.name}: vermagic is missing")
                ordered = [
                    {"name": name, "crc": symbols[name]} for name in sorted(symbols)
                ]
                ordered_exports = [
                    {"name": name, "crc": exports[name]} for name in sorted(exports)
                ]
                requirement_count += len(ordered)
                export_count += len(ordered_exports)
                modules.append(
                    {
                        "filename": path.name,
                        "vermagic": vermagic,
                        "dependencies": dependencies,
                        "symbols": ordered,
                    }
                )
                provider_modules.append(
                    {"filename": path.name, "exports": ordered_exports}
                )
        finally:
            primary.close()

        manifest = {
            "schema": SCHEMA,
            "status": "NOT BOOT-PROVEN",
            "module_count": len(modules),
            "symbol_requirement_count": requirement_count,
            "modules": modules,
        }
        provider_manifest = {
            "schema": PROVIDER_SCHEMA,
            "status": "NOT BOOT-PROVEN",
            "module_count": len(provider_modules),
            "export_count": export_count,
            "modules": provider_modules,
        }
        for output, content in (
            (args.output, manifest),
            (args.providers_output, provider_manifest),
        ):
            output.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                "w", encoding="utf-8", dir=output.parent, delete=False
            ) as handle:
                json.dump(content, handle, sort_keys=True, separators=(",", ":"))
                handle.write("\n")
                temporary = Path(handle.name)
            os.replace(temporary, output)
        print(
            f"Wrote sanitized manifests: modules={len(modules)} "
            f"requirements={requirement_count} exports={export_count}",
            file=sys.stderr,
        )
        return 0
    except (ExtractError, OSError, UnicodeError, struct.error) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
