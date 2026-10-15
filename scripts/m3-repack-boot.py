#!/usr/bin/env python3
"""Locally replace the kernel in an Android boot image v4."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import tempfile


BOOT_MAGIC = b"ANDROID!"
ARM64_MAGIC = b"ARMd"
PAGE_SIZE = 4096
HEADER_V4_SIZE = 1584
GKI_SIGNATURE_SIZE = 4096


class BootImageError(RuntimeError):
    pass


def align(value: int, alignment: int = PAGE_SIZE) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def decode_os_version(value: int) -> tuple[str, str]:
    version = value >> 11
    major = (version >> 14) & 0x7F
    minor = (version >> 7) & 0x7F
    patch = version & 0x7F
    level = value & 0x7FF
    year = 2000 + ((level >> 4) & 0x7F)
    month = level & 0xF
    return f"{major}.{minor}.{patch}", f"{year:04d}-{month:02d}"


def parse_boot(path: Path) -> dict:
    size = path.stat().st_size
    if size < PAGE_SIZE:
        raise BootImageError("stock boot image is smaller than one v4 header page")
    with path.open("rb") as handle:
        header_page = handle.read(PAGE_SIZE)
        magic = header_page[:8]
        kernel_size, ramdisk_size, os_version, header_size = struct.unpack_from(
            "<4I", header_page, 8
        )
        reserved = struct.unpack_from("<4I", header_page, 24)
        header_version = struct.unpack_from("<I", header_page, 40)[0]
        signature_size = struct.unpack_from("<I", header_page, 1580)[0]
        if magic != BOOT_MAGIC:
            raise BootImageError("stock input does not have ANDROID! boot magic")
        if header_version != 4 or header_size != HEADER_V4_SIZE:
            raise BootImageError(
                f"only boot header v4/{HEADER_V4_SIZE} is supported; got "
                f"v{header_version}/{header_size}"
            )
        if any(reserved):
            raise BootImageError("reserved v4 header fields are nonzero")
        if not kernel_size or not ramdisk_size:
            raise BootImageError("stock kernel and ramdisk must both be nonempty")
        if signature_size not in (0, GKI_SIGNATURE_SIZE):
            raise BootImageError(f"unexpected boot signature size: {signature_size}")

        kernel_offset = PAGE_SIZE
        ramdisk_offset = align(kernel_offset + kernel_size)
        signature_offset = align(ramdisk_offset + ramdisk_size)
        payload_end = signature_offset + signature_size
        if payload_end > size:
            raise BootImageError("stock boot payload exceeds the input file")
        handle.seek(kernel_offset)
        kernel = handle.read(kernel_size)
        handle.seek(ramdisk_offset)
        ramdisk = handle.read(ramdisk_size)
        if len(kernel) != kernel_size or len(ramdisk) != ramdisk_size:
            raise BootImageError("stock boot payload is truncated")

    version, patch_level = decode_os_version(os_version)
    return {
        "file_size": size,
        "header_page": header_page,
        "header_version": header_version,
        "header_size": header_size,
        "os_version_raw": os_version,
        "os_version": version,
        "os_patch_level": patch_level,
        "kernel_size": kernel_size,
        "ramdisk_size": ramdisk_size,
        "signature_size": signature_size,
        "kernel": kernel,
        "ramdisk": ramdisk,
    }


def validate_arm64_image(kernel: bytes) -> None:
    if len(kernel) < 64 or kernel[56:60] != ARM64_MAGIC:
        raise BootImageError("replacement kernel is not a raw arm64 Linux Image")


def write_padded(handle, data: bytes) -> None:
    handle.write(data)
    handle.write(b"\0" * (align(len(data)) - len(data)))


def require_distinct_paths(paths: dict[str, Path]) -> None:
    """Reject lexical, symlink, and existing hard-link path collisions."""
    items = list(paths.items())
    resolved: dict[Path, str] = {}
    for label, path in items:
        canonical = path.resolve(strict=False)
        if canonical in resolved:
            raise BootImageError(
                f"{label} and {resolved[canonical]} must be different files"
            )
        resolved[canonical] = label

    for index, (left_label, left) in enumerate(items):
        if not left.exists():
            continue
        for right_label, right in items[index + 1 :]:
            if right.exists() and os.path.samefile(left, right):
                raise BootImageError(
                    f"{right_label} and {left_label} must be different files"
                )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stock-boot", required=True, type=Path)
    parser.add_argument("--kernel", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    try:
        require_distinct_paths(
            {
                "stock input": args.stock_boot,
                "kernel": args.kernel,
                "output": args.output,
                "report": args.report,
            }
        )
        stock = parse_boot(args.stock_boot)
        replacement = args.kernel.read_bytes()
        validate_arm64_image(replacement)

        header = bytearray(stock["header_page"])
        struct.pack_into("<I", header, 8, len(replacement))
        struct.pack_into("<I", header, 1580, 0)
        expected_size = PAGE_SIZE + align(len(replacement)) + align(stock["ramdisk_size"])
        if expected_size > stock["file_size"]:
            raise BootImageError(
                f"repacked image ({expected_size} bytes) exceeds stock input/partition "
                f"size ({stock['file_size']} bytes)"
            )

        args.output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile("wb", dir=args.output.parent, delete=False) as out:
            temporary_output = Path(out.name)
            out.write(header)
            write_padded(out, replacement)
            write_padded(out, stock["ramdisk"])
        os.replace(temporary_output, args.output)

        rebuilt = parse_boot(args.output)
        if rebuilt["signature_size"] != 0:
            raise BootImageError("repacked image unexpectedly contains a boot signature")
        if rebuilt["kernel"] != replacement:
            raise BootImageError("repacked kernel verification failed")
        if rebuilt["ramdisk"] != stock["ramdisk"]:
            raise BootImageError("repacked ramdisk differs from stock")

        report = {
            "schema": "marble-m3-boot-repack-report-v1",
            "status": "HARDWARE TEST PENDING",
            "warning": "UNSIGNED TEST IMAGE — NOT BOOT-PROVEN — DO NOT FLASH",
            "header_version": rebuilt["header_version"],
            "header_size": rebuilt["header_size"],
            "page_size": PAGE_SIZE,
            "os_version": rebuilt["os_version"],
            "os_patch_level": rebuilt["os_patch_level"],
            "stock_boot_size": stock["file_size"],
            "stock_kernel_size": stock["kernel_size"],
            "replacement_kernel_size": len(replacement),
            "ramdisk_size": rebuilt["ramdisk_size"],
            "stock_signature_size": stock["signature_size"],
            "output_signature_size": rebuilt["signature_size"],
            "output_size": args.output.stat().st_size,
            "stock_boot_sha256": sha256_file(args.stock_boot),
            "replacement_kernel_sha256": sha256_bytes(replacement),
            "ramdisk_sha256": sha256_bytes(rebuilt["ramdisk"]),
            "output_sha256": sha256_file(args.output),
        }
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(report["status"])
        print(report["warning"])
        print(f"output={args.output}")
        print(f"output_sha256={report['output_sha256']}")
        print(f"output_size={report['output_size']}")
        return 0
    except (BootImageError, OSError, struct.error) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
