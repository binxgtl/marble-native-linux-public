#!/usr/bin/env python3
"""Verify an M6 module closure is loadable before anything is booted.

M2 already proved every stock module's imports resolve against the M1 kernel
plus *some* stock module. That is not the question M6 asks. M6 loads 37 modules
and no others, so a symbol that M2 happily resolved against module number 200
would be an unresolved symbol at insmod time. This checks the closure against
itself:

  1. every closure member appears in the audited stock manifest;
  2. every symbol any closure member imports is exported either by the kernel's
     own Module.symvers or by another module *inside the closure*;
  3. every CRC matches exactly, so MODVERSIONS cannot reject the module;
  4. every closure member declares the same vermagic as the audited set, which
     is what same_magic() compares after skipping the version prefix.

It reads only sanitized manifests and the kernel's own symbol table. No vendor
module is opened here and none needs to be present.

A pass is a static result. It says the modules can load, not that anything
probes; that is what the hardware experiment is for.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


class VerifyError(RuntimeError):
    pass


def normalize_crc(value: str) -> str:
    text = value.lower()
    if not text.startswith("0x"):
        text = "0x" + text
    return f"0x{int(text, 16) & 0xFFFFFFFF:08x}"


def module_key(filename: str) -> str:
    """modules.dep, modules.load and the manifests disagree about - vs _."""
    return filename.removesuffix(".ko").replace("-", "_")


def load_symvers(path: Path) -> dict[str, str]:
    table: dict[str, str] = {}
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        fields = line.split()
        if len(fields) < 2:
            raise VerifyError(f"Module.symvers:{number}: expected CRC and symbol")
        crc, symbol = normalize_crc(fields[0]), fields[1]
        if table.get(symbol, crc) != crc:
            raise VerifyError(f"Module.symvers has conflicting CRCs for {symbol}")
        table[symbol] = crc
    if not table:
        raise VerifyError("Module.symvers is empty")
    return table


def read_closure(path: Path) -> list[str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines or not lines[0].startswith("load\tmodule\t"):
        raise VerifyError(f"{path} is not an m6 closure manifest")
    names = [line.split("\t")[1] for line in lines[1:] if line.strip()]
    if not names:
        raise VerifyError(f"{path} lists no modules")
    return names


def merge_module_metadata(base: dict, overlays: list[Path], label: str) -> dict:
    """Overlay runtime-selected variants without rewriting the frozen M2 audit."""
    modules = list(base["modules"])
    by_key = {module_key(item["filename"]): item for item in modules}
    if len(by_key) != len(modules):
        raise VerifyError(f"duplicate module in base {label} manifest")
    for path in overlays:
        content = json.loads(path.read_text(encoding="utf-8"))
        items = content.get("modules", [])
        if not items:
            raise VerifyError(f"{path}: overlay lists no modules")
        seen: set[str] = set()
        for item in items:
            key = module_key(item["filename"])
            if key in seen:
                raise VerifyError(f"{path}: duplicate overlay module {key}")
            seen.add(key)
            by_key[key] = item
    merged = dict(base)
    merged["modules"] = list(by_key.values())
    return merged


def verify(closure: list[str], versions: dict, providers: dict,
           symvers: dict[str, str]) -> dict:
    by_name = {module_key(m["filename"]): m for m in versions["modules"]}
    exports_by_name = {module_key(m["filename"]): m for m in providers["modules"]}

    wanted = [module_key(name) for name in closure]
    missing = sorted(n for n in wanted if n not in by_name)
    if missing:
        raise VerifyError(f"closure members absent from the audited manifest: {missing}")
    if len(set(wanted)) != len(wanted):
        raise VerifyError("closure lists the same module twice")

    # Exports available at run time: the kernel, plus the closure and nothing else.
    inside: dict[str, tuple[str, str]] = {}
    for name in wanted:
        for export in exports_by_name.get(name, {}).get("exports", []):
            crc = normalize_crc(export["crc"])
            previous = inside.get(export["name"])
            if previous and previous[1] != crc:
                raise VerifyError(
                    f"{export['name']} is exported with conflicting CRCs by "
                    f"{previous[0]} and {name}")
            inside[export["name"]] = (name, crc)

    vermagics = {by_name[n]["vermagic"] for n in wanted}
    if len(vermagics) != 1:
        raise VerifyError(f"closure members disagree about vermagic: {sorted(vermagics)}")

    checked = kernel = peer = 0
    unresolved, mismatched = [], []
    for name in wanted:
        for want in by_name[name]["symbols"]:
            checked += 1
            symbol, crc = want["name"], normalize_crc(want["crc"])
            if symbol in symvers:
                kernel += 1
                if symvers[symbol] != crc:
                    mismatched.append(f"{name}: {symbol} kernel={symvers[symbol]} wants={crc}")
            elif symbol in inside:
                peer += 1
                if inside[symbol][1] != crc:
                    mismatched.append(
                        f"{name}: {symbol} {inside[symbol][0]}={inside[symbol][1]} wants={crc}")
            else:
                # The interesting failure: resolvable for stock, not for us.
                outside = [module_key(m["filename"]) for m in providers["modules"]
                           if any(e["name"] == symbol for e in m.get("exports", []))]
                unresolved.append(
                    f"{name}: {symbol} (provided only by {outside or ['nothing']})")

    return {
        "schema": "marble-m6-closure-kmi-report-v1",
        "status": "STATIC CLOSURE KMI CHECK PASSED — NOT BOOT-PROVEN"
                  if not unresolved and not mismatched else "FAILED",
        "closure_size": len(wanted),
        "vermagic": sorted(vermagics)[0],
        "symbol_requirements_checked": checked,
        "resolved_by_kernel": kernel,
        "resolved_within_closure": peer,
        "unresolved": unresolved,
        "mismatched": mismatched,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("closure", type=Path, help="manifests/m6-*-closure.tsv")
    parser.add_argument("versions", type=Path, help="manifests/stock-module-versions.json")
    parser.add_argument("providers", type=Path, help="manifests/stock-module-providers.json")
    parser.add_argument("symvers", type=Path, help="the kernel's Module.symvers")
    parser.add_argument("--versions-overlay", action="append", type=Path, default=[],
                        help="sanitized runtime module metadata replacing M2 entries")
    parser.add_argument("--providers-overlay", action="append", type=Path, default=[],
                        help="sanitized runtime export metadata replacing M2 entries")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    try:
        versions = merge_module_metadata(
            json.loads(args.versions.read_text(encoding="utf-8")),
            args.versions_overlay, "versions")
        providers = merge_module_metadata(
            json.loads(args.providers.read_text(encoding="utf-8")),
            args.providers_overlay, "providers")
        report = verify(read_closure(args.closure), versions, providers,
                        load_symvers(args.symvers))
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_bytes((json.dumps(report, indent=2) + "\n").encode("utf-8"))
        for key in ("status", "closure_size", "vermagic", "symbol_requirements_checked",
                    "resolved_by_kernel", "resolved_within_closure"):
            print(f"{key}: {report[key]}")
        for line in report["unresolved"][:20]:
            print(f"  UNRESOLVED {line}", file=sys.stderr)
        for line in report["mismatched"][:20]:
            print(f"  CRC MISMATCH {line}", file=sys.stderr)
        return 0 if report["status"].startswith("STATIC") else 1
    except (VerifyError, OSError, KeyError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
