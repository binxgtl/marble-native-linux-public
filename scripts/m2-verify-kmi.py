#!/usr/bin/env python3
"""Verify stock module imports against kernel and stock-module providers."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys


SCHEMA = "marble-stock-module-versions-v1"
PROVIDER_SCHEMA = "marble-stock-module-providers-v1"
CRC_RE = re.compile(r"^0x[0-9a-fA-F]{8}$")


class VerifyError(RuntimeError):
    pass


def normalize_crc(value: str) -> str:
    value = value.lower()
    if not value.startswith("0x"):
        value = "0x" + value
    try:
        return f"0x{int(value, 16) & 0xFFFFFFFF:08x}"
    except ValueError as error:
        raise VerifyError(f"invalid CRC: {value}") from error


def module_name(filename: str) -> str:
    return filename.removesuffix(".ko").replace("-", "_")


def load_symvers(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw_line.strip():
            continue
        fields = raw_line.split()
        if len(fields) < 2:
            raise VerifyError(f"Module.symvers:{number}: expected CRC and symbol")
        crc, symbol = normalize_crc(fields[0]), fields[1]
        if symbol in result and result[symbol] != crc:
            raise VerifyError(f"Module.symvers has conflicting CRCs for {symbol}")
        result[symbol] = crc
    if not result:
        raise VerifyError("Module.symvers is empty")
    return result


def validate_symbol_list(filename: str, label: str, items: object) -> int:
    if not isinstance(items, list):
        raise VerifyError(f"{filename}: {label}s must be a list")
    seen: set[str] = set()
    for item in items:
        if not isinstance(item, dict):
            raise VerifyError(f"{filename}: malformed {label} record")
        name, crc = item.get("name"), item.get("crc")
        if not isinstance(name, str) or not name or any(ch.isspace() for ch in name):
            raise VerifyError(f"{filename}: invalid {label} symbol name")
        if name in seen:
            raise VerifyError(f"{filename}: duplicate {label} symbol {name}")
        seen.add(name)
        if not isinstance(crc, str) or not CRC_RE.fullmatch(crc):
            raise VerifyError(f"{filename}:{name}: invalid {label} CRC")
        if label == "export" and normalize_crc(crc) == "0x00000000":
            raise VerifyError(f"{filename}:{name}: zero export CRC cannot prove compatibility")
    return len(items)


def load_manifest(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") != SCHEMA:
        raise VerifyError(f"requirement manifest must use schema {SCHEMA}")
    if data.get("status") != "NOT BOOT-PROVEN":
        raise VerifyError("manifest must retain NOT BOOT-PROVEN status")
    modules = data.get("modules")
    if not isinstance(modules, list) or not modules:
        raise VerifyError("manifest modules must be a non-empty list")
    if data.get("module_count") != len(modules):
        raise VerifyError("module_count does not match modules list")

    filenames: set[str] = set()
    identities: dict[str, str] = {}
    requirements = 0
    for module in modules:
        if not isinstance(module, dict):
            raise VerifyError("manifest contains a malformed module record")
        filename = module.get("filename")
        if (
            not isinstance(filename, str)
            or not filename.endswith(".ko")
            or Path(filename).name != filename
        ):
            raise VerifyError("manifest contains a non-sanitized module filename")
        if filename in filenames:
            raise VerifyError(f"duplicate module filename: {filename}")
        filenames.add(filename)
        identity = module_name(filename)
        if identity in identities:
            raise VerifyError(
                f"ambiguous module identity: {identities[identity]} and {filename}"
            )
        identities[identity] = filename

        vermagic = module.get("vermagic")
        if not isinstance(vermagic, str) or "modversions" not in vermagic.split():
            raise VerifyError(f"{filename}: MODVERSIONS is not declared in vermagic")
        dependencies = module.get("dependencies")
        if not isinstance(dependencies, list):
            raise VerifyError(f"{filename}: dependencies must be a list")
        normalized_dependencies: set[str] = set()
        for dependency in dependencies:
            if (
                not isinstance(dependency, str)
                or not dependency
                or "/" in dependency
                or any(ch.isspace() for ch in dependency)
            ):
                raise VerifyError(f"{filename}: invalid dependency name")
            normalized = dependency.replace("-", "_")
            if normalized in normalized_dependencies:
                raise VerifyError(f"{filename}: duplicate dependency {dependency}")
            normalized_dependencies.add(normalized)
        module["_dependency_identities"] = normalized_dependencies

        symbols = module.get("symbols")
        requirements += validate_symbol_list(filename, "requirement", symbols)
        if not symbols:
            raise VerifyError(f"{filename}: no versioned symbol requirements")
    for module in modules:
        filename = module["filename"]
        identity = module_name(filename)
        for dependency in module["_dependency_identities"]:
            if dependency == identity:
                raise VerifyError(f"{filename}: self dependency is invalid")
            if dependency not in identities:
                raise VerifyError(
                    f"{filename}: dependency {dependency} is absent from complete stock set"
                )

    if data.get("symbol_requirement_count") != requirements:
        raise VerifyError("symbol_requirement_count does not match module records")
    return data


def load_provider_manifest(path: Path, requirements: dict) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") != PROVIDER_SCHEMA:
        raise VerifyError(f"provider manifest must use schema {PROVIDER_SCHEMA}")
    if data.get("status") != "NOT BOOT-PROVEN":
        raise VerifyError("provider manifest must retain NOT BOOT-PROVEN status")
    modules = data.get("modules")
    if not isinstance(modules, list) or data.get("module_count") != len(modules):
        raise VerifyError("provider module_count does not match modules list")
    expected = [module["filename"] for module in requirements["modules"]]
    actual: list[str] = []
    export_count = 0
    for module in modules:
        if not isinstance(module, dict):
            raise VerifyError("provider manifest contains a malformed module record")
        filename = module.get("filename")
        if not isinstance(filename, str) or Path(filename).name != filename:
            raise VerifyError("provider manifest contains a non-sanitized filename")
        actual.append(filename)
        export_count += validate_symbol_list(filename, "export", module.get("exports"))
    if actual != expected:
        raise VerifyError("provider manifest module set/order differs from requirements")
    if data.get("export_count") != export_count:
        raise VerifyError("export_count does not match provider records")
    return data


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("providers", type=Path)
    parser.add_argument("symvers", type=Path)
    parser.add_argument("--report", type=Path, default=Path("m2-kmi-report.json"))
    args = parser.parse_args()
    try:
        manifest = load_manifest(args.manifest)
        provider_manifest = load_provider_manifest(args.providers, manifest)
        kernel_exports = load_symvers(args.symvers)
        providers: dict[str, list[dict[str, str]]] = {}
        for module in provider_manifest["modules"]:
            for exported in module["exports"]:
                providers.setdefault(exported["name"], []).append(
                    {
                        "module": module["filename"],
                        "identity": module_name(module["filename"]),
                        "crc": normalize_crc(exported["crc"]),
                    }
                )

        kernel_matches = 0
        stock_module_matches = 0
        missing: list[dict] = []
        mismatches: list[dict] = []
        ambiguous: list[dict] = []
        invalid: list[dict] = []
        for module in manifest["modules"]:
            filename = module["filename"]
            dependencies = module["_dependency_identities"]
            consumer_identity = module_name(filename)
            for requirement in module["symbols"]:
                symbol = requirement["name"]
                expected = normalize_crc(requirement["crc"])
                kernel_crc = kernel_exports.get(symbol)
                if kernel_crc is not None:
                    if kernel_crc == expected:
                        kernel_matches += 1
                    else:
                        mismatches.append(
                            {
                                "module": filename,
                                "symbol": symbol,
                                "expected_crc": expected,
                                "actual_crc": kernel_crc,
                                "provider_kind": "kernel",
                                "provider": "vmlinux",
                            }
                        )
                    continue

                candidates = [
                    item
                    for item in providers.get(symbol, [])
                    if item["identity"] != consumer_identity
                ]
                direct = [item for item in candidates if item["identity"] in dependencies]
                public_candidates = [
                    {"module": item["module"], "crc": item["crc"]}
                    for item in candidates
                ]
                if not candidates:
                    missing.append(
                        {"module": filename, "symbol": symbol, "expected_crc": expected}
                    )
                elif not direct:
                    invalid.append(
                        {
                            "module": filename,
                            "symbol": symbol,
                            "expected_crc": expected,
                            "reason": "no exporting module is a declared dependency",
                            "providers": public_candidates,
                        }
                    )
                elif len(direct) > 1:
                    ambiguous.append(
                        {
                            "module": filename,
                            "symbol": symbol,
                            "expected_crc": expected,
                            "providers": [
                                {"module": item["module"], "crc": item["crc"]}
                                for item in direct
                            ],
                        }
                    )
                elif direct[0]["crc"] != expected:
                    mismatches.append(
                        {
                            "module": filename,
                            "symbol": symbol,
                            "expected_crc": expected,
                            "actual_crc": direct[0]["crc"],
                            "provider_kind": "stock_module",
                            "provider": direct[0]["module"],
                        }
                    )
                else:
                    stock_module_matches += 1

        matches = kernel_matches + stock_module_matches
        failures = len(missing) + len(mismatches) + len(ambiguous) + len(invalid)
        summary = {
            "modules_checked": manifest["module_count"],
            "symbol_requirements_checked": manifest["symbol_requirement_count"],
            "matches": matches,
            "kernel_matches": kernel_matches,
            "stock_module_matches": stock_module_matches,
            "missing": len(missing),
            "mismatches": len(mismatches),
            "ambiguous_provider_resolutions": len(ambiguous),
            "invalid_provider_resolutions": len(invalid),
        }
        report = {
            "schema": "marble-m2-kmi-report-v2",
            "manifest_schema": manifest["schema"],
            "provider_manifest_schema": provider_manifest["schema"],
            "status": (
                "STATIC KMI CHECK PASSED — NOT BOOT-PROVEN"
                if failures == 0
                else "STATIC KMI CHECK FAILED — NOT BOOT-PROVEN"
            ),
            "summary": summary,
            "missing_symbols": missing,
            "crc_mismatches": mismatches,
            "ambiguous_provider_resolutions": ambiguous,
            "invalid_provider_resolutions": invalid,
        }
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

        print(report["status"])
        for key, value in summary.items():
            print(f"{key}: {value}")
        for label, entries in (
            ("missing symbols", missing),
            ("CRC mismatches", mismatches),
            ("ambiguous provider resolutions", ambiguous),
            ("invalid provider resolutions", invalid),
        ):
            if entries:
                print(f"{label}:")
                for item in entries[:50]:
                    print(
                        f"  {item['module']}: {item['symbol']} "
                        f"expected={item['expected_crc']}"
                    )
                if len(entries) > 50:
                    print(f"  ... {len(entries) - 50} more in {args.report}")
        return 1 if failures else 0
    except (VerifyError, OSError, json.JSONDecodeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
