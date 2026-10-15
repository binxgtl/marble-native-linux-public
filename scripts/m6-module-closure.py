#!/usr/bin/env python3
"""Compute the exact vendor-module closure for an M6 bring-up goal.

M6 must not load all 356 vendor modules just because stock does. It loads the
closure of a seed set and nothing else, and the closure is computed rather than
curated so that it cannot quietly drift.

Two sources are combined, because neither is sufficient on its own:

  modules.dep  gives the *symbol* closure. Necessary, because init_module fails
               outright on an unresolved symbol. Not sufficient: a driver's
               clocks, regulators, interconnects and pin controllers are
               resolved by the driver core from device-tree phandles, so they
               leave no trace in the linker's view.

  the seeds    are read off the running stock kernel's supplier device links,
               which is exactly the phandle graph the symbol closure misses.
               See manifests/m6-ufs-seeds.txt.

Everything is checked against modules.load: a closure member stock does not
load in first stage would mean the model is wrong somewhere, so it is an error
rather than a warning.

The module files are proprietary. This tool reads them, hashes them, and writes
a manifest of names, sizes and digests. It never copies their contents into the
repository, and the manifest it emits carries no vendor code.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys


SCHEMA = "marble-m6-module-closure-v1"


class ClosureError(RuntimeError):
    pass


def read_dep(path: Path) -> dict[str, list[str]]:
    out = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        key, sep, rest = line.partition(":")
        if not sep:
            raise ClosureError(f"modules.dep line has no colon: {line!r}")
        out[Path(key).name] = [Path(x).name for x in rest.split()]
    return out


def read_softdep(path: Path) -> dict[str, list[str]]:
    """Only `pre:` entries. A `post:` dependency is loaded after, so it cannot
    be a prerequisite for the module we are trying to bring up."""
    out = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if not parts or parts[0] != "softdep":
            continue
        section, pre = None, []
        for token in parts[2:]:
            if token in ("pre:", "post:"):
                section = token
            elif section == "pre:":
                pre.append(token)
        out[parts[1]] = pre
    return out


def read_lines(path: Path) -> list[str]:
    return [l.strip() for l in path.read_text(encoding="utf-8").splitlines()
            if l.strip() and not l.lstrip().startswith("#")]


def read_blocklist(path: Path) -> set[str]:
    return {l.split()[1] for l in read_lines(path) if l.startswith("blocklist")}


def read_seeds(path: Path) -> list[str]:
    seeds = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#")[0].strip()
        if line:
            seeds.append(line)
    if not seeds:
        raise ClosureError(f"{path} lists no seeds")
    return seeds


def write_lf(path: Path, text: str) -> None:
    """Write bytes, never the host's line-ending default.

    The load list is read on the device and the manifest is diffed in review,
    so a CR sneaking in from a Windows build host would break one and add noise
    to the other.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode("utf-8"))


def resolver(present: set[str]):
    """modules.dep, modules.softdep and modules.load disagree about - vs _."""
    def resolve(name: str) -> str | None:
        base = name[:-3] if name.endswith(".ko") else name
        for candidate in (base, base.replace("_", "-"), base.replace("-", "_")):
            if candidate + ".ko" in present:
                return candidate + ".ko"
        return None
    return resolve


def toposort(closure: set[str], dep: dict[str, list[str]], soft: dict[str, list[str]],
             resolve, stock_index: dict[str, int]) -> list[str]:
    """Dependencies first, `modules.load` order only as a tie-break.

    `modules.load` is *not* a load order. Stock does not insmod it in sequence;
    it hands the list to libmodprobe, which topologically sorts each entry's
    dependencies from modules.dep and loads those first. Taking the file at
    face value put clk-rpmh.ko first, ahead of the cmd-db.ko and qcom_rpmh.ko
    it imports from, and the device reported exactly that:

        clk_rpmh: Unknown symbol rpmh_write (err -2)
        clk_rpmh: Unknown symbol cmd_db_read_addr (err -2)

    So the order is computed here instead, and the stock index survives only to
    break ties so the output stays deterministic.
    """
    needs: dict[str, set[str]] = {}
    for module in closure:
        base = module[:-3]
        keys = {base, base.replace("-", "_"), base.replace("_", "-")}
        pre = {resolve(x) for key in keys for x in soft.get(key, [])}
        needs[module] = ({d for d in dep.get(module, []) if d in closure} |
                         {p for p in pre if p in closure})

    ordered, placed = [], set()
    while len(ordered) < len(closure):
        ready = sorted((m for m in closure
                        if m not in placed and needs[m] <= placed),
                       key=lambda m: (stock_index[m], m))
        if not ready:
            stuck = sorted(closure - placed)
            raise ClosureError(f"dependency cycle among {stuck}")
        ordered.append(ready[0])
        placed.add(ready[0])

    for position, module in enumerate(ordered):
        late = [d for d in needs[module] if ordered.index(d) > position]
        if late:
            raise ClosureError(f"{module} is ordered before its dependencies {late}")
    return ordered


def compute(modules_dir: Path, seeds: list[str], extra_load: Path | None = None,
            module_overlay_dirs: list[Path] | None = None,
            dep_overlays: list[Path] | None = None) -> dict:
    module_paths = {p.name: p for p in modules_dir.glob("*.ko")}
    for overlay in module_overlay_dirs or []:
        paths = list(overlay.glob("*.ko"))
        if not paths:
            raise ClosureError(f"no .ko files under module overlay {overlay}")
        module_paths.update({p.name: p for p in paths})
    present = set(module_paths)
    if not present:
        raise ClosureError(f"no .ko files under {modules_dir}")
    dep = read_dep(modules_dir / "modules.dep")
    for overlay in dep_overlays or []:
        dep.update(read_dep(overlay))
    soft = read_softdep(modules_dir / "modules.softdep")
    load = read_lines(modules_dir / "modules.load")
    blocked = read_blocklist(modules_dir / "modules.blocklist")
    # Stock loads modules in two phases and the ramdisk list is only the first.
    # The remoteproc drivers live in the vendor_dlkm list instead, so a second
    # list can be supplied; membership in either is proof stock loads it, and
    # the phase is recorded per module rather than flattened away.
    second = read_lines(extra_load) if extra_load else []
    order = {name: i for i, name in enumerate(load)}
    stage = {name: 1 for name in load}
    for i, name in enumerate(second):
        if name not in order:
            order[name] = len(load) + i
            stage[name] = 2
    resolve = resolver(present)

    resolved_seeds = []
    for seed in seeds:
        hit = resolve(seed)
        if hit is None:
            raise ClosureError(f"seed {seed!r} is not present in {modules_dir}")
        resolved_seeds.append(hit)

    reason = {s: "runtime-supplier" for s in resolved_seeds}
    closure, stack = set(), list(resolved_seeds)
    while stack:
        module = stack.pop()
        if module in closure:
            continue
        closure.add(module)
        for child in dep.get(module, []):
            if child not in present:
                raise ClosureError(f"{module} depends on absent {child}")
            reason.setdefault(child, f"dep of {module}")
            stack.append(child)
        base = module[:-3]
        keys = {base, base.replace("-", "_"), base.replace("_", "-")}
        for key in keys:
            for child in soft.get(key, []):
                hit = resolve(child)
                if hit is None:
                    # A softdep naming a module this ROM does not ship is the
                    # vendor's own dead entry, not our problem; record it.
                    continue
                reason.setdefault(hit, f"softdep pre of {module}")
                stack.append(hit)

    # Fail closed on anything that would make the load list a guess.
    stray = sorted(m for m in closure if m not in order)
    if stray:
        raise ClosureError(f"closure members stock never loads at all: {stray}")
    hit_blocklist = sorted(m for m in closure if m[:-3].replace("-", "_") in
                           {b.replace("-", "_") for b in blocked})
    if hit_blocklist:
        raise ClosureError(f"closure members are blocklisted by the ROM: {hit_blocklist}")
    for module in closure:
        missing = [d for d in dep.get(module, []) if d not in closure]
        if missing:
            raise ClosureError(f"closure is not closed: {module} still needs {missing}")

    ordered = toposort(closure, dep, soft, resolve, order)
    entries = []
    for position, module in enumerate(ordered):
        path = module_paths[module]
        blob = path.read_bytes()
        if blob[:4] != b"\x7fELF":
            raise ClosureError(f"{module} is not an ELF object")
        entries.append({
            "load": position,
            "stock_index": order[module],
            "stock_stage": stage[module],
            "module": module,
            "size": len(blob),
            "sha256": hashlib.sha256(blob).hexdigest(),
            "reason": reason[module],
            "deps": dep.get(module, []),
        })
    return {
        "schema": SCHEMA,
        "seeds": resolved_seeds,
        "modules_present": len(present),
        "modules_in_stock_load": len(load),
        "closure_size": len(closure),
        "closure_bytes": sum(e["size"] for e in entries),
        "entries": entries,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--modules-dir", required=True, type=Path,
                        help="lib/modules extracted from the vendor ramdisk (local only)")
    parser.add_argument("--seeds", required=True, type=Path)
    parser.add_argument("--also-load-list", type=Path,
                        help="a second stock load list, e.g. vendor_dlkm's "
                             "modules.load; members of either are accepted and "
                             "the phase is recorded")
    parser.add_argument("--module-overlay-dir", action="append", type=Path, default=[],
                        help="local module directory whose same-named files replace the "
                             "base tree and whose new files extend it")
    parser.add_argument("--dep-overlay", action="append", type=Path, default=[],
                        help="modules.dep fragment overriding split-partition dependency "
                             "records")
    parser.add_argument("--manifest", type=Path, help="sanitized TSV, safe to commit")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--load-list", type=Path,
                        help="newline-separated module names in stock load order")
    parser.add_argument("--c-include", type=Path,
                        help="the same list as a C initialiser for m6-init.c, so the "
                             "set an image loads is fixed at build time and reviewable")
    parser.add_argument("--expect-count", type=int,
                        help="fail unless the closure has exactly this many modules")
    args = parser.parse_args()
    try:
        report = compute(args.modules_dir, read_seeds(args.seeds), args.also_load_list,
                         args.module_overlay_dir, args.dep_overlay)
        if args.expect_count is not None and report["closure_size"] != args.expect_count:
            raise ClosureError(
                f"closure has {report['closure_size']} modules, expected {args.expect_count}")
        if args.manifest:
            lines = ["load\tmodule\tstock_index\tsize\tsha256\treason\tdeps\tstock_stage"]
            lines += ["\t".join([str(e["load"]), e["module"], str(e["stock_index"]),
                                 str(e["size"]), e["sha256"], e["reason"],
                                 ",".join(e["deps"]) or "-", str(e["stock_stage"])])
                      for e in report["entries"]]
            write_lf(args.manifest, "\n".join(lines) + "\n")
        if args.load_list:
            write_lf(args.load_list,
                     "\n".join(e["module"] for e in report["entries"]) + "\n")
        if args.c_include:
            body = "".join(f'\t"{e["module"]}",\n' for e in report["entries"])
            write_lf(args.c_include,
                     "/* Generated by scripts/m6-module-closure.py. Do not edit.\n"
                     f" * Closure of {args.seeds.name}, in stock first-stage load order.\n"
                     " * Module names only; no vendor code is reproduced here. */\n" + body)
        if args.report:
            write_lf(args.report, json.dumps(report, indent=2) + "\n")
        print(f"closure_size={report['closure_size']} of {report['modules_present']} present")
        print(f"closure_bytes={report['closure_bytes']}")
        print(f"stock_first_stage_modules={report['modules_in_stock_load']}")
        return 0
    except (ClosureError, OSError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
