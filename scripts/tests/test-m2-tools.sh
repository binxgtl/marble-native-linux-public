#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

make_fixture() {
  local name=$1 crc=$2 symbol=$3 dependency=$4 export_crc=$5 export_symbol=$6
  cat >"$tmp/$name.c" <<EOF
struct modversion_info { unsigned long crc; char name[56]; };
__attribute__((section("__versions"), used))
static const struct modversion_info versions[] = {
  { 0x11111111UL, "shared_symbol" },
  { ${crc}UL, "${symbol}" },
};
__attribute__((section(".modinfo"), used))
static const char vermagic[] = "vermagic=5.10.236-test SMP preempt mod_unload modversions aarch64";
__attribute__((section(".modinfo"), used))
static const char depends[] = "depends=${dependency}";
__asm__(".globl __crc_${export_symbol}\\n.set __crc_${export_symbol}, ${export_crc}");
__asm__(".globl __ksymtab_${export_symbol}\\n.set __ksymtab_${export_symbol}, 0");
EOF
  gcc -c "$tmp/$name.c" -o "$tmp/$name.ko"
}

make_fixture alpha 0xaaaaaaaa alpha_symbol beta 0xabababab provided_by_alpha
make_fixture beta 0xabababab provided_by_alpha alpha 0xbcbcbcbc provided_by_beta
make_fixture gamma 0xbcbcbcbc provided_by_beta beta 0xcdcdcdcd provided_by_gamma

python3 "$root/scripts/m2-module-manifest.py" \
  --expected-modules 3 --validation-count 3 \
  --providers-output "$tmp/providers.json" \
  "$tmp" "$tmp/manifest.json"

python3 - "$tmp/manifest.json" "$tmp/providers.json" "$tmp" <<'PY'
import copy
import json
import pathlib
import sys

source = pathlib.Path(sys.argv[1])
provider_source = pathlib.Path(sys.argv[2])
directory = pathlib.Path(sys.argv[3])
manifest = json.loads(source.read_text(encoding="utf-8"))
providers = json.loads(provider_source.read_text(encoding="utf-8"))
assert manifest["schema"] == "marble-stock-module-versions-v1"
assert manifest["module_count"] == 3
assert manifest["symbol_requirement_count"] == 6
assert providers["schema"] == "marble-stock-module-providers-v1"
assert providers["export_count"] == 3

def write(name, data):
    (directory / name).write_text(
        json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )

write("good.json", manifest)
write("providers-good.json", providers)

unresolved = copy.deepcopy(manifest)
unresolved["modules"][2]["symbols"][1]["name"] = "unresolved_symbol"
write("unresolved.json", unresolved)

kernel_mismatch = copy.deepcopy(manifest)
kernel_mismatch["modules"][0]["symbols"][0]["crc"] = "0x99999999"
write("kernel-mismatch.json", kernel_mismatch)

stock_mismatch = copy.deepcopy(manifest)
next(
    item
    for item in stock_mismatch["modules"][1]["symbols"]
    if item["name"] == "provided_by_alpha"
)["crc"] = "0x99999999"
write("stock-mismatch.json", stock_mismatch)

disambiguated = copy.deepcopy(providers)
disambiguated["modules"][2]["exports"].append(
    {"name": "provided_by_alpha", "crc": "0xabababab"}
)
disambiguated["export_count"] += 1
write("disambiguated.json", disambiguated)

ambiguous = copy.deepcopy(manifest)
ambiguous["modules"][1]["dependencies"].append("gamma")
write("ambiguous.json", ambiguous)

invalid_provider = copy.deepcopy(manifest)
invalid_provider["modules"][1]["dependencies"] = ["gamma"]
write("invalid-provider.json", invalid_provider)

legacy = copy.deepcopy(manifest)
legacy["schema"] = "marble-stock-module-versions-v0"
write("legacy.json", legacy)
PY

cat >"$tmp/good.symvers" <<'EOF'
0x11111111 shared_symbol vmlinux EXPORT_SYMBOL
0xaaaaaaaa alpha_symbol vmlinux EXPORT_SYMBOL
EOF

verify() {
  local manifest=$1 providers=$2 report=$3
  python3 "$root/scripts/m2-verify-kmi.py" \
    "$tmp/$manifest" "$tmp/$providers" "$tmp/good.symvers" --report "$tmp/$report"
}

expect_gate_failure() {
  local manifest=$1 providers=$2 report=$3
  if verify "$manifest" "$providers" "$report"; then
    echo "expected $manifest to fail the compatibility gate" >&2
    exit 1
  fi
}

verify good.json providers-good.json good-report.json
verify good.json disambiguated.json disambiguated-report.json
expect_gate_failure unresolved.json providers-good.json unresolved-report.json
expect_gate_failure kernel-mismatch.json providers-good.json kernel-mismatch-report.json
expect_gate_failure stock-mismatch.json providers-good.json stock-mismatch-report.json
expect_gate_failure ambiguous.json disambiguated.json ambiguous-report.json
expect_gate_failure invalid-provider.json providers-good.json invalid-provider-report.json

if verify legacy.json providers-good.json legacy-report.json; then
  echo 'expected legacy provider-unaware manifest to be rejected' >&2
  exit 1
fi

python3 - "$tmp" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
good = json.loads((root / "good-report.json").read_text())
assert good["status"] == "STATIC KMI CHECK PASSED — NOT BOOT-PROVEN"
assert good["summary"] == {
    "modules_checked": 3,
    "symbol_requirements_checked": 6,
    "matches": 6,
    "kernel_matches": 4,
    "stock_module_matches": 2,
    "missing": 0,
    "mismatches": 0,
    "ambiguous_provider_resolutions": 0,
    "invalid_provider_resolutions": 0,
}
disambiguated = json.loads((root / "disambiguated-report.json").read_text())
assert disambiguated["summary"] == good["summary"]

unresolved = json.loads((root / "unresolved-report.json").read_text())
assert unresolved["summary"]["missing"] == 1
assert unresolved["missing_symbols"][0]["symbol"] == "unresolved_symbol"

kernel = json.loads((root / "kernel-mismatch-report.json").read_text())
assert kernel["summary"]["mismatches"] == 1
assert kernel["crc_mismatches"][0]["provider_kind"] == "kernel"

stock = json.loads((root / "stock-mismatch-report.json").read_text())
assert stock["summary"]["mismatches"] == 1
assert stock["crc_mismatches"][0]["provider_kind"] == "stock_module"

ambiguous = json.loads((root / "ambiguous-report.json").read_text())
assert ambiguous["summary"]["ambiguous_provider_resolutions"] == 1

invalid = json.loads((root / "invalid-provider-report.json").read_text())
assert invalid["summary"]["invalid_provider_resolutions"] == 1

for path in root.glob("*-report.json"):
    report = json.loads(path.read_text())
    assert "NOT BOOT-PROVEN" in report["status"]
PY
