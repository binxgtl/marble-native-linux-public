#!/usr/bin/env bash
set -euo pipefail

# Synthetic regression suite for the M6 closure tooling and the storage init.
# Every input is fabricated: no vendor module, no ROM, no boot image, no cross
# toolchain, so it runs on a hosted runner and carries nothing proprietary.

root=$(cd "$(dirname "$0")/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

. "$root/scripts/m3-python.sh"
m3_resolve_python

closure() { "$PYTHON" "$root/scripts/m6-module-closure.py" "$@"; }
verify() { "$PYTHON" "$root/scripts/m6-verify-closure-kmi.py" "$@"; }

# ------------------------------------------------------- synthetic module tree
# top needs mid (symbol) and side (softdep pre). mid needs leaf. far is only
# reachable through a `post:` softdep, which is not a prerequisite and must
# stay out. orphan is present but unrelated.
"$PYTHON" - "$tmp" <<'PY'
import pathlib, sys
root = pathlib.Path(sys.argv[1]) / "modules"
root.mkdir(parents=True)
elf = b"\x7fELF" + bytes(60)
for name in ("top", "mid", "leaf", "side", "far", "orphan", "blocked"):
    (root / f"{name}.ko").write_bytes(elf + name.encode())
(root / "modules.dep").write_text(
    "/lib/modules/top.ko: /lib/modules/mid.ko /lib/modules/leaf.ko\n"
    "/lib/modules/mid.ko: /lib/modules/leaf.ko\n"
    "/lib/modules/leaf.ko:\n"
    "/lib/modules/side.ko:\n"
    "/lib/modules/far.ko:\n"
    "/lib/modules/orphan.ko:\n"
    "/lib/modules/blocked.ko:\n")
(root / "modules.softdep").write_text(
    "# Soft dependencies extracted from modules themselves.\n"
    "softdep top pre: side post: far\n")
# Stock load order; leaf before mid before top, as a real one would be.
(root / "modules.load").write_text(
    "leaf.ko\nside.ko\nmid.ko\ntop.ko\nfar.ko\norphan.ko\nblocked.ko\n")
(root / "modules.blocklist").write_text("blocklist blocked\n")
PY

mods="$tmp/modules"
printf 'top\n' >"$tmp/seeds.txt"

closure --modules-dir "$mods" --seeds "$tmp/seeds.txt" \
  --manifest "$tmp/c.tsv" --load-list "$tmp/c.txt" --c-include "$tmp/c.inc" \
  --report "$tmp/c.json" --expect-count 4 >/dev/null

"$PYTHON" - "$tmp" <<'PY'
import json, pathlib, sys
tmp = pathlib.Path(sys.argv[1])
names = (tmp / "c.txt").read_text().split()
# Load order, and `post:` softdeps excluded: far must not be dragged in.
assert names == ["leaf.ko", "side.ko", "mid.ko", "top.ko"], names
report = json.loads((tmp / "c.json").read_text())
assert report["closure_size"] == 4 and report["modules_present"] == 7
reasons = {e["module"]: e["reason"] for e in report["entries"]}
assert reasons["top.ko"] == "runtime-supplier"
assert reasons["side.ko"] == "softdep pre of top.ko"
assert reasons["mid.ko"] == "dep of top.ko"
# The manifest is the committed artefact: it must carry a digest per module and
# no vendor bytes.
rows = (tmp / "c.tsv").read_text().splitlines()
assert rows[0] == "load\tmodule\tstock_index\tsize\tsha256\treason\tdeps\tstock_stage"
assert len(rows) == 5
for row in rows[1:]:
    assert len(row.split("\t")[4]) == 64
# Stock loads modules in two phases; with no second list supplied everything
# here is first stage, and the phase is recorded rather than assumed.
assert all(row.split("\t")[7] == "1" for row in rows[1:])
# Dependencies first. modules.load is not a load order: stock hands it to
# libmodprobe, which sorts each entry's dependencies out of modules.dep. Taking
# it at face value put clk-rpmh.ko ahead of the cmd-db.ko it imports from, and
# the device answered with "Unknown symbol cmd_db_read_addr".
pos = {r.split("\t")[1]: int(r.split("\t")[0]) for r in rows[1:]}
assert sorted(pos.values()) == list(range(len(pos)))
for row in rows[1:]:
    field = row.split("\t")
    for d in ([] if field[6] == "-" else field[6].split(",")):
        assert pos[d] < pos[field[1]], f"{field[1]} loads before its dependency {d}"
# Host line endings must never reach a device-consumed list.
for name in ("c.tsv", "c.txt", "c.inc", "c.json"):
    assert b"\r\n" not in (tmp / name).read_bytes(), name
inc = [l.strip().strip('",') for l in (tmp / "c.inc").read_text().splitlines()
       if l.startswith("\t")]
assert inc == names, inc
PY

# Name resolution across the - / _ split the vendor files are inconsistent about.
printf 'top.ko\n' >"$tmp/seeds-suffix.txt"
closure --modules-dir "$mods" --seeds "$tmp/seeds-suffix.txt" \
  --load-list "$tmp/c2.txt" --expect-count 4 >/dev/null
cmp "$tmp/c.txt" "$tmp/c2.txt"

# A runtime partition can replace a stale same-named vendor-ramdisk module and
# add a new dependency. Its dependency fragment overrides the base record,
# including cross-partition edges absent from either partition's depmod view.
mkdir "$tmp/overlay"
printf '\177ELFnew-top' >"$tmp/overlay/top.ko"
printf '\177ELFaddon' >"$tmp/overlay/addon.ko"
printf '/vendor/lib/modules/top.ko: /vendor/lib/modules/mid.ko /vendor/lib/modules/addon.ko\n/vendor/lib/modules/addon.ko:\n' >"$tmp/dep-overlay"
printf 'addon.ko\n' >"$tmp/second.load"
closure --modules-dir "$mods" --module-overlay-dir "$tmp/overlay" \
  --dep-overlay "$tmp/dep-overlay" --seeds "$tmp/seeds.txt" \
  --also-load-list "$tmp/second.load" --manifest "$tmp/overlay.tsv" \
  --expect-count 5 >/dev/null
"$PYTHON" - "$tmp" <<'PY'
import hashlib, pathlib, sys
tmp = pathlib.Path(sys.argv[1])
rows = [line.split("\t") for line in (tmp / "overlay.tsv").read_text().splitlines()[1:]]
by_name = {row[1]: row for row in rows}
assert by_name["top.ko"][4] == hashlib.sha256(b"\x7fELFnew-top").hexdigest()
assert by_name["addon.ko"][7] == "2"
assert int(by_name["addon.ko"][0]) < int(by_name["top.ko"][0])
PY

expect_closure_failure() {
  local label=$1; shift
  if closure "$@" >/dev/null 2>&1; then
    echo "expected $label to be rejected" >&2
    exit 1
  fi
}
printf 'nosuch\n' >"$tmp/seeds-bad.txt"
expect_closure_failure absent-seed \
  --modules-dir "$mods" --seeds "$tmp/seeds-bad.txt" --load-list "$tmp/x.txt"
: >"$tmp/seeds-empty.txt"
expect_closure_failure empty-seeds \
  --modules-dir "$mods" --seeds "$tmp/seeds-empty.txt" --load-list "$tmp/x.txt"
expect_closure_failure wrong-expected-count \
  --modules-dir "$mods" --seeds "$tmp/seeds.txt" --expect-count 99

# A closure member the ROM never loads in first stage means the model is wrong.
cp -r "$mods" "$tmp/m-noload"
grep -v '^side\.ko$' "$mods/modules.load" >"$tmp/m-noload/modules.load"
expect_closure_failure member-not-in-modules-load \
  --modules-dir "$tmp/m-noload" --seeds "$tmp/seeds.txt" --load-list "$tmp/x.txt"

cp -r "$mods" "$tmp/m-blocked"
printf 'blocklist side\n' >>"$tmp/m-blocked/modules.blocklist"
expect_closure_failure blocklisted-member \
  --modules-dir "$tmp/m-blocked" --seeds "$tmp/seeds.txt" --load-list "$tmp/x.txt"

cp -r "$mods" "$tmp/m-notelf"
printf 'not an elf' >"$tmp/m-notelf/leaf.ko"
expect_closure_failure non-elf-member \
  --modules-dir "$tmp/m-notelf" --seeds "$tmp/seeds.txt" --load-list "$tmp/x.txt"

cp -r "$mods" "$tmp/m-absentdep"
printf '/lib/modules/top.ko: /lib/modules/ghost.ko\n' >"$tmp/m-absentdep/modules.dep"
expect_closure_failure dep-on-absent-module \
  --modules-dir "$tmp/m-absentdep" --seeds "$tmp/seeds.txt" --load-list "$tmp/x.txt"

# ------------------------------------------------------------ closure KMI gate
"$PYTHON" - "$tmp" <<'PY'
import json, pathlib, sys
tmp = pathlib.Path(sys.argv[1])
VM = "5.10.160-gki-gdeadbeef SMP preempt mod_unload modversions aarch64"

def versions(mods):
    return {"schema": "marble-stock-module-versions-v1", "modules": mods}

# leaf exports leaf_sym; outsider exports only_outside. top imports a kernel
# symbol, leaf's, and - in the bad case - the outsider's.
def mod(name, imports, vermagic=VM):
    return {"filename": name, "vermagic": vermagic, "dependencies": [],
            "symbols": [{"name": n, "crc": c} for n, c in imports]}

def prov(name, exports):
    return {"filename": name, "exports": [{"name": n, "crc": c} for n, c in exports]}

good_v = versions([
    mod("top.ko", [("kernel_sym", "0x11111111"), ("leaf_sym", "0x22222222")]),
    mod("leaf.ko", [("kernel_sym", "0x11111111")]),
    mod("outsider.ko", [("kernel_sym", "0x11111111")]),
])
good_p = {"schema": "marble-stock-module-providers-v1", "modules": [
    prov("top.ko", []), prov("leaf.ko", [("leaf_sym", "0x22222222")]),
    prov("outsider.ko", [("only_outside", "0x33333333")])]}
(tmp / "v.json").write_text(json.dumps(good_v))
(tmp / "p.json").write_text(json.dumps(good_p))
(tmp / "symvers").write_text("0x11111111\tkernel_sym\tvmlinux\tEXPORT_SYMBOL\n")

def tsv(path, names):
    rows = ["load\tmodule\tstock_index\tsize\tsha256\treason\tdeps"]
    rows += [f"{i}\t{n}\t{i}\t1\t{'0'*64}\tseed\t-" for i, n in enumerate(names)]
    path.write_text("\n".join(rows) + "\n")

tsv(tmp / "ok.tsv", ["leaf.ko", "top.ko"])

# Runtime-selected variants can replace a stale M2 entry and add a module from
# another partition without mutating the frozen baseline manifests.
tsv(tmp / "runtime.tsv", ["leaf.ko", "runtime.ko", "top.ko"])
(tmp / "v-overlay.json").write_text(json.dumps({"modules": [
    mod("runtime.ko", [("kernel_sym", "0x11111111")]),
    mod("top.ko", [("kernel_sym", "0x11111111"),
                   ("leaf_sym", "0x22222222"),
                   ("runtime_sym", "0x44444444")]),
]}))
(tmp / "p-overlay.json").write_text(json.dumps({"modules": [
    prov("runtime.ko", [("runtime_sym", "0x44444444")]),
]}))

# The M6-specific failure: a symbol only an *excluded* module exports. M2 is
# happy with this; insmod would not be.
bad_v = json.loads(json.dumps(good_v))
bad_v["modules"][0]["symbols"].append({"name": "only_outside", "crc": "0x33333333"})
(tmp / "v-outside.json").write_text(json.dumps(bad_v))

crc_v = json.loads(json.dumps(good_v))
crc_v["modules"][0]["symbols"][1]["crc"] = "0xdeadbeef"
(tmp / "v-crc.json").write_text(json.dumps(crc_v))

mag_v = json.loads(json.dumps(good_v))
mag_v["modules"][1]["vermagic"] = "5.10.160-gki-other SMP preempt aarch64"
(tmp / "v-vermagic.json").write_text(json.dumps(mag_v))

tsv(tmp / "missing.tsv", ["leaf.ko", "ghost.ko"])
tsv(tmp / "dup.tsv", ["leaf.ko", "leaf.ko"])
PY

verify "$tmp/ok.tsv" "$tmp/v.json" "$tmp/p.json" "$tmp/symvers" --report "$tmp/k.json" >/dev/null
verify "$tmp/runtime.tsv" "$tmp/v.json" "$tmp/p.json" "$tmp/symvers" \
  --versions-overlay "$tmp/v-overlay.json" \
  --providers-overlay "$tmp/p-overlay.json" --report "$tmp/k-overlay.json" >/dev/null
"$PYTHON" - "$tmp" <<'PY'
import json, pathlib, sys
tmp = pathlib.Path(sys.argv[1])
r = json.loads((tmp / "k.json").read_text())
assert r["status"].startswith("STATIC"), r
assert r["symbol_requirements_checked"] == 3
assert r["resolved_by_kernel"] == 2 and r["resolved_within_closure"] == 1
overlay = json.loads((tmp / "k-overlay.json").read_text())
assert overlay["status"].startswith("STATIC"), overlay
assert overlay["symbol_requirements_checked"] == 5
assert overlay["resolved_by_kernel"] == 3
assert overlay["resolved_within_closure"] == 2
PY

expect_verify_failure() {
  local label=$1; shift
  if verify "$@" >/dev/null 2>&1; then
    echo "expected $label to be rejected" >&2
    exit 1
  fi
}
expect_verify_failure symbol-only-outside-closure \
  "$tmp/ok.tsv" "$tmp/v-outside.json" "$tmp/p.json" "$tmp/symvers"
expect_verify_failure crc-mismatch \
  "$tmp/ok.tsv" "$tmp/v-crc.json" "$tmp/p.json" "$tmp/symvers"
expect_verify_failure mixed-vermagic \
  "$tmp/ok.tsv" "$tmp/v-vermagic.json" "$tmp/p.json" "$tmp/symvers"
expect_verify_failure member-not-in-manifest \
  "$tmp/missing.tsv" "$tmp/v.json" "$tmp/p.json" "$tmp/symvers"
expect_verify_failure duplicate-member \
  "$tmp/dup.tsv" "$tmp/v.json" "$tmp/p.json" "$tmp/symvers"

# ------------------------------------------------ committed artefacts agree
# The generated include and the committed manifest must not drift apart: the
# manifest is what review reads, the include is what the image loads.
"$PYTHON" - "$root" <<'PY'
import pathlib, sys
root = pathlib.Path(sys.argv[1])
rows = (root / "manifests" / "m6-ufs-closure.tsv").read_text().splitlines()
manifest = [r.split("\t")[1] for r in rows[1:] if r.strip()]
# The committed manifest has to be a real load order, not just a list. This is
# the case the device caught: clk-rpmh.ko is third in modules.load but imports
# from cmd-db.ko and qcom_rpmh.ko, which are nineteenth and seventy-seventh.
pos = {r.split("\t")[1]: int(r.split("\t")[0]) for r in rows[1:] if r.strip()}
for row in rows[1:]:
    field = row.split("\t")
    for d in ([] if field[6] == "-" else field[6].split(",")):
        assert pos[d] < pos[field[1]], f"{field[1]} loads before its dependency {d}"
assert pos["cmd-db.ko"] < pos["clk-rpmh.ko"]
assert pos["qcom_rpmh.ko"] < pos["clk-rpmh.ko"]
assert pos["ufs_qcom.ko"] > pos["phy-qcom-ufs.ko"]
inc = [l.strip().strip('",') for l in
       (root / "scripts" / "m6-closure-load-order.inc").read_text().splitlines()
       if l.startswith("\t")]
assert manifest == inc, "m6-closure-load-order.inc has drifted from m6-ufs-closure.tsv"
assert len(manifest) == 38, len(manifest)
# Added by evidence after run D3, not by importing what Android loads: the
# controller's two dormant suppliers vote through a BCM voter under the
# display RSC, whose only supplier is the display clock controller.
assert "dispcc-waipio.ko" in manifest
assert pos["dispcc-waipio.ko"] < pos["qnoc-waipio.ko"]

# M6a is a hardware-proven baseline, so M6b extends it and never revises it:
# the same modules, in the same relative order, plus the remoteproc set.
brows = [r.split("\t") for r in
         (root / "manifests" / "m6b-remoteproc-closure.tsv").read_text().splitlines()[1:]
         if r.strip()]
b = [r[1] for r in brows]
assert set(manifest) <= set(b), sorted(set(manifest) - set(b))
assert [m for m in b if m in set(manifest)] == manifest, \
    "M6a relative order changed inside M6b"
assert len(b) == 53, len(b)
bpos = {r[1]: int(r[0]) for r in brows}
# Named by the R2 dump and by nothing else: every remoteproc and every smp2p
# sat in devices_deferred behind one dormant, unbound supplier. smp2p reaches
# the mailbox through an `mboxes` phandle, which modules.dep cannot see, so it
# has to load first.
assert "qcom_ipcc.ko" in b
assert bpos["qcom_ipcc.ko"] < bpos["smp2p.ko"] < bpos["qcom_q6v5_pas.ko"]
for r in brows:
    for d in ([] if r[6] == "-" else r[6].split(",")):
        assert bpos[d] < bpos[r[1]], f"{r[1]} loads before its dependency {d}"
for needed in ("qcom_q6v5_pas.ko", "smp2p.ko", "mdt_loader.ko", "qcom_sysmon.ko",
               "rproc_qcom_common.ko", "qmi_helpers.ko", "qrtr.ko"):
    assert needed in b, needed
for forbidden in ("msm_drm", "cfg80211", "kgsl", "venus", "camera", "snd", "touch"):
    assert not any(forbidden in m for m in b), forbidden
# Every member is one stock loads, in one phase or the other, and which phase is
# recorded rather than flattened away.
assert {r[7] for r in brows} == {"1", "2"}
second = {r[1] for r in brows if r[7] == "2"}
assert "qcom_q6v5_pas.ko" in second and "smp2p.ko" in second
assert not (second & set(manifest)), "no M6a module may be reclassified as second stage"
# The M6b include must not rot either: it is what a future M6b image will load.
binc = [l.strip().strip('",') for l in
        (root / "scripts" / "m6b-closure-load-order.inc").read_text().splitlines()
        if l.startswith("\t")]
assert binc == b, "m6b-closure-load-order.inc has drifted from m6b-remoteproc-closure.tsv"
assert "ufs_qcom.ko" in manifest and "arm_smmu.ko" in manifest
# The cape parts, not the waipio ones: this device binds the cape PHY and
# pinctrl, which is the correction the runtime seed list exists to carry.
assert "phy-qcom-ufs-qmp-v4-cape.ko" in manifest
assert "pinctrl-cape.ko" in manifest
assert not any("waipio" in m and ("phy" in m or "pinctrl" in m) for m in manifest)
# Nothing outside the storage goal.
for forbidden in ("msm_drm", "cfg80211", "q6", "adsp", "cdsp", "venus", "kgsl"):
    assert not any(forbidden in m for m in manifest), forbidden
PY

# ------------------------------------------------------- init source discipline
init="$root/scripts/m6-init.c"
if grep -qE '#include *<|modprobe|/vendor/|/system/' "$init"; then
  echo "m6-init.c must not include system headers or reference Android paths" >&2
  exit 1
fi
grep -q '#include "m6-closure-load-order.inc"' "$init"
# Nothing in M6 phase 1 may go near userdata.
if grep -qE '"/data|userdata|f2fs|metadata' "$init"; then
  echo "m6-init.c must not reference /data, userdata or f2fs" >&2
  exit 1
fi
# Read-only twice over, and no journal replay on the ext4 one.
grep -q 'BLKROSET' "$init"
grep -q 'MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC' "$init"
grep -q '"norecovery"' "$init"
# The block flag must be read back, not assumed from an ioctl return, and put
# back afterwards: it is a per-boot attribute, not a change to the partition.
grep -q 'BLKROGET' "$init"
grep -q 'blkro(TARGETS\[i\].node, TARGETS\[i\].label, 0, "after-umount")' "$init"
grep -q 'blkro(node, label, 1, "before-mount")' "$init"

# Our own namespace only. Android owns the stock mount points and nothing here
# may look like a partial version of its first-stage mount.
for stockpoint in /vendor/firmware_mnt /vendor/bt_firmware /vendor/dsp /mnt/vendor; do
  if grep -qF "\"$stockpoint" "$init"; then
    echo "m6-init.c must not mount on the stock path $stockpoint" >&2
    exit 1
  fi
done
# Exactly the three firmware partitions, by GPT label, on the active slot.
for p in modem_a bluetooth_a dsp_a; do grep -q "\"$p\"" "$init"; done
"$PYTHON" - "$init" <<'PY'
import re, sys
src = open(sys.argv[1]).read()
block = src[src.index("static const struct target TARGETS[]"):]
block = block[:block.index("};")]
labels = re.findall(r'\{\s*"([a-z]+)"', block)
assert labels == ["modem", "bluetooth", "dsp"], labels
# Every target mounts read-only; the flags are shared, so assert no per-target
# data string smuggles a write-enabling option in.
assert "norecovery" in block and block.count('"vfat"') == 2 and block.count('"ext4"') == 1
# The ext4 target is the only one with a data string, and it is norecovery.
assert re.search(r'"ext4",\s*"norecovery"', block)
# Every mount point and device node lives under /m6.
for path in re.findall(r'"(/[^"]*)"', block):
    assert path.startswith("/m6/"), path

# Loading modules is not the result. The storage pass value must be the last
# storage stage, and that stage must be the one that lists a directory.
storage_pass = int(re.search(r"#define M6_STORAGE_PASS (\d+)", src).group(1))
rproc_pass = int(re.search(r"#define M6_RPROC_PASS (\d+)", src).group(1))
stages = [int(m) for m in re.findall(r"^\t*stage = (\d+);", src, re.M)]
assert stages == sorted(stages) and stages == list(range(1, storage_pass)), stages
assert re.search(r"if \(readable < TARGET_COUNT\)[\s\S]{0,120}?goto done;"
                 r"[\s\S]{0,40}?stage = M6_STORAGE_PASS;", src), \
    "the pass stage must be gated on every filesystem listing entries"
# A control image passes at the storage stage; only an image that selects a
# remoteproc can reach the higher ladder.
assert re.search(r"#if M6_RPROC == M6_RPROC_NONE\n#define M6_STAGE_PASS M6_STORAGE_PASS\n"
                 r"#else\n#define M6_STAGE_PASS M6_RPROC_PASS\n#endif", src)

# The unmount must happen before the handover, not after it.
done = src.index("\ndone:")
assert src.index("unmount_all();", done) < src.index("SYS_execve", done), \
    "m6-init.c must unmount /m6 before exec /init.stock"

# A narrowing build must not be able to touch storage, and that is enforced by
# not compiling any of it in rather than by promising not to call it.
guard = src.index("#if !M6_BISECT\n/*\n * Everything from here to the handover is storage work.")
region = src[guard:src.index("#endif /* !M6_BISECT */", guard)]
for fn in ("static int exists(", "static int wait_for(", "static int find_partition(",
           "static int blkro(", "static int mount_ro(", "static int count_entries(",
           "static void unmount_all(", "static slong s_umount(", "static slong s_rmdir("):
    assert fn in region, f"{fn} must be compiled out of a narrowing build"
    assert src.count(fn) == 1, f"{fn} is defined more than once"

# Android must inherit the mount table it would have had. The E4 wrapper handed
# over successfully while mounting nothing; this init left /proc and /sys
# mounted and the handover stopped working. /proc is gone entirely, /sys is
# mounted only where it is needed, and it is unmounted before the exec.
assert '"proc"' not in src, "m6-init.c must not mount /proc; nothing reads it"
assert src.count('s_mount("sysfs", "/sys", "sysfs", 0, 0)') == 1
assert src.index('s_mount("sysfs"') > guard, "the sysfs mount must be storage-only"
assert 's_umount("/sys")' in region, "the sysfs mount must be undone before the handover"
assert src.index('s_umount("/sys")') < src.index("sys(SYS_execve,"), \
    "sysfs must be unmounted before exec /init.stock"

# The D3 observability build adds reading, never doing. It must default off,
# live inside the storage-only region, mount nothing of its own, and stop before
# any storage work whether or not the controller bound.
assert "#define M6_SUPPLIER_DUMP 0" in src
dump = src.index("#if M6_SUPPLIER_DUMP || M6_RPROC_DUMP\n\n/*\n * One line per device link")
dump_end = src.index("#endif /* M6_SUPPLIER_DUMP || M6_RPROC_DUMP */")
assert guard < dump < dump_end < src.index("#endif /* !M6_BISECT */")
# The D3 half and the R2 half share the link walker but have different budgets:
# D3 touches no filesystem at all, R2 may mount debugfs and nothing else.
body = src[dump:src.index("#if M6_RPROC_DUMP", dump)]
r2 = src[src.index("#if M6_RPROC_DUMP", dump):dump_end]
for forbidden in ("s_mount(", "mount_ro(", "s_mknod(", "BLKROSET", "finit_module"):
    assert forbidden not in body, f"the supplier dump must not {forbidden}"
# Only primitives the pinned ACK actually exposes. waiting_for_supplier is
# removed by device_links_driver_bound(), so absence is recorded, not read as
# "unsupported"; status is the devlink attribute, one of six documented strings.
for needle in ('"status"', '"sync_state_only"', "waiting_for_supplier",
               "SYS_readlinkat", "driver_bound="):
    assert needle in body, f"the dump is missing {needle}"
assert "waiting_for_supplier=absent" in body
# Both the bound and unbound paths dump and then stop.
assert src.count("dump_consumer(UFSHC_SYSFS);") == 2
after_bound = src.index("dump_consumer(UFSHC_SYSFS);", src.index("stage = 2;"))
assert "goto done;" in src[after_bound:after_bound + 200], \
    "the observability build must stop before the storage stages"

# And the narrowing arm of m6_main reaches the handover without calling any of it.
main = src.index("int m6_main(")
arm_start = src.index("#if M6_BISECT", main)
arm = src[arm_start:src.index("#else", arm_start)]
assert "goto done;" in arm
for forbidden in ("mount_ro(", "find_partition(", "wait_for(", "unmount_all(", "blkro("):
    assert forbidden not in arm, f"{forbidden} must not run in a narrowing build"

# R2 reads and does not act. The only filesystem it may touch is debugfs, which
# is virtual, mounted read-only inside the sysfs tree the init already has, and
# unmounted again before anything else is torn down.
assert "#define M6_RPROC_DUMP 0" in src
assert '#error "the observability build starts nothing and needs the phase 2 closure"' in src
assert r2.count("s_mount(") == 1 and 's_mount("debugfs", "/sys/kernel/debug", "debugfs"' in r2
assert 'MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC' in r2
assert 's_umount("/sys/kernel/debug")' in r2
for forbidden in ("mount_ro(", "s_mknod(", "BLKROSET", "finit_module", "O_WRONLY", '"start"'):
    assert forbidden not in r2, f"the R2 dump must not {forbidden}"
# devices_deferred is the point of the run: membership separates a late supplier
# from a hard failure, and only the first is an ordering problem.
assert "/sys/kernel/debug/devices_deferred" in r2
# All four devices, by name, never by sysfs index.
r2devs = re.findall(r'"/sys/bus/platform/devices/([\w.-]+)"', r2)
assert r2devs == ["3000000.remoteproc-adsp", "32300000.remoteproc-cdsp",
                  "4080000.remoteproc-mss", "2400000.remoteproc-slpi"], r2devs

# ------------------------------------------------------------ M6b remoteproc
# The closure an image carries is a build-time switch between the two committed
# lists, so a phase 1 image cannot pick up the remoteproc modules by accident
# and a phase 2 one cannot silently drop them.
assert '#include "m6b-closure-load-order.inc"' in src
assert re.search(r"#if M6_PHASE == 2\n#include \"m6b-closure-load-order\.inc\"\n"
                 r"#else\n#include \"m6-closure-load-order\.inc\"\n#endif", src)
assert "#error \"starting a remoteproc needs the phase 2 closure\"" in src

rp = src.index("/* --------------------------------------------------------------- remoteproc */")
rp_end = src.index("#endif /* M6_PHASE == 2 */")
assert guard < rp < rp_end < src.index("#endif /* !M6_BISECT */")
rproc = src[rp:rp_end]
# One node per image, and no way to ask for two: the target is a single const
# struct chosen by a #if chain with an #error default, never an array.
sel = re.findall(r"^#(?:el)?if M6_RPROC == (M6_RPROC_\w+)$", rproc, re.M)
assert sel == ["M6_RPROC_ADSP", "M6_RPROC_CDSP", "M6_RPROC_SLPI", "M6_RPROC_MSS"], sel
assert rproc.count("static const struct rproc_target RPROC = {") == 4
assert "struct rproc_target RPROC[]" not in rproc
assert '#error "M6_RPROC must name one of the four remoteprocs"' in rproc
# Exactly the four firmware files that exist on this ROM. The driver's own
# per-compatible defaults are adsp.mdt and slpi.mdt and neither is present, so
# a build that trusted the driver would fail to find its firmware.
names = re.findall(r'RPROC = \{\s*"\w+", "[\w.-]+", "([\w.]+)" \}', rproc)
assert names == ["adsp2.mdt", "cdsp.mdt", "slpi2.mdt", "modem.mdt"], names
assert "adsp.mdt" not in names and "slpi.mdt" not in names
# The image directory is on a partition M6a already mounts; this phase mounts
# nothing of its own and starts nothing in a control build.
fw_dir = re.search(r'#define FW_DIR "([^"]+)"', src).group(1)
assert fw_dir == "/m6/modem/image", fw_dir
assert fw_dir.startswith(re.search(r'\{ "modem",\s+"modem_a",\s+"[^"]+",\s+"([^"]+)"', src).group(1) + "/")
for forbidden in ("s_mount(", "mount_ro(", "s_mknod(", "BLKROSET", "finit_module", "s_unlink("):
    assert forbidden not in rproc, f"the remoteproc phase must not {forbidden}"
# Writing is only compiled into an image that selects a node.
writers = rproc.index("#if M6_RPROC != M6_RPROC_NONE")
for fn in ("static slong sysfs_put(", "static slong attr_put(",
           "static int rproc_bringup(", "static void rproc_restore("):
    assert rproc.index(fn) > writers, f"{fn} must be compiled out of a control build"
assert rproc.index("static int rproc_scan(") < writers, \
    "the control build must still record every node's state"
assert "O_WRONLY" not in rproc[:writers]
# The loader parameter is a global: saved before it is changed, restored after,
# and the restore runs before the unmount takes /sys away and before the exec.
assert rproc.index("fw_path saved=") < rproc.index("fw_path set rc=")
assert "fw_path restore rc=" in rproc
assert src.index("rproc_restore();", done) < src.index("unmount_all();", done) \
    < src.index("SYS_execve", done)
# Started means started and stopped: Android must inherit them all offline.
assert rproc.index('attr_put(node, "state", "start")') \
    < rproc.index('attr_put(node, "state", "stop")')
assert re.search(r'poll_state\(node, "offline"[\s\S]{0,200}?return M6_RPROC_PASS;', rproc), \
    "the pass value must be gated on the node going back offline"
assert rproc.count("return M6_RPROC_PASS;") == 1
for value in re.findall(r"^\t+return (\d+);", rproc, re.M):
    assert int(value) < rproc_pass, value

# A prefix is a prefix: the load loop walks CLOSURE from index 0 upward and the
# limit is clamped, so no build can reorder or exceed the closure.
assert "for (i = 0; i < limit; i++)" in src
assert "if (limit < 0 || limit > CLOSURE_COUNT)" in src
# Before and after every insmod, so a surviving prefix yields a full record.
assert src.count("say_mod(i, CLOSURE[i]") == 3
assert 'say_mod(i, CLOSURE[i], " begin", 0, 0);' in src
PY

echo "M6 closure and storage-init checks passed"
