#!/usr/bin/env python3
"""Mutation check for R5a + R5b: every mutant of the audio helper, the audio stage, T3-audio, T9-audio, the amplifier
sample, or the Run31 session speaker holder must fail test.py."""
import concurrent.futures
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
REPAIR = ROOT / 'scripts/m11/qualification/runtime-repair'
OWN = ROOT / 'scripts/m11/qualification/ownership'
NATIVE = ROOT / 'scripts/m11/anchor-native'

HELPER = ('Helper',)
LOADER = ('Loader',)
STAGE = ('Stage',)
OBSERVER = ('Observer',)
AUDIOPREP = ('AudioPrep',)
SPEAKER = ('Speaker',)

SPK_FIXED_SRCS = (
    HERE.parent / 'unlock/hash.c',
    *(REPAIR / f'{u}.c' for u in ('m11_gpr_engine', 'm11_shmem', 'm11_apm_protocol', 'm11_aw_protection', 'm11_strict_mock')),
    *(OWN / f'{u}.c' for u in ('m11_custodian', 'm11_pid1_anchor', 'm11_anchor_linux', 'm11_anchor_owner')),
    *(NATIVE / f'{u}.c' for u in (
        'gpr_transport_native', 'shmem_backend_native', 'dmabuf_pool_native', 'heap_node_native',
        'intent_journal_native', 'pdr_loop_native', 'terminal_native', 'custodian_runner_native',
        'custodian_boot_native', 'pd_session_native', 'custodian_entry_native', 'snd_backend_native',
        'speaker_plan_native', 'speaker_session_native')),
    HERE / 'test-speaker.c',
)
SPK_CFLAGS = (
    '-std=c11', '-O1', '-w',
    '-DM11_ANCHOR_NATIVE', '-DM11_CUSTODIAN_NATIVE', '-DM11_ANCHOR_NATIVE_ION',
    f'-I{OWN}', f'-I{REPAIR}', f'-I{NATIVE}',
)

MUTANTS = (
    # The LP metadata: every check refuses before any device exists.
    ('audio.c', 'if (le32(geometry) != LP_GEOMETRY_MAGIC || le32(geometry + 4) != LP_GEOMETRY_BYTES)', 'if (0)', HELPER),
    ('audio.c', 'if (!checksum_ok(geometry, sizeof(geometry), 8))', 'if (0)', HELPER),
    ('audio.c', 'slot >= slots', 'slot > slots', HELPER),
    ('audio.c', 'if (!checksum_ok(metadata, header_size, 12)) {', 'if (0) {', HELPER),
    ('audio.c', 'if (memcmp(digest, metadata + 48, 32)) {', 'if (0) {', HELPER),
    ('audio.c', 'if (le32(descriptor + 8) != entry_bytes[i] || end > tables_size) {', 'if (end > tables_size) {', HELPER),
    ('audio.c', 'if (!entries[DEVICES] || !name_is(table[DEVICES] + 24, "super")) {', 'if (!entries[DEVICES]) {', HELPER),
    ('audio.c', '        if (found) {', '        if (0) {', HELPER),
    ('audio.c', 'if (le32(extent + 8) != 0 || le32(extent + 20) != 0) {', 'if (le32(extent + 8) != 0) {', HELPER),
    ('audio.c', 'if (!sectors || target < first || target > end || sectors > end - target) {', 'if (!sectors || target > end || sectors > end - target) {', HELPER),
    ('audio.c', 'if (!sectors || target < first || target > end || sectors > end - target) {', 'if (!sectors || target < first || target > end || sectors > end) {', HELPER),
    ('audio.c', '    if (end > super_sectors)\n        end = super_sectors;\n', '', HELPER),
    ('audio.c', 'if (!number || number > EXTENTS_MAX ||', 'if (!number ||', HELPER),
    # The table: read-only, end to end.
    ('audio.c', 'prepare(io, at, name, DM_READONLY_FLAG);', 'prepare(io, at, name, 0);', HELPER),
    ('audio.c', '        spec->sector_start = start;\n', '        spec->sector_start = 0;\n', HELPER),
    ('audio.c', '        if (dm_simple(kernel, control, DM_DEV_REMOVE, name)) {', '        if (0) {', HELPER),
    ('audio.c', 'if (dm_table(kernel, control, name, device, extents, count) || dm_simple(kernel, control, DM_DEV_SUSPEND, name)) {',
     'if (dm_table(kernel, control, name, device, extents, count)) {', HELPER),
    ('audio.c', '        strlen(partition) >= 36 || !*name ||', '        !*name ||', HELPER),
    # The loader: whole files, exact sizes, hashed before the first load.
    ('audio.c', '        if (strcmp(hash, rows[i].hash)) {', '        if (0) {', LOADER),
    ('audio.c', '(unsigned long long)st.st_size == size && ', '', LOADER),
    ('audio.c', 'O_RDONLY | O_CLOEXEC | O_NOFOLLOW', 'O_RDONLY | O_CLOEXEC', LOADER),
    ('audio.c', 'status = loaded ? CHANGED : UNCHANGED;', 'status = UNCHANGED;', LOADER),
    ('audio.c', 'return wanted == count ? DONE : UNCHANGED;', 'return DONE;', LOADER),
    ('audio.c', '            if (!strcmp(rows[i].name, row->name)) {', '            if (0) {', LOADER),
    ('audio.c', 'strlen(row->hash) != 64 || !is_hex(row->hash) ||', 'strlen(row->hash) != 64 ||', LOADER),
    ('audio.c', '|| !row->size ||', '||', LOADER),
    ('audio.c', 'if (!strchr(line, \'\\n\') || count == (int)LIST_MAX ||', 'if (count == (int)LIST_MAX ||', LOADER),
    ('audio.c', 'strcmp(rows[i].source, "vendor_dlkm") ? boot : dlkm', 'strcmp(rows[i].source, "vendor_boot") ? boot : dlkm', LOADER),
    # The stage: the graded stop, the cleanup and Run12's order.
    ('audio-stage', '[ "$rc" -ne 2 ] || mapped=0', ':', STAGE),
    ('audio-stage', 'undo || skip cleanup', ':', STAGE),
    ('audio-stage', '"$HELPER" check "$list" "$work/modules" "$R/lib/modules" || skip check', ':', STAGE),
    ('audio-stage', ' invariants "$1"\n', ' :\n', STAGE),
    ('audio-stage', '[ "$now" -ne 102 ] || skip "load $1 rc=$rc"', ':', STAGE),
    ('audio-stage', '[ "$now" -eq "$2" ] || publish partial "count $1 $now"', ':', STAGE),
    ('audio-stage', '[ "$amp_state" = both ] && [ "$stable" -eq 5 ] || publish partial "amps $amp_state stable=$stable"', ':', STAGE),
    ('audio-stage', '[ "$($BB blockdev --getro "$dlkm_node")" = 1 ] || skip dlkm-writable', ':', STAGE),
    ('audio-stage', '-o ro,nosuid,nodev,noexec', '-o nosuid,nodev,noexec', STAGE),
    ('audio-stage', '[ "$rows" -eq 45 ] && [ "$dlkm" -eq 37 ] || skip "list rows $rows $dlkm"', ':', STAGE),
    ('audio-stage', '"$MAPPER" --check-maps || skip mapper-maps', ':', STAGE),
    ('audio-stage', 'phase haptics 146\n', '', STAGE),
    ('audio-stage', 'invariants start\n', ':\n', STAGE),
    ('audio-stage', '[ "$(count)" -eq 102 ] || hold "module count $(count)"', ':', STAGE),
    ('audio-stage', ' printf \'1\\n\' >"$R/run/m11/pd.stop" 2>/dev/null || :', ' :', STAGE),
    ('audio-stage', ' alive || mapper_fail mapper-exited\n', ' :\n', STAGE),
    ('audio-stage', '[ ! -e "$super_node" ] && [ ! -e "$control" ] && [ ! -e "$dlkm_node" ] || skip nodes-exist', ':', STAGE),
    ('audio-stage', '  if "$HELPER" unmap "$control" m19-vendor-dlkm; then mapped=0; else left=1; fi', '  :', STAGE),
    ('audio-stage', 'case "$slot" in _a) index=0;; _b) index=1;;', 'case "$slot" in _a) index=0;; _b) index=0;;', STAGE),
    # The observer: read-only, and every criterion of Run12's.
    ('t3-audio', '[ "$result" = ready ] || fail "stage $result"', ':', OBSERVER),
    ('t3-audio', 'mapper_alive || fail mapper-exited', ':', OBSERVER),
    ('t3-audio', 'if [ "$valid" -eq 1 ] && [ "$amp_state" = both ] && [ "$adsp_state" = running ]; then',
     'if [ "$valid" -eq 1 ] && [ "$amp_state" = both ]; then', OBSERVER),
    ('t3-audio', ' && [ "${devno%%:*}" -gt 0 ]', '', OBSERVER),
    ('t3-audio', '"^${prefix}.*capture"', '"^${prefix}.*playback"', OBSERVER),
    ('t3-audio', '[ "$stable" -eq 5 ] || fail', '[ "$stable" -ge 0 ] || fail', OBSERVER),
    # The amplifier sample both share.
    ('amps', 'then linked=1; else amp_bad=1; fi', 'then linked=1; else linked=1; fi', STAGE),
    ('amps', ' && [ "$amp34_adapter" = "$amp35_adapter" ]', '', STAGE),
    # T9-audio: RAM udev persistent ALSA rule mask, /dev cleanliness, and SHA256-verified speaker bundle.
    ('t9-audio', '[ "$($BB cat "$R/run/m19/audio.result")" = ready ] || fail audio-stage', ':', AUDIOPREP),
    ('t9-audio', '[ ! -e "$new/dev/$node" ] && [ ! -L "$new/dev/$node" ] || fail "dev dirty $node"', ':', AUDIOPREP),
    ('t9-audio', '$BB ln -s /dev/null "$target" || fail "udev mask $rule"', ':', AUDIOPREP),
    ('t9-audio', '[ "$rules" -ge 1 ] || fail "udev mask count $rules"', ':', AUDIOPREP),
    ('t9-audio', '[ "$got" = "$want" ] || fail "speaker plan hash $got != $want"', ':', AUDIOPREP),
    ('t9-audio', '[ "${copied%% *}" = "$want" ] || fail plan-rehash', ':', AUDIOPREP),
    # m19-speaker: /dev/snd recursive scanner, pre-open holder scan, plan verification, single-run lock, and Run31 gates.
    ('speaker.c', 'if (depth == 0 && !S_ISDIR(st.st_mode)) return 1;', 'if (0) return 1;', SPEAKER),
    ('speaker.c', 'if (stat(path, &target) == 0) return 1;\n        return errno == ENOENT ? 0 : 1;', 'return 1;', SPEAKER),
    ('speaker.c', 'if (stat(path, &target) == 0) return 1;', 'if (stat(path, &target) == 0) return 0;', SPEAKER),
    ('speaker.c', 'if (snd_devs < 3u) return -ENODEV;', 'if (0) return -ENODEV;', SPEAKER),
    ('speaker.c', 'if (st.st_rdev == rdevs[i]) {\n                    rc = -EBUSY;',
     'if (0) {\n                    rc = -EBUSY;', SPEAKER),
    ('speaker.c', 'if (memcmp(ctx->plan_sha, sha_raw, 64u) != 0) return -EBADMSG;', 'if (0) return -EBADMSG;', SPEAKER),
    ('speaker.c', 'if (ctx->plan.duration_ms == 0u || ctx->plan.duration_ms > M19_SPK_MAX_DURATION_MS) return -EINVAL;',
     'if (ctx->plan.duration_ms == 0u) return -EINVAL;', SPEAKER),
    ('speaker.c', 'if (ctx->plan.peak_mdbfs > M19_SPK_MAX_PEAK_MDBFS) return -EINVAL;', 'if (0) return -EINVAL;', SPEAKER),
    ('speaker.c', 'if (ctx->plan.volume_level == 0u || ctx->plan.volume_level > M19_SPK_MAX_VOLUME_LEVEL) return -EINVAL;',
     'if (ctx->plan.volume_level == 0u) return -EINVAL;', SPEAKER),
    ('speaker.c', 'O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC', 'O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC', SPEAKER),
    ('speaker.c', 'return -EPERM; /* A session daemon never calls reboot(2); falls through to speaker_terminal_hold. */',
     'return 0;', SPEAKER),
    ('speaker.c', 'm11_snd_release(&ctx->snd);', '(void)0;', SPEAKER),
    ('speaker.c', 're_verified == 1 && re0_q12 > 0u && re1_q12 > 0u &&', 're0_q12 > 0u && re1_q12 > 0u &&', SPEAKER),
    ('speaker.c', 'r->bytes_played == plan->pcm.len &&', '1 &&', SPEAKER),
)


class Broken(Exception):
    """A mutant that does not apply or does not build: the check itself is wrong."""


def precompile_speaker_objects(obj_dir: Path):
    objs = []
    for idx, src in enumerate(SPK_FIXED_SRCS):
        obj = obj_dir / f'o{idx}_{src.stem}.o'
        built = subprocess.run(['gcc', *SPK_CFLAGS, f'-I{HERE}', '-c', str(src), '-o', str(obj)],
                               capture_output=True, timeout=120)
        if built.returncode:
            raise Broken(f'precompile failed for {src}:\n{built.stderr.decode("utf-8", "replace")}')
        objs.append(str(obj))
    return objs


def run(number, name, old, new, classes, spk_objs):
    """True when test.py fails on the mutant. Each mutant gets its own tree, so they run side by side."""
    source = (HERE / name).read_text(encoding='utf-8')
    if old not in source:
        raise Broken(f'mutant {number} does not apply to {name}: {old}')
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory) / 'm19'
        target = root / 'run5'
        (root / 'unlock').mkdir(parents=True)
        shutil.copytree(HERE, target, ignore=shutil.ignore_patterns('__pycache__'))
        for item in ('core.h', 'hash.c'):
            shutil.copy(HERE.parent / 'unlock' / item, root / 'unlock')
        (target / name).write_text(source.replace(old, new), encoding='utf-8', newline='\n')
        built = subprocess.run(['gcc', '-std=c11', '-O1', '-w', '-DM19_AUDIO_TEST', '../unlock/hash.c', 'audio.c', 'test-audio.c', '-o', 'driver'],
                               cwd=target, capture_output=True, timeout=120)
        if built.returncode:
            raise Broken(f'mutant {number} does not compile:\n{built.stderr.decode("utf-8", "replace")}')
        cmd = [sys.executable, 'test.py', '--failfast', '--driver', 'driver']
        if 'Speaker' in classes:
            built_spk = subprocess.run(['gcc', *SPK_CFLAGS, '-I.', 'speaker.c', *spk_objs, '-o', 'speaker-driver'],
                                       cwd=target, capture_output=True, timeout=120)
            if built_spk.returncode:
                raise Broken(f'mutant {number} speaker does not compile:\n{built_spk.stderr.decode("utf-8", "replace")}')
            cmd.extend(['--speaker-driver', 'speaker-driver'])
        cmd.extend(classes)
        try:
            # The first failure kills the mutant, so the rest of its classes need not run.
            result = subprocess.run(cmd, cwd=target, capture_output=True, timeout=600)
            return result.returncode != 0
        except subprocess.TimeoutExpired:
            return True


def main():
    for number, (name, old, _, _) in enumerate(MUTANTS):
        source = (HERE / name).read_text(encoding='utf-8')
        if old not in source:
            sys.exit(f'mutant {number} does not apply to {name}: {old}')
    with tempfile.TemporaryDirectory() as obj_tmp:
        spk_objs = precompile_speaker_objects(Path(obj_tmp))
        workers = max(1, min(8, os.cpu_count() or 1))
        with concurrent.futures.ThreadPoolExecutor(workers) as pool:
            futures = [pool.submit(run, number, *mutant, spk_objs) for number, mutant in enumerate(MUTANTS)]
            try:
                killed = [future.result() for future in futures]
            except Broken as error:
                for future in futures:
                    future.cancel()
                sys.exit(str(error))
    survivors = [(number, name, old) for number, ((name, old, _, _), dead) in enumerate(zip(MUTANTS, killed)) if not dead]
    print(f'{len(MUTANTS) - len(survivors)} of {len(MUTANTS)} R5 mutants killed, {workers} at a time')
    for survivor in survivors:
        print('SURVIVED', survivor)
    sys.exit(1 if survivors else 0)


if __name__ == '__main__':
    main()
