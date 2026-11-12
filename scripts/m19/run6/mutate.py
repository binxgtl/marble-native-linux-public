#!/usr/bin/env python3
"""Mutation check for R6: every mutant of m19-wifi, the stream, the sink, T9-wifi or T9-sound must fail test.py."""
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
M12 = ROOT / 'scripts/m12'

WIFI = ('WifiRunner',)
STAGE = ('WifiStage',)
SOUND = ('SoundPrep',)
SINK = ('Sink',)

M11_FLAGS = ('-std=c11', '-O1', '-w', '-DM11_ANCHOR_NATIVE', '-DM11_CUSTODIAN_NATIVE', '-DM11_ANCHOR_NATIVE_ION', f'-I{OWN}', f'-I{REPAIR}',
             f'-I{NATIVE}')
M11_FIXED = (
    HERE.parent / 'unlock/hash.c',
    *(REPAIR / f'{u}.c' for u in ('m11_gpr_engine', 'm11_shmem', 'm11_apm_protocol', 'm11_aw_protection', 'm11_strict_mock')),
    *(OWN / f'{u}.c' for u in ('m11_custodian', 'm11_pid1_anchor', 'm11_anchor_linux', 'm11_anchor_owner')),
    *(NATIVE / f'{u}.c' for u in ('gpr_transport_native', 'shmem_backend_native', 'dmabuf_pool_native', 'heap_node_native',
                                  'intent_journal_native', 'pdr_loop_native', 'terminal_native', 'custodian_runner_native',
                                  'custodian_boot_native', 'pd_session_native', 'custodian_entry_native', 'snd_backend_native',
                                  'speaker_plan_native')))
M12_FIXED = (M12 / 'run10/owner-supervisor.c', M12 / 'run5/cbc-evidence.c', M12 / 'next/caldb.c')

MUTANTS = (
    # m19-wifi: the checks before anything loads, M12's order and its fail-closed stops.
    ('wifi.c', '        if (got != want.v[i])\n            return -EXDEV;\n', '', WIFI),
    ('wifi.c', '    if (!text_is(c->fw_path, c->fw_want))\n', '    if (0)\n', WIFI),
    ('wifi.c', 'O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);\n    if (stamp < 0) {',
     'O_WRONLY | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);\n    if (stamp < 0) {', WIFI),
    ('wifi.c', '    if (read_text(c->stage, text, sizeof(text)) || strcmp(text, "staged\\n")) {', '    if (read_text(c->stage, text, sizeof(text))) {', WIFI),
    ('wifi.c', '    if (st.wifi_rc)\n        return finish(0, "load-wifi", st.wifi_rc);\n', '', WIFI),
    ('wifi.c', '        if (!driver_is(path, "cnss_pci"))\n            continue;\n', '', WIFI),
    ('wifi.c', '    closedir(directory);\n    return found == 1 ? 0 : found ? -EEXIST : -ENODEV;\n}\n\nstatic int module_loaded',
     '    closedir(directory);\n    return found >= 1 ? 0 : -ENODEV;\n}\n\nstatic int module_loaded', WIFI),
    ('wifi.c', '    if (st.wlan_rc)\n        return finish(0, "load-wlan", st.wlan_rc);\n', '', WIFI),
    ('wifi.c', '    if (!owner_idle())\n        return owner_fault ? -EPROTO : -ETIMEDOUT;\n', '', WIFI),
    ('wifi.c', '    st.firmware = cbc.firmware && !cbc.fault;', '    st.firmware = 1;', WIFI),
    ('wifi.c', '        if (owner_fault || cbc.fault)\n', '        if (0)\n', WIFI),
    ('wifi.c', '        if (cbc.requirement == M12_CAL_REQUIRED)\n', '        if (0)\n', WIFI),
    ('wifi.c', '    while (!m12_cbc_ready(&cbc, owner_idle(), 0)) {', '    while (0) {', WIFI),
    ('wifi.c', '        !driver_is(link, "cnss2") || !mhi_entries)', '        !mhi_entries)', WIFI),
    ('wifi.c', '    if (!module_loaded("qca6490") || !module_loaded("cnss_utils") || pci_ready(again, sizeof(again)) || strcmp(again, bdf) ||',
     '    if (!module_loaded("cnss_utils") || pci_ready(again, sizeof(again)) || strcmp(again, bdf) ||', WIFI),
    ('wifi.c', '            if (ready && publish(C->result, "fault owner\\n"))', '            if (0 && publish(C->result, "fault owner\\n"))', WIFI),
    ('wifi.c', '    char *start[] = {(char *)c->systemctl, "start", "--no-block", (char *)c->nm_unit, NULL};',
     '    char *start[] = {(char *)c->systemctl, "start", (char *)c->nm_unit, NULL};', WIFI),
    ('wifi.c', '    if (kmsg_fd < 0 || lseek(kmsg_fd, 0, SEEK_END) < 0)', '    if (kmsg_fd < 0)', WIFI),
    # The stream: never louder than the chord, the amplifier with the sound, the stop.
    ('stream.c', '        if (o > limit) o = limit;\n', '', SINK),
    ('stream.c', '        int32_t o = (int32_t)(((int64_t)v * gain_q15) / 32768);', '        int32_t o = v;', SINK),
    ('stream.c', '        if (!st->amp_on && (rc = amp_set(s, 1))) return rc;\n', '', SINK),
    ('stream.c', '    } else if (st->amp_on && t - st->last_loud_ms >= sio->idle_off_ms && (rc = amp_set(s, 0))) {', '    } else if (0) {', SINK),
    ('stream.c', '        if (!rc && !stopping && sio->stop_fn(sio->user)) {', '        if (0) {', SINK),
    ('stream.c', '    if (!rc) rc = switches_read(s, item);\n    rec(s, "phase=stream amp=%s rc=%d", item, rc);',
     '    rec(s, "phase=stream amp=%s rc=%d", item, rc);', SINK),
    # The sink: the qualifications and its stop.
    ('sink.c', '           r->amp_on == 1 && r->amp_off_verified == 0 && r->pdr_seen == 0 &&', '           r->amp_on == 1 && r->pdr_seen == 0 &&', SINK),
    ('sink.c', '           st->streaming == 1 && st->amp_on == 1;', '           st->streaming == 1;', SINK),
    ('sink.c', '           r->stage == M19_SPK_STREAMED && r->fail_step == 0 && r->rc == 0 &&', '           r->stage >= M11_SPK_PLAYED && r->fail_step == 0 && r->rc == 0 &&',
     SINK),
    ('sink.c', '    return terminate_requested || access(ctx->cfg.stop_path, F_OK) == 0;', '    return terminate_requested;', SINK),
    # T9-wifi: read-only, every hash, every count.
    ('t9-wifi', '[ "$(read_value "$R/sys/module/firmware_class/parameters/path")" = /run/m19/firmware ] || skip firmware-path\n', '', STAGE),
    ('t9-wifi', '[ "$($BB blockdev --getro "$modem_node")" = 1 ] || skip modem-writable\n', '', STAGE),
    ('t9-wifi', 'mount -t vfat -o ro,nosuid,nodev,noexec', 'mount -t vfat -o nosuid,nodev,noexec', STAGE),
    ('t9-wifi', '[ "$files" -eq 222 ] || skip "firmware count $files"\n', '', STAGE),
    ('t9-wifi', '(cd "$firmware" && $BB sha256sum -c -s "$plan/firmware.sha256") || skip firmware-hash\n', '', STAGE),
    ('t9-wifi', '[ "${got%% *}" = "$want" ] || skip ini-hash\n', '', STAGE),
    ('t9-wifi', '[ "$rows" -eq 13 ] && [ "$dlkm" -eq 1 ] || skip "list rows $rows $dlkm"\n', '', STAGE),
    ('t9-wifi', '"$HELPER" check "$dest/modules.list" "$dest/modules" "$dest/modules" || skip module-check\n', '', STAGE),
    ('t9-wifi', '[ "${got%% *}" = "$want" ] || skip "cnssd hash ${got%% *}"\n', '', STAGE),
    ('t9-wifi', '$BB chmod 600 "$connections/m19-wifi.nmconnection" || skip profile-mode\n', '', STAGE),
    ('t9-wifi', ' undo || die "cleanup after $*"\n', ' undo || :\n', STAGE),
    # T9-sound: R5b's checks, the FIFO.
    ('t9-sound', ' [ ! -e "$new/dev/$node" ] && [ ! -L "$new/dev/$node" ] || fail "dev dirty $node"\n', '', SOUND),
    ('t9-sound', '$BB mkfifo -m 600 "$new/run/m19/sink/fifo" || fail fifo\n', '', SOUND),
    ('t9-sound', '[ "$rules" -ge 1 ] || fail "udev mask count $rules"\n', '', SOUND),
)


class Broken(Exception):
    pass


def compile_obj(cmd, label):
    built = subprocess.run(cmd, capture_output=True, timeout=180)
    if built.returncode:
        raise Broken(f'precompile failed for {label}:\n{built.stderr.decode("utf-8", "replace")}')


def precompile(obj_dir):
    jobs, m11, m12 = [], [], []
    for index, src in enumerate(M11_FIXED):
        obj = obj_dir / f'm11_{index}_{src.stem}.o'
        m11.append(str(obj))
        jobs.append((['gcc', *M11_FLAGS, '-c', str(src), '-o', str(obj)], str(src)))
    for index, src in enumerate(M12_FIXED):
        obj = obj_dir / f'm12_{index}_{src.stem}.o'
        m12.append(str(obj))
        jobs.append((['gcc', '-std=c11', '-O1', '-w', '-c', str(src), '-o', str(obj)], str(src)))
    with concurrent.futures.ThreadPoolExecutor(max(1, min(8, os.cpu_count() or 1))) as pool:
        for future in [pool.submit(compile_obj, cmd, label) for cmd, label in jobs]:
            future.result()
    return m11, m12


def build_wifi(src_dir, m12, out):
    built = subprocess.run(['gcc', '-std=c11', '-O1', '-w', '-DM19_WIFI_TEST', 'wifi.c', 'wifi-main.c', *m12, '-o', str(out)], cwd=src_dir,
                           capture_output=True, timeout=180)
    if built.returncode:
        raise Broken(f'wifi build failed:\n{built.stderr.decode("utf-8", "replace")}')


def build_sink(src_dir, m11, out):
    built = subprocess.run(['gcc', *M11_FLAGS, '-I.', 'stream.c', 'sink.c', 'test-sink.c', *m11, '-o', str(out)], cwd=src_dir,
                           capture_output=True, timeout=180)
    if built.returncode:
        raise Broken(f'sink build failed:\n{built.stderr.decode("utf-8", "replace")}')


def tree(directory):
    """scripts/m19/run6 with what its includes reach: ../unlock and ../../m12."""
    scripts = Path(directory) / 'scripts'
    target = scripts / 'm19/run6'
    shutil.copytree(HERE, target, ignore=shutil.ignore_patterns('__pycache__'))
    (scripts / 'm19/unlock').mkdir(parents=True)
    for item in ('core.h', 'hash.c'):
        shutil.copy(HERE.parent / 'unlock' / item, scripts / 'm19/unlock')
    for sub in ('run10', 'run5', 'next', 'run7'):
        shutil.copytree(M12 / sub, scripts / 'm12' / sub, ignore=shutil.ignore_patterns('__pycache__', 'fixtures'))
    return target


def run(number, name, old, new, classes, base, m11, m12):
    source = (HERE / name).read_text(encoding='utf-8')
    if source.count(old) != 1:
        raise Broken(f'mutant {number} does not apply once to {name}: {old!r}')
    with tempfile.TemporaryDirectory() as directory:
        target = tree(directory)
        (target / name).write_text(source.replace(old, new), encoding='utf-8', newline='\n')
        wifi, sink = base['wifi'], base['sink']
        if name == 'wifi.c':
            wifi = target / 'test-wifi'
            build_wifi(target, m12, wifi)
        if name in ('stream.c', 'sink.c'):
            sink = target / 'test-sink'
            build_sink(target, m11, sink)
        cmd = [sys.executable, 'test.py', '--failfast', '--wifi', str(wifi), '--cnssd', str(base['cnssd']), '--sink', str(sink), *classes]
        try:
            result = subprocess.run(cmd, cwd=target, stdin=subprocess.DEVNULL, capture_output=True, timeout=300, start_new_session=True)
            return result.returncode != 0
        except subprocess.TimeoutExpired:
            return True


def main():
    with tempfile.TemporaryDirectory() as directory:
        work = Path(directory)
        (work / 'obj').mkdir()
        m11, m12 = precompile(work / 'obj')
        source = tree(work / 'base')
        base = {'wifi': work / 'test-wifi', 'sink': work / 'test-sink', 'cnssd': work / 'test-cnssd'}
        build_wifi(source, m12, base['wifi'])
        build_sink(source, m11, base['sink'])
        built = subprocess.run(['gcc', '-std=c11', '-O1', '-w', 'test-cnssd.c', '-o', str(base['cnssd'])], cwd=source, capture_output=True)
        if built.returncode:
            raise Broken(built.stderr.decode('utf-8', 'replace'))
        # The base must pass, or no mutant result means anything.
        for classes in (WIFI + STAGE + SOUND, SINK):
            check = subprocess.run([sys.executable, 'test.py', '--wifi', str(base['wifi']), '--cnssd', str(base['cnssd']), '--sink', str(base['sink']),
                                    *classes], cwd=source, stdin=subprocess.DEVNULL, capture_output=True, timeout=600, start_new_session=True)
            if check.returncode:
                print(check.stdout.decode('utf-8', 'replace') + check.stderr.decode('utf-8', 'replace'))
                raise Broken(f'the unmutated tests fail: {classes}')
        survivors = []
        with concurrent.futures.ThreadPoolExecutor(max(1, min(4, os.cpu_count() or 1))) as pool:
            futures = {pool.submit(run, number, name, old, new, classes, base, m11, m12): (number, name, old)
                       for number, (name, old, new, classes) in enumerate(MUTANTS, 1)}
            for future in concurrent.futures.as_completed(futures):
                number, name, old = futures[future]
                if not future.result():
                    survivors.append((number, name, old))
        for number, name, old in sorted(survivors):
            print(f'SURVIVED {number} {name}: {old!r}')
        print(f'R6 mutants killed: {len(MUTANTS) - len(survivors)} of {len(MUTANTS)}')
        return 1 if survivors else 0


if __name__ == '__main__':
    sys.exit(main())
