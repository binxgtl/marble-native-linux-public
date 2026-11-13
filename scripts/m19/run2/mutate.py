#!/usr/bin/env python3
"""Mutation check for R2 to R4: every mutant of the hand-off, the reporter, T9, the plans, PID 1, the shim or the probes must fail test.py."""
import argparse
import concurrent.futures
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
HANDOFF = ('Kthread', 'Sweep', 'Handoff')
MUTANTS = (
    # R6: landscape, T12-wifi, T12-audio through the sound server, the redaction, r6plan and pid6.
    ('r6plan.py', "ROTATE = 'right'", "ROTATE = 'left'", ('Plan6',)),
    # R7: the keypad unit, started by the reporter only, and R7's own target.
    ('r7plan.py', 'ConditionPathExists=/run/m19/ce/ce.sock\n', '', ('Plan7',)),
    ('r7plan.py', 'ExecStart=/run/m19/m19-ce-prompt /run/m19/ce/ce.sock /run/m19/ce.result\n', 'ExecStart=/run/m19/m19-ce-prompt\n', ('Plan7',)),
    ('r7plan.py', 'StandardOutput=null\n', 'StandardOutput=journal\n', ('Plan7',)),
    ('r7plan.py', "              'systemd/system/marble-ce.service': CE})", "              })", ('Plan7',)),
    ('r7plan.py', "    out['m19/r2/default'] = b'm19-r7.target\\n'", "    out['m19/r2/default'] = b'm19-r6.target\\n'", ('Plan7',)),
    ('pid7.c', '    {"T9-ce", "/m19/t9-ce", 30000, M19_STEP_REQUIRED},\n', '', ('Static',)),
    ('pid7.c', '.keep_root = "/tee", ', '', ('Static',)),
    ('pid7.c', '.ce = 1, ', '.ce = 0, ', ('Static',)),
    ('r6plan.py', "TOUCH_MATRIX = '0 1 0 -1 0 1 0 0 1'", "TOUCH_MATRIX = '0 -1 1 1 0 0 0 0 1'", ('Plan6',)),
    ('r6plan.py', "NETWORK_MASKED = ('NetworkManager-wait-online.service',)", 'NETWORK_MASKED = ()', ('Plan6',)),
    ('r6plan.py', 'ConditionPathExists=/run/m19/wifi.ready\n', '', ('Plan6',)),
    ('r6plan.py', 'unmanaged-devices=except:interface-name:wlan0\n', 'unmanaged-devices=except:type:wifi\n', ('Plan6',)),
    ('r6plan.py', "              'systemd/network/10-m19-wlan.link': WLAN_LINK})", '              })', ('Plan6',)),
    ('r6plan.py', 'NamePolicy=\nMACAddressPolicy=none', 'MACAddressPolicy=none', ('Plan6',)),
    ('r6plan.py', "HIDDEN = tuple(name for name in r3plan.HIDDEN if name != 'nm-applet')", 'HIDDEN = r3plan.HIDDEN', ('Plan6',)),
    ('r6plan.py', "HIDDEN = tuple(name for name in r3plan.HIDDEN if name != 'nm-applet')",
     "HIDDEN = tuple(name for name in r3plan.HIDDEN if name not in ('nm-applet', 'pulseaudio'))", ('Plan6',)),
    ('r6plan.py', "              'systemd/system/marble-pulse.service': PULSE,\n", '', ('Plan6',)),
    ('r6plan.py', 'Environment=HOME=/run/m19/session XDG_RUNTIME_DIR=/run/m19/xdg\nExecStart=/usr/bin/pulseaudio',
     'ExecStart=/usr/bin/pulseaudio', ('Plan6',)),
    ('r6plan.py', ' --exit-idle-time=-1', '', ('Plan6',)),
    ('pid6.c', '    .pulse_unit = "marble-pulse.service", .held_dir = "/dev/m11-snd", .held_uid = 0,\n', '', ('Static',)),
    ('r6plan.py', "WPA_DROPIN = '''[Service]\nLogLevelMax=warning\n'''", "WPA_DROPIN = '''[Service]\n'''", ('Plan6',)),
    ('pid6.c', '    {"T9-wifi", "/m19/t9-wifi", 240000, M19_STEP_REQUIRED},\n', '', ('Static',)),
    ('pid6.c', '.rotation = "right",', '.rotation = NULL,', ('Static',)),
    ('pid6.c', '.idle_wait_ms = 12000,', '.idle_wait_ms = 1200,', ('Static',)),
    ('report.c', 'd->landscape_ok = !strcmp(d->rotation, c->rotation) && d->width > d->height && d->height > 0;',
     'd->landscape_ok = !strcmp(d->rotation, c->rotation);', ('Landscape',)),
    ('report.c', '&& d.touch_ok && guard_ok && (!c->rotation || d.landscape_ok);', '&& d.touch_ok && guard_ok;', ('Landscape',)),
    ('report.c', '                if (at[used] == \'(\' || sscanf(at + used, "%15s", word) != 1)', '                if (sscanf(at + used, "%15s", word) != 1)',
     ('Landscape',)),
    ('report.c', '    w->wifi_ok = w->ready && w->connected && w->route && w->ping;', '    w->wifi_ok = w->ready && w->connected && w->route;', ('WifiReport',)),
    ('report.c', '        if (destination == 0 && (flags & 0x3) == 0x3 && via) {', '        if (destination == 0 && via) {', ('WifiReport',)),
    ('report.c', '                    w->connected |= !strcmp(line, want);', '                    w->connected |= strstr(line, ":connected") != NULL;', ('WifiReport',)),
    ('report.c', '        if (w->connected || now >= end || (!w->ready && strcmp(w->result, "none") && strncmp(w->result, "ready", 5)))',
     '        if (w->connected || now >= end)', ('WifiReport',)),
    ('report.c', "            memset(at, '*', length);\n", '', ('WifiReport',)),
    ('report.c', "                    p[j] = 'x';\n", '', ('WifiReport',)),
    ('report.c', "            if (report[k] != '.')\n                report[k] = 'x';\n", '', ('WifiReport',)),
    ('report.c', '    if (c->wifi) {\n        /* Network names', '    if (0) {\n        /* Network names', ('WifiReport',)),
    ('report.c', '    int all_ok = init_ok && state_ok && targets_ok && writes_ok && ro_ok && mounts_ok && !write_warning && desktop_ok && gpu_ok && audio_ok &&\n                 wifi_ok && ce_ok;',
     '    int all_ok = init_ok && state_ok && targets_ok && writes_ok && ro_ok && mounts_ok && !write_warning && desktop_ok && gpu_ok && audio_ok &&\n                 ce_ok;',
     ('WifiReport',)),
    # R7: T12-ce, judged by the broker's status and Android's own names; the TEE island kept through the hand-off.
    ('report.c', '                 wifi_ok && ce_ok;', '                 wifi_ok;', ('CeReport',)),
    ('report.c', '    e->ce_ok = e->status_ok && e->entry_seen;', '    e->ce_ok = e->status_ok;', ('CeReport',)),
    ('report.c', '    e->ce_ok = e->status_ok && e->entry_seen;', '    e->ce_ok = e->entry_seen;', ('CeReport',)),
    ('report.c', '    e->status_ok = !strcmp(e->status, "OK");', '    e->status_ok = e->result_seen;', ('CeReport',)),
    ('report.c', '            e->entry_seen |= !strcmp(entry->d_name, c->ce_entry);', '            e->entry_seen = 1;', ('CeReport',)),
    ('report.c', '        if (e->unit_rc != 0 || now >= deadline)', '        if (e->unit_rc != 0)', ('CeReport',)),
    ('report.c', '    if (strncmp(text, head, sizeof(head) - 1))\n        return;\n    const char *word = text + sizeof(head) - 1;',
     '    const char *word = strstr(text, "status=") ? strstr(text, "status=") + 7 : text;', ('CeReport',)),
    ('report.c', '            audio_ok = audio_ok && k.sink_ok;', '            audio_ok = audio_ok;', ('SinkReport',)),
    # R6b: PulseAudio started by the reporter, only once the sink streams, its unit judged; Run31's held directory.
    ('report.c', '        k->pulse_unit_rc = section(pulse_argv, SECTION_CAP / 16, c->command_ms);', '        k->pulse_unit_rc = 0;', ('SinkReport',)),
    ('report.c', '    if (k->streaming && c->pulse_unit) {', '    if (c->pulse_unit) {', ('SinkReport',)),
    ('report.c', '                 (!c->pulse_unit || k->pulse_unit_rc == 0) &&\n', '', ('SinkReport',)),
    ('report.c', '    if (fstat(fd, &st) || st.st_uid != uid || (st.st_mode & 07777) != 0700) {', '    if (fstat(fd, &st) || (st.st_mode & 07777) != 0700) {',
     ('SinkReport',)),
    ('report.c', '    if (fstat(fd, &st) || st.st_uid != uid || (st.st_mode & 07777) != 0700) {', '    if (fstat(fd, &st) || st.st_uid != uid) {',
     ('SinkReport',)),
    ('report.c', '    return entries == 0;\n}', '    return 1;\n}', ('SinkReport',)),
    ('report.c', '    int fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);\n    if (fd < 0)\n        return 0;\n    struct stat st;\n    if (fstat(fd, &st) || st.st_uid',
     '    int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);\n    if (fd < 0)\n        return 0;\n    struct stat st;\n    if (fstat(fd, &st) || st.st_uid',
     ('SinkReport',)),
    ('report.c', '        if (k->streaming && c->held_dir && !strcmp(path, c->held_dir) && held_dir_empty(path, c->held_uid)) {',
     '        if (c->held_dir && !strcmp(path, c->held_dir) && held_dir_empty(path, c->held_uid)) {', ('SinkReport',)),
    ('report.c', '        if (k->streaming && c->held_dir && !strcmp(path, c->held_dir) && held_dir_empty(path, c->held_uid)) {',
     '        if (k->streaming && c->held_dir && held_dir_empty(path, c->held_uid)) {', ('SinkReport',)),
    ('report.c', '        k->tone_peaks = k->peak_in >= 30000 && k->peak_out >= 9000 && k->peak_out <= 10362;',
     '        k->tone_peaks = k->peak_in >= 30000 && k->peak_out >= 9000;', ('SinkReport',)),
    ('report.c', '                 k->amp_on_seen && k->amp_idle_off;', '                 k->amp_on_seen;', ('SinkReport',)),
    ('report.c', '                 k->pulse_sink && k->pulse_default && k->tone_rc == 0 && k->amp_off_before && k->tone_loud && k->tone_peaks &&',
     '                 k->pulse_sink && k->tone_rc == 0 && k->amp_off_before && k->tone_loud && k->tone_peaks &&', ('SinkReport',)),
    ('report.c', '        k->tone_loud = k->loud_after != LONG_MIN && k->loud_before != LONG_MIN && k->loud_after - k->loud_before >= 172800; /* 90 % */',
     '        k->tone_loud = k->loud_after != LONG_MIN;', ('SinkReport',)),
    ('report.c', '        k->streaming = kv_long(text, "streaming") == 1 && !strcmp(k->state, "streaming");',
     '        k->streaming = !strcmp(k->state, "streaming");', ('SinkReport',)),
    ('report.c', '                 k->volume_level <= 8 && is_hex64(k->plan_sha) && k->holder_alive && k->holder_fds >= 8 && k->private_clean &&',
     '                 k->volume_level <= 8 && is_hex64(k->plan_sha) && k->holder_fds >= 8 && k->private_clean &&', ('SinkReport',)),
    # R5a / R5b: T9-gpu on top of the audio stage, recursive /dev/snd scan, T12-audio speaker gate, r5plan, and pid5.
    ('t9-gpu', ' base=147', ' base=102', ('GpuScript',)),
    ('t9-gpu', '[ "$($BB cat "$R/run/m19/audio.result")" = ready ] || fail audio-stage', ':', ('GpuScript',)),
    ('report.c', '!write_warning && desktop_ok && gpu_ok && audio_ok &&\n', '!write_warning && desktop_ok && gpu_ok &&\n', ('Audio',)),
    ('report.c', '    a->card = -1;', '    a->card = 0;', ('Audio',)),
    ('report.c', 'a->audio_ok = a->card >= 0 && a->control && a->playback && a->capture && !a->snd_nodes && (!c->speaker_unit || sp->speaker_ok);',
     'a->audio_ok = a->card >= 0 && a->playback && a->capture && !a->snd_nodes && (!c->speaker_unit || sp->speaker_ok);', ('Audio',)),
    ('report.c', 'a->audio_ok = a->card >= 0 && a->control && a->playback && a->capture && !a->snd_nodes && (!c->speaker_unit || sp->speaker_ok);',
     'a->audio_ok = a->card >= 0 && a->control && a->capture && !a->snd_nodes && (!c->speaker_unit || sp->speaker_ok);', ('Audio',)),
    ('report.c', 'a->audio_ok = a->card >= 0 && a->control && a->playback && a->capture && !a->snd_nodes && (!c->speaker_unit || sp->speaker_ok);',
     'a->audio_ok = a->card >= 0 && a->control && a->playback && !a->snd_nodes && (!c->speaker_unit || sp->speaker_ok);', ('Audio',)),
    ('report.c', 'a->audio_ok = a->card >= 0 && a->control && a->playback && a->capture && !a->snd_nodes && (!c->speaker_unit || sp->speaker_ok);',
     'a->audio_ok = a->card >= 0 && a->control && a->playback && a->capture && (!c->speaker_unit || sp->speaker_ok);', ('Audio',)),
    ('report.c', 'a->audio_ok = a->card >= 0 && a->control && a->playback && a->capture && !a->snd_nodes && (!c->speaker_unit || sp->speaker_ok);',
     'a->audio_ok = a->card >= 0 && a->control && a->playback && a->capture && !a->snd_nodes;', ('SpeakerReport',)),
    ('report.c', '    if (depth == 0 && !S_ISDIR(st.st_mode))\n        return 1;', '    if (0)\n        return 1;', ('Audio',)),
    ('report.c', '        if (stat(path, &target) == 0)\n            return 1;\n        return errno == ENOENT ? 0 : 1;',
     '        if (0)\n            return 1;\n        return errno == ENOENT ? 0 : 1;', ('Audio',)),
    ('report.c', '        return errno == ENOENT ? 0 : 1;', '        return 1;', ('Audio',)),
    ('report.c', '    if (!S_ISDIR(st.st_mode))\n        return 1;', '    if (!S_ISDIR(st.st_mode))\n        return 0;', ('Audio',)),
    ('report.c', '        sp->re_verified == 1 &&\n', '', ('SpeakerReport',)),
    ('report.c', '        sp->amp_off_verified == 1 &&\n', '', ('SpeakerReport',)),
    ('report.c', '        sp->bytes_played == sp->pcm_bytes &&\n', '', ('SpeakerReport',)),
    ('report.c', '        sp->unmap_attempted == 0 &&\n', '', ('SpeakerReport',)),
    ('report.c', '        sp->holder_alive &&\n', '', ('SpeakerReport',)),
    ('report.c', '        sp->holder_fds >= 8 &&\n', '        sp->holder_fds >= 0 &&\n', ('SpeakerReport',)),
    ('report.c', '        sp->private_clean;', '        1;', ('SpeakerReport',)),
    ('report.c', ' && major > 0;', ';', ('Audio',)),
    ('report.c', 'used && index >= 0 && strstr(line, c->audio_card) && a->card < 0)', 'used && index >= 0 && a->card < 0)', ('Audio',)),
    ('report.c', 'if (!strncmp(line, prefix, strlen(prefix))) {', 'if (1) {', ('Audio',)),
    ('report.c', '    if (c->audio) {\n        struct audio a;', '    if (0) {\n        struct audio a;', ('Audio',)),
    ('pid5.c', '    {"T3-audio", "/m19/t3-audio", 120000, M19_STEP_REQUIRED},\n', '', ('Static',)),
    ('pid5.c', '    {"T9-audio", "/m19/t9-audio", 30000, M19_STEP_REQUIRED},\n', '', ('Static',)),
    ('pid5.c', '.speaker_unit = "marble-speaker.service",', '.speaker_unit = NULL,', ('Static',)),
    ('pid5.c', '.bootstrap = "/m19/bootstrap-audio"', '.bootstrap = "/m19/bootstrap"', ('Static',)),
    ('pid5.c', '"00ff0000", "600000"', '"00ffff00", "600000"', ('Static',)),
    ('r5plan.py', "'alsa-restore.service', ", '', ('Plan5',)),
    ('r5plan.py', 'KillMode=none\n', '', ('Plan5',)),
    ('r5plan.py', "UDEV_MASKED = ('60-persistent-alsa.rules',)", 'UDEV_MASKED = ()', ('Plan5',)),
    ('handoff.c', 'if (left)\n        return fail(tty, h, "survivors", left);', 'if (0)\n        return fail(tty, h, "survivors", left);', HANDOFF),
    ('handoff.c', '!h->keep_root && umount2(h->android, MNT_DETACH))', '!h->keep_root && umount2(h->android, MNT_DETACH) && 0)', HANDOFF),
    ('handoff.c', 'if (!h->keep_root && umount2(h->android, MNT_DETACH))', 'if (umount2(h->android, MNT_DETACH))', HANDOFF),
    ('handoff.c', '        if (keeping && kept(h, pid, &keep))\n            continue;\n', '', HANDOFF),
    ('handoff.c', 'return !stat(path, &st) && st.st_dev == keep->st_dev && st.st_ino == keep->st_ino;', 'return !stat(path, &st);', HANDOFF),
    ('handoff.c', 'int keeping = h->keep_root && !stat(h->keep_root, &keep);', 'int keeping = h->keep_root != NULL;', HANDOFF),
    ('handoff.c', 'parent.st_dev == root.st_dev', '0', HANDOFF),
    ('handoff.c', 'if (access(path, X_OK))', 'if (0 && access(path, X_OK))', HANDOFF),
    ('handoff.c', 'return !!(flags & PF_KTHREAD_FLAG);', 'return 0;', HANDOFF),
    ('handoff.c', 'if (kill_them)\n            (void)h->signal((pid_t)pid, SIGKILL);', '', HANDOFF),
    ('handoff.c', 'pid <= 1 || pid == (long)h->self', 'pid < 1 || pid == (long)h->self', HANDOFF),
    ('handoff.c', 'if (!(n < 0 && error == ESRCH))\n                count++;', '', HANDOFF),
    ('handoff.c', '(void)m19_wire_line(tty, h->pace_ms, M19_DEVICE_STEP " T10-handoff OK 0 0");', '', HANDOFF),
    ('handoff.c', 'mount(".", "/", NULL, MS_MOVE, NULL)', 'mount(".", "/", NULL, MS_BIND, NULL)', HANDOFF),
    ('handoff.c', '*moved = 1;', '', HANDOFF),
    ('report.c', 'int state_ok = !strcmp(state, "running") || !strcmp(state, "degraded");', 'int state_ok = 1;', ('Report',)),
    ('report.c', 'int init_ok = n > 0 && !strcmp(exe, c->expected_init);', 'int init_ok = 1;', ('Report',)),
    ('report.c', 'section(active, SECTION_CAP, c->command_ms) == 0;', 'section(active, SECTION_CAP, c->command_ms) >= 0;', ('Report',)),
    ('report.c', 'return count >= 7 && !field[4] && !field[6] && !field[11] && !field[13];', 'return count >= 7 && !field[4];', ('Report',)),
    ('report.c', 'if (!ro)\n        *ro_ok = 0;', '', ('Report',)),
    ('report.c', 'if (read_small(inner, flag, sizeof(flag)) || strcmp(flag, "1\\n")) {', 'if (0) {', ('Report',)),
    ('report.c', 'if (!disks) {', 'if (0) {', ('Report',)),
    ('report.c', 'if (!starts_ro(options) || !starts_ro(super)) {', 'if (!starts_ro(options)) {', ('Report',)),
    ('report.c', 'return ok && root && lines > 0;', 'return ok && lines > 0;', ('Report',)),
    ('report.c', 'int write_warning = memmem(', 'int write_warning = 0 && memmem(', ('Report',)),
    ('report.c', 'if (taken == limit)', 'if (0)', ('Report',)),
    ('report.c', 'all_ok ? GREEN : YELLOW', 'GREEN', ('Report',)),
    ('report.c', '"tmpfs", "proc"', '"f2fs", "tmpfs", "proc"', ('Report',)),
    ('t9-root', '$BB blockdev --setro "$node" || fail "set read-only $name"', ':', ('Script',)),
    ('t9-root', '[ "$($BB blockdev --getro "$node")" = 1 ] || fail "read-only check $name"', ':', ('Script',)),
    ('t9-root', '$BB mount -o remount,bind,ro "$new" || fail root-read-only', ':', ('Script',)),
    ('t9-root', 'case "$options" in ro|ro,*) ;; *) fail "root-read-only-check $options";; esac', ':', ('Script',)),
    ('t9-root', '  safe_dir "$at" || return 1', '  :', ('Script',)),
    ('t9-root', 'machine=uninitialized; : >"$new/etc/machine-id" || fail machine-id', 'machine=uninitialized', ('Script',)),
    ('t9-root', 'selinux=hidden; $BB rm -f "$new/etc/selinux/config" || fail selinux-config', 'selinux=hidden', ('Script',)),
    ('t9-root', '$BB ln -s "$default_unit" "$new/etc/systemd/system/default.target" || fail default-target', ':', ('Script',)),
    ('t9-root', 'case "$default_unit" in m19-r[0-9].target) ;; *) fail "default target $default_unit";; esac', ':', ('Script',)),
    ('t9-root', '$BB ln -s /dev/null "$path" || fail "mask $unit"', ':', ('Script',)),
    ('t9-root', '$BB ln -s /dev/null "$path" || fail "mask generator $name"', ':', ('Script',)),
    ('t9-root', 'case "$class" in mem/*|tty/*|drm/*) ;; *) fail "node class $name";; esac', ':', ('Script',)),
    ('t9-root', '[ "${hash%% *}" = "$ROOTFS_PROBE_SHA256" ] || fail probe-hash', ':', ('Script',)),
    ('t9-root', '[ ! -e "$new" ] && [ ! -L "$new" ] || fail newroot-exists', ':', ('Script',)),
    ('t9-root', '$BB rm -f "$new/etc/crypttab" || fail crypttab', ':', ('Script',)),
    ('t9-root', '[ "$blocks" -gt 0 ] || fail no-block-device', ':', ('Script',)),
    ('t9-root', "[ -z \"$R\" ] || [ ! -L \"$R\" ] || fail root", ':', ('Script',)),
    ('r2plan.py', "'udisks2.service', ", '', ('Plan',)),
    ('r2plan.py', "('ttyGS0', 'tty/ttyGS0', '600'), ", "('ttyGS0', 'tty/ttyGS0', '600'), ('sg0', 'scsi_generic/sg0', '600'), ", ('Plan',)),
    ('r2plan.py', 'IgnoreOnIsolate=yes\n', '', ('Plan',)),
    ('r2plan.py', 'ReadKMsg=no\n', '', ('Plan',)),
    ('r2plan.py', "'systemd-fstab-generator', ", '', ('Plan',)),
    ('pid2.c', '{"T9-root", "/m19/t9-root", 120000, M19_STEP_REQUIRED},', '{"T9-root", "/m19/t9-root", 120000, 0},', ('Static',)),
    ('pid2.c', 'if (m19_run_main(&run) == M19_END_PASS) {', 'if (m19_run_main(&run) != M19_END_BOOTSTRAP) {', ('Static',)),    ('report.c', 'd->mode_ok = d->xrandr_hz > c->want_hz - 1.0 && d->xrandr_hz < c->want_hz + 1.0;', 'd->mode_ok = 1;', ('Desktop',)),
    ('report.c', 'd->vblank_ok = d->crtc >= 0 && d->vblank_hz > c->want_hz * 0.96 && d->vblank_hz < c->want_hz * 1.04;', 'd->vblank_ok = d->crtc >= 0;', ('Desktop',)),
    ('report.c', 'd->touch_ok = d->touch_device && d->irq_delta > 0 && d->events > 0;', 'd->touch_ok = d->touch_device && d->events > 0;', ('Desktop',)),
    ('report.c', 'd->touch_ok = d->touch_device && d->irq_delta > 0 && d->events > 0;', 'd->touch_ok = d->irq_delta > 0 && d->events > 0;', ('Desktop',)),
    ('report.c', 'd->touch_ok = d->touch_device && d->irq_delta > 0 && d->events > 0;', 'd->touch_ok = d->touch_device && d->irq_delta > 0;', ('Desktop',)),
    ('report.c', 'desktop_ok = d.x_ok && d.session_ok && d.mode_ok && d.vblank_ok && d.touch_ok && guard_ok && (!c->rotation || d.landscape_ok);',
     'desktop_ok = d.x_ok;', ('Desktop',)),
    ('report.c', 'if (c->desktop && d.x_ok)\n        return 0;', '', ('Desktop',)),
    ('report.c', "|| line[n - name - 1] != ' ')", '|| 0)', ('Desktop',)),
    ('report.c', 'return seen[0] && seen[1] && seen[2];', 'return seen[0];', ('Desktop',)),
    ('report.c', "if (*end == '*') {", 'if (1) {', ('Desktop',)),
    ('t9-desktop', '$BB grep -qx "$mode" "$panel/modes" || fail "panel mode $mode"', ':', ('DesktopScript',)),
    ('t9-desktop', '[ -z "$found" ] || fail "touch duplicate"', ':', ('DesktopScript',)),
    ('t9-desktop', '[ "$($BB cat "$panel/status")" = connected ] || fail panel-status', ':', ('DesktopScript',)),
    ('t9-desktop', 'safe_dir "$src/root" && safe_dir "$src/root/.config" && safe_dir "$src/root/.config/xfce4" || fail xfce-settings', ':', ('DesktopScript',)),
    ('t9-desktop', '$BB chmod 700 "$home" || fail home', ':', ('DesktopScript',)),
    ('t9-desktop', 'Hidden=true', 'Hidden=false', ('DesktopScript',)),
    ('t9-desktop', '  $BB rm -f "$path" || fail "prune $path"', '  :', ('DesktopScript',)),
    ('t9-desktop', 'for kind in l p s c b; do', 'for kind in p s c b; do', ('DesktopScript',)),
    ('t9-desktop', 'case "$touch" in \'\'|*[!a-z0-9_]*) fail "touch name $touch";; esac', ':', ('DesktopScript',)),
    ('t9-desktop', 'safe_dir "$new/run/m19" && safe_dir "$new/dev" || fail newroot', ':', ('DesktopScript',)),
    ('r3plan.py', "'light-locker', ", '', ('Plan3',)),
    ('r3plan.py', "'poweroff.target', ", '', ('Plan3',)),
    ('r3plan.py', "lines.append('OnFailure=marble-xorg-fallback.service')", 'pass', ('Plan3',)),
    ('r3plan.py', 'TimeoutStartSec=150\n', '', ('Plan3',)),
    ('r3plan.py', 'i=$$((i+1)); [ "$$i" -lt 600 ]', 'i=$((i+1)); [ "$i" -lt 600 ]', ('Plan3',)),
    ('pid3.c', '{"T9-desktop", "/m19/t9-desktop", 60000, M19_STEP_REQUIRED},', '', ('Static',)),
    ('report.c', 'if (battery != LONG_MIN && battery >= g->battery_limit)', 'if (0)', ('Guard',)),
    ('report.c', 'else if (zone != LONG_MIN && zone >= g->zone_limit)', 'else if (0)', ('Guard',)),
    ('report.c', 'else if (busy_since && now - busy_since >= g->busy_ms)', 'else if (0)', ('Guard',)),
    ('report.c', 'else if (now - start >= g->session_ms)', 'else if (0)', ('Guard',)),
    ('report.c', 'int status = capture(stop, out, sizeof(out), &taken, g->command_ms);', 'int status = 0;', ('Guard',)),
    ('report.c', 'if (status)\n                (void)capture(kill_units', 'if (0)\n                (void)capture(kill_units', ('Guard',)),
    ('report.c', 'execv(g->display, argv);\n            return 70;', 'return 70;', ('Guard',)),
    ('report.c', '*busy = sum - field[3] - field[4]; /* idle and iowait */', '*busy = 0;', ('Guard',)),
    ('report.c', 'if (read_long(path, &value) || value <= -40000 || value >= 200000)', 'if (read_long(path, &value))', ('Guard',)),
    ('report.c', 'int guard_ok = guard_active && !tripped;', 'int guard_ok = 1;', ('Desktop',)),
    ('r3plan.py', 'm19-r3-guard.service marble-xorg.service', 'marble-xorg.service', ('Plan3',)),
    ('pid3.c', '.battery_limit = 420', '.battery_limit = 4200', ('Static',)),
    ('xorg-shim.c', 'int keep = p && (p->flags & (M19_PROP_RANGE | M19_PROP_ENUM | M19_PROP_BLOB));', 'int keep = 1;', ('Shim',)),
    ('xorg-shim.c', 'int keep = p && (p->flags & (M19_PROP_RANGE | M19_PROP_ENUM | M19_PROP_BLOB));', 'int keep = p && (p->flags & (M19_PROP_RANGE | M19_PROP_ENUM));', ('Shim',)),
    ('xorg-shim.c', '                c->prop_values[kept] = c->prop_values[i];', '', ('Shim',)),
    ('xorg-shim.c', '    c->count_props = kept;', '', ('Shim',)),
    ('xorg-shim.c', 'if (guarded && act && trapped(number))', 'if (0)', ('Shim',)),
    ('xorg-shim.c', 'real = (get_connector_fn)dlsym(RTLD_NEXT, "drmModeGetConnectorCurrent");\n    struct m19_connector *c = real ? real(fd, connector_id) : NULL;\n    filter(fd, c);', 'real = (get_connector_fn)dlsym(RTLD_NEXT, "drmModeGetConnectorCurrent");\n    struct m19_connector *c = real ? real(fd, connector_id) : NULL;', ('Shim',)),
    ('xorg-shim.c', 'return number == SIGSEGV || number == SIGBUS', 'return number == SIGBUS', ('Shim',)),
    ('xorg-shim.c', '    sigprocmask(SIG_UNBLOCK, &only, NULL);\n', '', ('Shim',)),
    ('r3plan.py', ', \'    Option "Monitor-Virtual-1" "writeback"\'', '', ('Plan3',)),
    ('r3plan.py', ', \'    Option "Ignore" "true"\'', '', ('Plan3',)),
    ('t9-desktop', ' printf off >"$R/sys/class/drm/$writeback/status" || fail writeback-off', ' :', ('DesktopScript',)),
    ('t9-desktop', ' [ "$($BB cat "$R/sys/class/drm/$writeback/status")" = disconnected ] || fail writeback-still-connected', ' :', ('DesktopScript',)),
    ('t9-desktop', 'case "$writeback" in card0-Virtual-[0-9]) ;; *) fail "writeback name $writeback";; esac', ':', ('DesktopScript',)),
    ('r3plan.py', ', \'    Option "NoTrapSignals" "true"\'', '', ('Plan3',)),
    ('r3plan.py', "'LimitCORE=0', ", '', ('Plan3',)),
    ('r3plan.py', "              'sysctl.d/m19-r3.conf': SYSCTL,\n", '', ('Plan3',)),
    ('present-probe.c', '    if (xcb_connection_has_error(c)) {\n        printf("M19 PRESENT compositor FAIL connect\\n");\n        return 1;', '    if (xcb_connection_has_error(c)) {\n        printf("M19 PRESENT compositor FAIL connect\\n");\n        return 0;', ('PresentProbe',)),
    ('r4plan.py', '-p /general/vblank_mode -n -t string -s xpresent', '-p /general/vblank_mode -n -t string -s glx', ('Plan4', 'CompositorScript')),
    ('r4plan.py', '  /usr/bin/xfconf-query -c xfwm4 -p /general/unredirect_overlays -n -t bool -s true &&\n', '', ('Plan4', 'CompositorScript')),
    ('t9-gpu', ' usr/bin/xfconf-query \
', ' \
', ('GpuScript',)),
    ('t9-gpu', ' usr/lib/aarch64-linux-gnu/libEGL.so.1 usr/lib/aarch64-linux-gnu/libGLESv2.so.2; do', ' usr/lib/aarch64-linux-gnu/libEGL.so.1; do', ('GpuScript',)),
    ('report.c', 'g->flips * 10 >= (long)c->present_frames * 9 && ', '', ('Gpu',)),
    ('report.c', ' &&\n                     g->flip_msc <= 1.10;', ';', ('Gpu',)),
    ('report.c', 'g->flip_ok = status == 0 && g->flip_done == (long)c->present_frames &&', 'g->flip_ok = g->flip_done == (long)c->present_frames &&', ('Gpu',)),
    ('report.c', 'g->flip_ok = status == 0 && g->flip_done == (long)c->present_frames &&', 'g->flip_ok = status == 0 &&', ('Gpu',)),
    ('report.c', '    char *full[] = {(char *)c->glxgears, "-fullscreen", NULL};', '    char *full[] = {(char *)c->glxgears, NULL};', ('Gpu',)),
    ('report.c', '    snprintf(key, sizeof(key), "M19 PRESENT %s frames=", mode);', '    snprintf(key, sizeof(key), "M19 PRESENT copy frames=");', ('Gpu',)),
    ('present-probe.c', 'msc + 1, 0, 0, 0, NULL);', 'msc + 2, 0, 0, 0, NULL);', ('PresentProbe',)),
    ('present-probe.c', '        case XCB_PRESENT_COMPLETE_MODE_COPY: copies++; break;\n', '', ('PresentProbe',)),
    ('present-probe.c', '        msc = complete->msc;\n', '', ('PresentProbe',)),
    ('present-probe.c', 'if ((!flip && !copy && !card) || frames < 2 || frames > 10000) {', 'if ((!flip && !copy && !card) || frames > 10000) {', ('PresentProbe',)),
    ('t9-gpu', 'for probe in gpu-probe present-probe; do', 'for probe in gpu-probe; do', ('GpuScript',)),
    ('r4plan.py', '    conf = _swap(conf, \'    Option "PageFlip" "false"\\n\', \'    Option "PageFlip" "true"\\n\')\n', '', ('Plan4',)),
    ('pid4.c', '.present_frames = 120,', '.present_frames = 12,', ('Static',)),
    ('xorg-shim.c', '    if (!bridge_on || !bo || !plane_fd || !device_of || !device_fd)\n        return original;', '    if (!bo || !plane_fd || !device_of || !device_fd)\n        return original;', ('Shim',)),
    ('xorg-shim.c', '        if (bridge[i].bo == bo && bridge[i].plane == plane) {', '        if (0) {', ('Shim',)),
    ('xorg-shim.c', '        if (!shared) {', '        if (1) {', ('Shim',)),
    ('xorg-shim.c', '        bridge[i].bo = NULL;\n', '', ('Shim',)),
    ('xorg-shim.c', '    union m19_gbm_handle out = original;\n', '    union m19_gbm_handle out = {.u64 = 0};\n', ('Shim',)),
    ('xorg-shim.c', '    return bridge_handle(bo, plane, original);', '    return bridge_handle(bo, 0, original);', ('Shim',)),
    ('xorg-shim.c', '    bridge_on = gbm && !strcmp(gbm, "1");', '    bridge_on = 1;', ('Shim',)),
    ('report.c', 'g->glamor_ok = g->glamor_init && g->glamor_on && adreno_named(g->glamor_renderer) && g->xorg_unit && !strcmp(g->profile, "dri3");', 'g->glamor_ok = g->glamor_init && g->glamor_on && g->xorg_unit && !strcmp(g->profile, "dri3");', ('Gpu',)),
    ('report.c', 'g->glamor_ok = g->glamor_init && g->glamor_on && adreno_named(g->glamor_renderer) && g->xorg_unit && !strcmp(g->profile, "dri3");', 'g->glamor_ok = g->glamor_init && g->glamor_on && adreno_named(g->glamor_renderer) && g->xorg_unit;', ('Gpu',)),
    ('report.c', 'g->glamor_ok = g->glamor_init && g->glamor_on && adreno_named(g->glamor_renderer) && g->xorg_unit && !strcmp(g->profile, "dri3");', 'g->glamor_ok = g->glamor_on && adreno_named(g->glamor_renderer) && g->xorg_unit && !strcmp(g->profile, "dri3");', ('Gpu',)),
    ('report.c', '&& taken >= 6 && !memcmp(out, "active", 6);', '|| 1;', ('Gpu',)),
    ('report.c', '&& g.gears && (!c->glamor || g.glamor_ok) &&', '&& g.gears &&', ('Gpu',)),
    ('report.c', '        status = section_env(info, c->copy_env, SECTION_CAP / 4, c->gpu_ms, &start, &length);', '        status = section_env(info, c->gl_env, SECTION_CAP / 4, c->gpu_ms, &start, &length);', ('Gpu',)),
    ('report.c', '        if (status == 0 && score[0])\n            g->glmark2 = strtol(score, NULL, 10);', '        g->glmark2 = strtol(score, NULL, 10);', ('Gpu',)),
    ('pid4.c', '.vk_env = dri3_env, .gl_env = dri3_env,', '.vk_env = dri3_env, .gl_env = copy_env,', ('Static',)),
    ('pid4.c', '"FD_FORCE_KGSL=1", "FD_KGSL_ENABLE_DMABUF=1", M19_VK_ICD, NULL};', '"FD_FORCE_KGSL=1", M19_VK_ICD, NULL};', ('Static',)),
    ('r4plan.py', "GLAMOR_ENV = ('MESA_LOADER_DRIVER_OVERRIDE=kgsl', 'FD_FORCE_KGSL=1', 'FD_KGSL_ENABLE_DMABUF=1')", "GLAMOR_ENV = ('MESA_LOADER_DRIVER_OVERRIDE=kgsl', 'FD_FORCE_KGSL=1')", ('Static', 'Plan4')),
    ('r4plan.py', "f'Environment=LD_PRELOAD={r3plan.SHIM}\\nEnvironment=M19_SHIM_GBM=1 M19_SHIM_NODIRTY=1 ' + ' '.join(GLAMOR_ENV) + '\\n')", "f'Environment=LD_PRELOAD={r3plan.SHIM}\\nEnvironment=M19_SHIM_NODIRTY=1 ' + ' '.join(GLAMOR_ENV) + '\\n')", ('Plan4',)),
    # R4g: kernel dirty updates off for glamor's X server only.
    ('r4plan.py', "M19_SHIM_GBM=1 M19_SHIM_NODIRTY=1 '", "M19_SHIM_GBM=1 '", ('Plan4',)),
    ('xorg-shim.c', '        return -ENOSYS;\n    }\n    if (!real)\n        real = (dirty_fb_fn)', '    }\n    if (!real)\n        real = (dirty_fb_fn)', ('Shim',)),
    ('xorg-shim.c', '    dirty_off = dirty && !strcmp(dirty, "1");', '    dirty_off = 1;', ('Shim',)),
    ('xorg-shim.c', '        told = 1;\n', '', ('Shim',)),
    ('r4plan.py', '\'    Option "AccelMethod" "glamor"\\n    Option "DRI" "3"\\n\'', '\'    Option "AccelMethod" "none"\\n\'', ('Plan4',)),
    ('r4plan.py', "'Restart=no\\n', 'Restart=on-failure\\nRestartSec=2\\n')", "'Restart=no\\n', 'Restart=no\\n')", ('Plan4',)),
    ('r4plan.py', "/usr/bin/grep -q 'glamor initialized' /var/log/Xorg.0.log; then", 'true; then', ('SessionScript',)),
    ('r4plan.py', '[ "$(/usr/bin/systemctl is-active marble-xorg.service 2>/dev/null)" = active ] && ', '', ('SessionScript',)),
    ('r4plan.py', 'printf \'%s\\\\n\' "$profile" >/run/m19/gpu-profile\n', '', ('SessionScript',)),
    ('r4plan.py', ' case "$line" in \'\'|\'#\'*) ;; *=*) export "$line";; esac\n', ' :\n', ('SessionScript',)),
    ('t9-gpu', '$BB cp "$plan/xorg-glamor.conf" "$new/run/m19/xorg-glamor.conf" || fail xorg-glamor', ':', ('GpuScript',)),
    ('t9-gpu', 'printf \'%s\' /run/m19/firmware >"$param" || fail firmware-path', ':', ('GpuScript',)),
    ('t9-gpu', '[ "$count" -eq 7 ] || fail "firmware count $count"', ':', ('GpuScript',)),
    ('t9-gpu', '[ "$before" -eq "$base" ] || fail "module count $before"', ':', ('GpuScript',)),
    ('t9-gpu', '[ "$after" -eq $((base+8)) ] || fail "module count $after"', ':', ('GpuScript',)),
    ('t9-gpu', '[ "$#" -eq 8 ] || fail "module list $#"', ':', ('GpuScript',)),
    ('t9-gpu', '"$LOAD" "$@" || fail module-load', '"$LOAD" "$@" || :', ('GpuScript',)),
    ('t9-gpu', 'for directory in "$R/run/m19/firmware" "$new/run/m19/firmware"; do', 'for directory in "$new/run/m19/firmware"; do', ('GpuScript',)),
    ('t9-gpu', '$BB mknod -m 600 "$3" c', '$BB mknod -m 666 "$3" c', ('GpuScript',)),
    ('t9-gpu', 'make_node dma_heap system "$new/dev/dma_heap/system"', ':', ('GpuScript',)),
    ('t9-gpu', ' number_ok "$number" || fail "$2 number"', ' :', ('GpuScript',)),
    ('t9-gpu', ' [ -e "$new/$tool" ] || fail "missing $tool"', ' :', ('GpuScript',)),
    ('t9-gpu', ' case "$module" in ?*.ko) ;; *) fail "module name $module";; esac', ' :', ('GpuScript',)),
    ('report.c', 'g->probe = status == 0 && strstr(text, "M19 GPU vulkan fill ok") != NULL && adreno_named(g->probe_device);', 'g->probe = status == 0 && adreno_named(g->probe_device);', ('Gpu',)),
    ('report.c', 'g->probe = status == 0 && strstr(text, "M19 GPU vulkan fill ok") != NULL && adreno_named(g->probe_device);', 'g->probe = status == 0 && strstr(text, "M19 GPU vulkan fill ok") != NULL;', ('Gpu',)),
    ('report.c', 'g->vk = status == 0 && strstr(text, "DRIVER_ID_MESA_TURNIP") != NULL && adreno_named(g->device);', 'g->vk = status == 0;', ('Gpu',)),
    ('report.c', '    g->cube = status == 0;\n', '    g->cube = 1;\n', ('Gpu',)),
    ('report.c', 'g->gl = status == 0 && adreno_named(g->renderer) && !(c->glamor && strstr(g->renderer, "zink"));', 'g->gl = status == 0;', ('Gpu',)),
    ('report.c', 'g->gl = status == 0 && adreno_named(g->renderer) && !(c->glamor && strstr(g->renderer, "zink"));',
     'g->gl = status == 0 && adreno_named(g->renderer);', ('Gpu',)),
    ('report.c', 'gpu_ok = g.node && g.probe && g.vk && g.cube && g.gl && g.gears &&', 'gpu_ok = g.node && g.probe && g.vk && g.gl && g.gears &&', ('Gpu',)),
    ('report.c', 'gpu_ok = g.node && g.probe && g.vk && g.cube && g.gl && g.gears &&', 'gpu_ok = g.probe && g.vk && g.cube && g.gl && g.gears &&', ('Gpu',)),
    ('report.c', '        for (unsigned i = 0; env && env[i]; i++)\n            if (putenv((char *)env[i]))', '        for (unsigned i = 0; 0 && env && env[i]; i++)\n            if (putenv((char *)env[i]))', ('Gpu',)),
    ('report.c', '        if (c->gpu && d.x_ok)\n            gpu_phase(c, tty, &g);', '        if (c->gpu)\n            gpu_phase(c, tty, &g);', ('Gpu',)),
    ('report.c', '!write_warning && desktop_ok && gpu_ok && audio_ok &&\n', '!write_warning && desktop_ok && audio_ok &&\n', ('Gpu',)),
    ('report.c', "if (*at == ' ' || *at == '\\t' || *at == '=')", "if (*at == '\\t' || *at == '=')", ('Gpu',)),
    ('report.c', 'g->node = !stat(c->kgsl_node, &node) && S_ISCHR(node.st_mode);', 'g->node = !stat(c->kgsl_node, &node);', ('Gpu',)),
    ('pid4.c', '"MESA_LOADER_DRIVER_OVERRIDE=zink", "LIBGL_KOPPER_DRI2=1", NULL};', '"MESA_LOADER_DRIVER_OVERRIDE=zink", NULL};', ('Static',)),
    ('pid4.c', '    {"T9-gpu", "/m19/t9-gpu", 90000, M19_STEP_REQUIRED},\n', '', ('Static',)),
    ('pid4.c', '.gpu = 1, ', '.gpu = 0, ', ('Static',)),
    ('gpu-probe.c', '    if (p->deviceType == VK_PHYSICAL_DEVICE_TYPE_CPU)\n        return allow_cpu;', '    if (p->deviceType == VK_PHYSICAL_DEVICE_TYPE_CPU)\n        return 1;', ('GpuProbe',)),
    ('gpu-probe.c', '    vkCmdFillBuffer(commands, buffer, 0, VK_WHOLE_SIZE, FILL_WORD);\n', '', ('GpuProbe',)),
    # R4e: the probe's vblank, crtc and root modes, the reporter's three views, the Xorg log's filter, the session's bus.
    ('present-probe.c', '        v.request.sequence = 1;\n', '        v.request.sequence = 2;\n', ('CardProbe',)),
    ('present-probe.c', '        late += event.sequence != target;\n', '', ('CardProbe',)),
    ('present-probe.c', '        target = event.sequence + 1;\n', '        target = event.sequence + 2;\n', ('CardProbe',)),
    ('present-probe.c', '        wall += now_us() - queued;\n', '', ('CardProbe',)),
    ('present-probe.c', 'return n == (ssize_t)sizeof(*event) && event->type == M19_EVENT_VBLANK && event->user_data == serial;', 'return 1;', ('CardProbe',)),
    ('present-probe.c', 'if (!ioctl(fd, M19_GET_CRTC, &c) && c.mode_valid && c.fb_id)', 'if (!ioctl(fd, M19_GET_CRTC, &c))', ('CardProbe',)),
    ('present-probe.c', '        changes += c.fb_id != previous;\n', '', ('CardProbe',)),
    ('present-probe.c', '        if (!known && distinct < 8)\n', '        if (distinct < 8)\n', ('CardProbe',)),
    ('present-probe.c', "c.mode.name[i] > ' ' && c.mode.name[i] < 127 && c.mode.name[i] != '=' ? c.mode.name[i] : '_';", 'c.mode.name[i];', ('CardProbe',)),
    ('present-probe.c', '    if (!id) {\n        printf("M19 PRESENT crtc FAIL no active crtc\\n");', '    if (0) {\n        printf("M19 PRESENT crtc FAIL no active crtc\\n");', ('CardProbe',)),
    ('present-probe.c', '            sum += (unsigned)p[0] + p[1] + p[2];\n', '            sum += p[0];\n', ('PresentProbe',)),
    ('present-probe.c', '    for (uint16_t y = 0; y < height; y += 64) {', '    for (uint16_t y = 0; y < height / 2; y += 64) {', ('PresentProbe',)),
    ('present-probe.c', "    if (argc == 2 && !strcmp(argv[1], \"root\"))\n        return root();\n", '', ('PresentProbe',)),
    ('report.c', 'g->vblank_ok = vblank_line(section_text(start, length), g) && status == 0;', 'g->vblank_ok = vblank_line(section_text(start, length), g);', ('Gpu',)),
    ('report.c', 'g->compositor_ok = g->on_rc == 0 && g->off_rc == 0 && g->view[0].owner_ok &&', 'g->compositor_ok = g->off_rc == 0 && g->view[0].owner_ok &&', ('Gpu',)),
    ('report.c', 'g->compositor_ok = g->on_rc == 0 && g->off_rc == 0 && g->view[0].owner_ok &&', 'g->compositor_ok = g->on_rc == 0 && g->view[0].owner_ok &&', ('Gpu',)),
    ('report.c', 'g->compositor_ok = g->on_rc == 0 && g->off_rc == 0 && g->view[0].owner_ok &&', 'g->compositor_ok = g->on_rc == 0 && g->off_rc == 0 &&', ('Gpu',)),
    ('report.c', ' && g->view[1].owner > 0 && g->view[2].owner == 0;', ' && g->view[2].owner == 0;', ('Gpu',)),
    ('report.c', ' && g->view[1].owner > 0 && g->view[2].owner == 0;', ' && g->view[1].owner > 0;', ('Gpu',)),
    ('report.c', 'g->scanout_ok = g->scanout_ok && g->view[i].crtc_ok && g->view[i].root_ok;', 'g->scanout_ok = g->scanout_ok && g->view[i].crtc_ok;', ('Gpu',)),
    ('report.c', 'g->scanout_ok = g->scanout_ok && g->view[i].crtc_ok && g->view[i].root_ok;', 'g->scanout_ok = g->scanout_ok && g->view[i].root_ok;', ('Gpu',)),
    ('report.c', '(!c->compositor_script || (g.compositor_ok && g.vblank_ok && g.scanout_ok)) &&', '(!c->compositor_script || (g.vblank_ok && g.scanout_ok)) &&', ('Gpu',)),
    ('report.c', '(!c->compositor_script || (g.compositor_ok && g.vblank_ok && g.scanout_ok)) &&', '(!c->compositor_script || (g.compositor_ok && g.scanout_ok)) &&', ('Gpu',)),
    ('report.c', '(!c->compositor_script || (g.compositor_ok && g.vblank_ok && g.scanout_ok)) &&', '(!c->compositor_script || (g.compositor_ok && g.vblank_ok)) &&', ('Gpu',)),
    ('report.c', '    v->gl = xfwm4_gl(c);\n', '    v->gl = 0;\n', ('Gpu',)),
    ('report.c', '        keep = have < 63 ? have : 63;\n', '        keep = 0;\n', ('Gpu',)),
    ('report.c', '    snprintf(samples, sizeof(samples), "%u", c->crtc_samples);', '    snprintf(samples, sizeof(samples), "%u", 5u);', ('Gpu',)),
    ('report.c', '            snprintf(vblank_frames, sizeof(vblank_frames), "%u", c->vblank_frames);', '            snprintf(vblank_frames, sizeof(vblank_frames), "%u", 12u);', ('Gpu',)),
    ('report.c', '            wait_owner(c, 1);\n            observe(c, 1, &g->view[1]);', '            observe(c, 1, &g->view[1]);', ('Gpu',)),
    ('report.c', '    if (!v->crtc_ok)\n        v->fb = v->fbs = v->changes = v->pitch = -1;', '', ('Gpu',)),
    # R4f: the hardware cursor for glamor's X server, and the scanned-out framebuffer's pitch.
    ('r4plan.py', '    return _swap(conf, \'    Option "SWcursor" "true"\\n\', \'    Option "SWcursor" "false"\\n\')', '    return conf', ('Plan4',)),
    ('present-probe.c', '    f.fb_id = fb;\n', '', ('CardProbe',)),
    ('present-probe.c', '        pitch = f.pitch;\n', '        pitch = f.width;\n', ('CardProbe',)),
    ('report.c', '&v->changes, &v->pitch) == 4;', '&v->changes, &v->fb) == 4;', ('Gpu',)),
    ('report.c', '            if (memmem(piece + at, line, drop, size))\n                dropped++;', '            if (0)\n                dropped++;', ('Desktop',)),
    ('report.c', '            else if (!full && used - start + line <= cap)\n', '            else if (used - start + line <= cap)\n', ('Desktop',)),
    ('report.c', '            else if (!full && used - start + line <= cap)\n', '            else if (!full)\n', ('Desktop',)),
    ('report.c', '((end || (!at && have == sizeof(piece))) ? have - at : 0);', '(end ? have - at : 0);', ('Desktop',)),
    ('report.c', '"overflowing for touch");', '"overflowing for touch 2");', ('Desktop',)),
    ('r4plan.py', 'printf "%s\\\\n" "$DBUS_SESSION_BUS_ADDRESS" >/run/m19/session-bus && exec', 'exec', ('SessionScript',)),
    ('r4plan.py', ' IFS= read -r DBUS_SESSION_BUS_ADDRESS </run/m19/session-bus || exit 69\n', ' :\n', ('CompositorScript',)),
    ('r4plan.py', ' export DBUS_SESSION_BUS_ADDRESS\n', '', ('CompositorScript',)),
    ('r4plan.py', '-n -t string -s xpresent &&\n', '-n -t string -s xpresent\n', ('CompositorScript',)),
    ('r4plan.py', ' 2>/dev/null) || value=unset\n', ' 2>/dev/null) || :\n', ('CompositorScript',)),
    # R4h: touch counted by updates and motion too, the copy judged at one vblank, no compositor views.
    ('report.c', ' + count_text(events, "(TouchUpdate)") + count_text(events, "(RawTouchUpdate)") +', ' +', ('Desktop',)),
    ('report.c', '                count_text(events, "(Motion)") + count_text(events, "(RawMotion)");', '                0;', ('Desktop',)),
    ('report.c', 'g->copy_ok = status == 0 && g->copy_done == (long)c->present_frames &&', 'g->copy_ok = g->copy_done == (long)c->present_frames &&', ('Gpu',)),
    ('report.c', 'g->copy_ok = status == 0 && g->copy_done == (long)c->present_frames &&', 'g->copy_ok = status == 0 &&', ('Gpu',)),
    ('report.c', ' && g->copy_msc > 0 && g->copy_msc <= 1.10;', ' && g->copy_msc > 0;', ('Gpu',)),
    ('report.c', ' && (!c->judge_copy || g.copy_ok) &&', ' &&', ('Gpu',)),
    ('pid4.c', '.judge_copy = 1,', '.judge_copy = 0,', ('Static',)),
    # R4i: glxgears covering the screen through six paths, the screen read while it runs.
    ('report.c', '                g->show_visible += g->show_nonblack[i] >= 5;', '                g->show_visible += g->show_nonblack[i] >= 4;', ('Gpu',)),
    ('report.c', '        g->shows_ok = g->show_ran == (int)c->show_count &&', '        g->shows_ok = 1 &&', ('Gpu',)),
    ('report.c', ' &&\n                 (!c->show_count || g.shows_ok) &&', ' &&', ('Gpu',)),
    ('report.c', '"%s -fullscreen & gears=$!;', '"%s & gears=$!;', ('Gpu',)),
    ('report.c', '            } else {\n                g->show_nonblack[i] = g->show_mean[i] = -1;\n            }', '            }', ('Gpu',)),
    ('pid4.c', '{"noubwc", noubwc_env}, ', '', ('Static',)),
    ('pid4.c', '"FD_MESA_DEBUG=noubwc,notile"', '"FD_MESA_DEBUG=noubwc"', ('Static',)),
    ('pid4.c', '.show_seconds = 3,', '.show_seconds = 0,', ('Static',)),
    # R4j: which side loses a program's frame.
    ('present-probe.c', '        memcpy(b->p + i, b->paint, 3);\n', '        memcpy(b->p + i, b->paint, 2);\n', ('CardProbe',)),
    ('present-probe.c', '    if (failed) {\n        printf("M19 PRESENT %s FAIL heap alloc', '    if (0) {\n        printf("M19 PRESENT %s FAIL heap alloc', ('CardProbe',)),
    ('present-probe.c', '    if (!extension || !extension->present) {\n        printf("M19 PRESENT %s FAIL no dri3', '    if (0) {\n        printf("M19 PRESENT %s FAIL no dri3', ('PresentProbe',)),
    ('present-probe.c', '    if (!egl || !gles || !get_proc) {', '    if (!egl && !gles && !get_proc) {', ('CardProbe',)),
    ('report.c', '            (void)section_env(gpuwrite, c->dmabuf_env,', '            (void)section_env(gpuwrite, NULL,', ('Gpu',)),
    ('report.c', '            (void)section_env(chain, c->dmabuf_env,', '            (void)section_env(chain, NULL,', ('Gpu',)),
    ('report.c', '    return end == at + strlen(pattern) ? -1 : value;', '    return value;', ('Gpu',)),
    ('report.c', '    if (!at || at >= line + n)\n        return -1;', '    if (!at)\n        return -1;', ('Gpu',)),
    ('report.c', '            g->xread_window = field(text, "M19 PRESENT xread pixmap=", "window");', '            g->xread_window = g->xread_pixmap;', ('Gpu',)),
    ('pid4.c', '.dmabuf_env = dri3_env,', '.dmabuf_env = copy_env,', ('Static',)),
    # R4k: writes after the import, and glxgears finishing its GPU work before every swap.
    ('present-probe.c', '    if (!strcmp(mode, "xread")) {\n        cpu_paint(&b);', '    if (strcmp(mode, "kgslsync")) {\n        cpu_paint(&b);', ('PresentProbe',)),
    ('present-probe.c', ' || !strcmp(argv[1], "xlate") ||', ' ||', ('PresentProbe',)),
    ('present-probe.c', ' || !strcmp(argv[1], "chainlate") ||', ' ||', ('CardProbe',)),
    ('present-probe.c', '        printf("M19 PRESENT %s FAIL heap alloc errno=%d\\n", b->mode, errno);', '        printf("M19 PRESENT xread FAIL heap alloc errno=%d\\n", errno);', ('CardProbe',)),
    ('glfinish.c', '    if (finish)\n        finish();\n', '', ('Shim',)),
    ('glfinish.c', '    if (finish)\n        finish();\n    if (real)\n        real(display, drawable);', '    if (real)\n        real(display, drawable);\n    if (finish)\n        finish();', ('Shim',)),
    ('glfinish.c', '        told = 1;\n', '', ('Shim',)),
    ('glfinish.c', '    if (real)\n        real(display, drawable);', '', ('Shim',)),
    ('report.c', '            (void)section_env(chainlate, c->dmabuf_env,', '            (void)section_env(chainlate, NULL,', ('Gpu',)),
    ('report.c', '            g->xlate_window = field(text, "M19 PRESENT xlate pixmap=", "window");', '            g->xlate_window = g->xlate_pixmap;', ('Gpu',)),
    ('report.c', '            g->chainlate_window = field(text, "M19 PRESENT chainlate pixmap=", "window");', '            g->chainlate_window = g->chainlate_pixmap;', ('Gpu',)),
    ('report.c', '            g->xlate_cpu = field(text, "M19 PRESENT xlate cpu=", "cpu");', '            g->xlate_cpu = -1;', ('Gpu',)),
    ('pid4.c', ', {"finish", finish_env}', '', ('Static',)),
    ('pid4.c', 'static const char *const finish_env[] = {M19_DRI3, M19_FINISH, NULL};', 'static const char *const finish_env[] = {M19_DRI3, NULL};', ('Static',)),
    ('t9-gpu', '$BB cp "$R/m19/m19-glfinish.so" "$new/run/m19/m19-glfinish.so" || fail glfinish\n', '', ('GpuScript',)),
    ('t9-gpu', '[ -f "$R/m19/m19-glfinish.so" ] && [ ! -L "$R/m19/m19-glfinish.so" ] || fail glfinish', '[ -f "$R/m19/m19-glfinish.so" ] || fail glfinish', ('GpuScript',)),
    # R4l: KGSL cache maintenance over a late write, a second import, a delayed read.
    ('present-probe.c', '            uint32_t op = strstr(name, "clean") ? M19_KGSL_CLEAN : M19_KGSL_FLUSH;', '            uint32_t op = M19_KGSL_FLUSH;', ('CardProbe',)),
    ('present-probe.c', '            if (!strncmp(name, "obj-", 4)) {', '            if (1) {', ('CardProbe',)),
    ('present-probe.c', '#define M19_KGSL_SYNC _IOW(0x09, 0x49,', '#define M19_KGSL_SYNC _IOW(0x09, 0x4A,', ('CardProbe',)),
    ('present-probe.c', 'struct m19_kgsl_sync_obj object = {.length = size,', 'struct m19_kgsl_sync_obj object = {.length = size / 2,', ('CardProbe',)),
    ('present-probe.c', '            (void)ioctl(k, M19_KGSL_FREE_ID, &release);\n', '', ('CardProbe',)),
    ('present-probe.c', '    opened = k < 0 ? errno : 0;', '    opened = 0;', ('CardProbe',)),
    ('present-probe.c', '        imported = ioctl(k, M19_KGSL_IMPORT, &request) ? errno : 0;\n        if (!imported) {', '        imported = ioctl(k, M19_KGSL_IMPORT, &request) ? errno : 0;\n        if (1) {', ('CardProbe',)),
    ('present-probe.c', ' && !strcmp(argv[1], "xsync") && kgsl_op_known(argv[4]))', ' && !strcmp(argv[1], "xsync"))', ('PresentProbe',)),
    ('report.c', '                {probe, "xwait", heap, NULL, NULL, NULL},\n', '', ('Gpu',)),
    ('report.c', '                {probe, "xsync", heap, kgsl, "obj-clean", NULL},', '                {probe, "xsync", heap, kgsl, "obj-flush", NULL},', ('Gpu',)),
    ('report.c', '!strncmp(r4l[i][1], "chain", 5) ? c->dmabuf_env : NULL', 'NULL', ('Gpu',)),
    ('present-probe.c', ' || !strcmp(argv[1], "xagain") ||', ' ||', ('CardProbe',)),
    ('present-probe.c', ' || !strcmp(argv[1], "chainagain")))', '))', ('CardProbe',)),
    # R4m: the layer that keeps an import's stale view.
    ('present-probe.c', '    if (argc == 3 && !strcmp(argv[1], "glimport"))\n', '    if (0)\n', ('CardProbe',)),
    ('present-probe.c', '    if (argc == 4 && !strcmp(argv[1], "gbmimport"))\n', '    if (0)\n', ('CardProbe',)),
    ('present-probe.c', '        int card_fd = open(card, O_RDWR | O_CLOEXEC);', '        int card_fd = open(heap, O_RDWR | O_CLOEXEC);', ('CardProbe',)),
    ('present-probe.c', '    if (heap_alloc(&b, heap))\n        return 1;\n    if (card) {', '    if (card) {', ('CardProbe',)),
    ('gpu-probe.c', '.enabledExtensionCount = dmabuf ? 2u : 0u,', '.enabledExtensionCount = 0u,', ('GpuProbe',)),
    ('gpu-probe.c', '        cpu[i] = LATE_WORD;', '        cpu[i] = LATE_WORD + 1u;', ('GpuProbe',)),
    ('gpu-probe.c', '    if ((result = copy_share(l, second, &again)) != VK_SUCCESS || (result = copy_share(l, first, &first_again)) != VK_SUCCESS)',
     '    if ((result = copy_share(l, second, &again)) != VK_SUCCESS)', ('GpuProbe',)),
    ('gpu-probe.c', '    int allow_cpu = argc == base + 1 && !strcmp(argv[base], "--allow-cpu");', '    int allow_cpu = argc == base + 1;', ('GpuProbe',)),
    ('report.c', '                {probe, "gbmimport", heap, card, NULL},', '                {probe, "gbmimport", heap, heap, NULL},', ('Gpu',)),
    ('report.c', '                {gpu, "dmabuf", heap, NULL, NULL},\n', '', ('Gpu',)),
    ('report.c', 'const char *const *const r4m_env[] = {c->dmabuf_env, c->dmabuf_env, c->vk_env, NULL};',
     'const char *const *const r4m_env[] = {c->dmabuf_env, NULL, c->vk_env, NULL};', ('Gpu',)),
    # R4n: the hash of the Mesa the session loads.
    ('t9-gpu', "printf 'M19 T9 gpu: libgallium sha256=%s\\n' \"${mesa%% *}\" >&2\n", '', ('GpuScript',)),
    ('t9-gpu', ') || fail mesa-hash', ') || :', ('GpuScript',)),
    # R4o: DRI3 judged.
    ('report.c', ' && (!c->judge_dri3 || g->show_visible == (int)c->show_count);', ';', ('Gpu',)),
    ('report.c', 'g->late_ok = g->xlate_pixmap >= 990 && g->xlate_window >= 990 && g->chainlate_pixmap >= 990 && g->chainlate_window >= 990;',
     'g->late_ok = g->xlate_pixmap >= 990 && g->xlate_window >= 990 && g->chainlate_pixmap >= 990;', ('Gpu',)),
    ('report.c', 'g->late_ok = g->xlate_pixmap >= 990 && g->xlate_window >= 990 && g->chainlate_pixmap >= 990 && g->chainlate_window >= 990;',
     'g->late_ok = g->xlate_pixmap >= 989 && g->xlate_window >= 990 && g->chainlate_pixmap >= 990 && g->chainlate_window >= 990;', ('Gpu',)),
    ('report.c', 'g->late_ok = g->xlate_pixmap >= 990 && g->xlate_window >= 990 && g->chainlate_pixmap >= 990 && g->chainlate_window >= 990;',
     'g->late_ok = g->xlate_pixmap >= 990 && g->chainlate_pixmap >= 990 && g->chainlate_window >= 990;', ('Gpu',)),
    ('report.c', ' && (!c->judge_dri3 || (c->dmabuf_heap && g.late_ok));', ';', ('Gpu',)),
    ('pid4.c', '.judge_dri3 = 1,', '.judge_dri3 = 0,', ('Static',)),
)


WRAPS = '-Wl,--wrap=umount2,--wrap=mount,--wrap=chroot,--wrap=chdir,--wrap=execve,--wrap=stat,--wrap=ioctl'
DRIVER_UNITS = ('wire.c', 'handoff.c', 'report.c', 'test-r2.c')


class Broken(Exception):
    """A mutant that does not apply or does not build: the check itself is wrong."""


def compile_cmd(cmd, label, cwd=None):
    built = subprocess.run(cmd, cwd=cwd, capture_output=True, timeout=120)
    if built.returncode:
        raise Broken(f'compile failed for {label}:\n{built.stderr.decode("utf-8", "replace")}')


def precompile_base(obj_dir: Path, need_present: bool, need_gpu: bool):
    base = {'objs': {}, 'xvfb': shutil.which('Xvfb'),
            'icds': sorted(Path('/usr/share/vulkan/icd.d').glob('lvp_icd*.json'))}
    if need_present and not base['xvfb']:
        raise Broken('no Xvfb installed for PresentProbe/CardProbe mutants')
    if need_gpu and not base['icds']:
        raise Broken('no lavapipe ICD installed for GpuProbe mutants')

    hash_o = obj_dir / 'hash.o'
    base['objs']['hash.c'] = str(hash_o)
    jobs = [(['gcc', '-std=c11', '-O1', '-w', '-c', str(HERE.parent / 'unlock/hash.c'), '-o', str(hash_o)], 'hash.c')]
    for unit in DRIVER_UNITS:
        out_o = obj_dir / f'{Path(unit).stem}.o'
        base['objs'][unit] = str(out_o)
        jobs.append((['gcc', '-std=c11', '-O1', '-w', f'-I{HERE}', '-c', str(HERE / unit), '-o', str(out_o)], unit))

    fakedrm_so = obj_dir / 'libfakedrm.so'
    shim_so = obj_dir / 'base-xorg-shim.so'
    glfinish_so = obj_dir / 'base-glfinish.so'
    fakecard_so = obj_dir / 'libfakecard.so'
    jobs.extend([
        (['gcc', '-std=c11', '-O2', '-w', '-shared', '-fPIC', str(HERE / 'fake-drm.c'), '-o', str(fakedrm_so)], 'fake-drm.c'),
        (['gcc', '-std=c11', '-O2', '-w', '-shared', '-fPIC', str(HERE / 'xorg-shim.c'), '-ldl', '-o', str(shim_so)], 'xorg-shim.c'),
        (['gcc', '-std=c11', '-O2', '-w', '-shared', '-fPIC', str(HERE / 'glfinish.c'), '-ldl', '-o', str(glfinish_so)], 'glfinish.c'),
        (['gcc', '-std=c11', '-O2', '-w', '-shared', '-fPIC', str(HERE / 'fake-card.c'), '-ldl', '-o', str(fakecard_so)], 'fake-card.c'),
    ])
    if need_present:
        present_bin = obj_dir / 'base-present-probe'
        base['present_probe'] = str(present_bin)
        jobs.append((['gcc', '-std=c11', '-O2', '-w', str(HERE / 'present-probe.c'), '-lxcb-dri3', '-lxcb-present', '-lxcb', '-ldl',
                      '-o', str(present_bin)], 'present-probe.c'))
    if need_gpu:
        gpu_bin = obj_dir / 'base-gpu-probe'
        base['gpu_probe'] = str(gpu_bin)
        jobs.append((['gcc', '-std=c11', '-O2', '-w', str(HERE / 'gpu-probe.c'), '-ldl', '-o', str(gpu_bin)], 'gpu-probe.c'))

    with concurrent.futures.ThreadPoolExecutor(max(1, min(8, os.cpu_count() or 1))) as pool:
        futures = [pool.submit(compile_cmd, cmd, label) for cmd, label in jobs]
        for fut in futures:
            fut.result()

    base_drv = obj_dir / 'base-driver'
    compile_cmd(['gcc', '-std=c11', '-O1', '-w', *(base['objs'][u] for u in ('hash.c', *DRIVER_UNITS)), WRAPS, '-o', str(base_drv)], 'base-driver')
    test_shim = obj_dir / 'test-shim'
    compile_cmd(['gcc', '-std=c11', '-O0', '-w', '-rdynamic', str(HERE / 'test-shim.c'), f'-L{obj_dir}', '-lfakedrm',
                 f'-Wl,-rpath,{obj_dir}', '-o', str(test_shim)], 'test-shim')
    base.update(driver=str(base_drv), fakedrm=str(fakedrm_so), shim=str(shim_so), glfinish=str(glfinish_so),
                test_shim=str(test_shim), fakecard=str(fakecard_so))
    return base


def run(number, name, old, new, classes, base):
    """True when test.py fails on the mutant. Each mutant gets its own tree, so they run side by side."""
    source = (HERE / name).read_text(encoding='utf-8')
    if old not in source:
        raise Broken(f'mutant {number} does not apply to {name}: {old}')
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory) / 'm19'
        target = root / 'run2'
        (root / 'unlock').mkdir(parents=True)
        (root / 'run1').mkdir()
        shutil.copytree(HERE, target, ignore=shutil.ignore_patterns('__pycache__'))
        for path in HERE.parent.glob('*.py'):
            shutil.copy(path, root)
        for item in ('core.h', 'hash.c'):
            shutil.copy(HERE.parent / 'unlock' / item, root / 'unlock')
        for item in ('r1.h', 'pins'):
            shutil.copy(HERE.parent / 'run1' / item, root / 'run1')
        (target / name).write_text(source.replace(old, new), encoding='utf-8', newline='\n')
        drv_path = base['driver']
        if name in DRIVER_UNITS:
            mut_o = target / 'mutated.o'
            compile_cmd(['gcc', '-std=c11', '-O1', '-w', '-c', name, '-o', str(mut_o)], f'mutant {number} ({name})', cwd=target)
            objs = [str(mut_o) if u == name else base['objs'][u] for u in ('hash.c', *DRIVER_UNITS)]
            compile_cmd(['gcc', '-std=c11', '-O1', '-w', *objs, WRAPS, '-o', 'driver'], f'mutant {number} link', cwd=target)
            drv_path = 'driver'
        environment = dict(os.environ)
        if 'PresentProbe' in classes or 'CardProbe' in classes:
            # The Present probe on Xvfb and on the fake card, as test.sh builds and runs it.
            present_bin = base['present_probe']
            if name == 'present-probe.c':
                compile_cmd(['gcc', '-std=c11', '-O2', '-w', 'present-probe.c', '-lxcb-dri3', '-lxcb-present', '-lxcb', '-ldl',
                             '-o', 'present-probe-test'], f'mutant {number} present-probe', cwd=target)
                present_bin = str(target / 'present-probe-test')
            environment.update(M19_PRESENT_PROBE=present_bin, M19_XVFB=base['xvfb'], M19_FAKE_CARD=base['fakecard'])
        if 'GpuProbe' in classes:
            # The probe on lavapipe, as test.sh builds and runs it, with the fake card's heap (R4m).
            gpu_bin = base['gpu_probe']
            if name == 'gpu-probe.c':
                compile_cmd(['gcc', '-std=c11', '-O2', '-w', 'gpu-probe.c', '-ldl', '-o', 'gpu-probe-test'],
                            f'mutant {number} gpu-probe', cwd=target)
                gpu_bin = str(target / 'gpu-probe-test')
            environment.update(M19_GPU_PROBE=gpu_bin, M19_LVP_ICD=str(base['icds'][0]), M19_FAKE_CARD=base['fakecard'])
        if 'Shim' in classes:
            # The preload library on the fake libdrm, as test.sh builds them.
            shim_so = base['shim']
            glfinish_so = base['glfinish']
            if name == 'xorg-shim.c':
                compile_cmd(['gcc', '-std=c11', '-O2', '-w', '-shared', '-fPIC', 'xorg-shim.c', '-ldl', '-o', 'xorg-shim-test.so'],
                            f'mutant {number} xorg-shim', cwd=target)
                shim_so = str(target / 'xorg-shim-test.so')
            if name == 'glfinish.c':
                compile_cmd(['gcc', '-std=c11', '-O2', '-w', '-shared', '-fPIC', 'glfinish.c', '-ldl', '-o', 'glfinish-test.so'],
                            f'mutant {number} glfinish', cwd=target)
                glfinish_so = str(target / 'glfinish-test.so')
            environment.update(M19_SHIM_LIB=shim_so, M19_SHIM_DRIVER=base['test_shim'], M19_GLFINISH_LIB=glfinish_so)
        try:
            # The first failure kills the mutant, so the rest of its classes need not run.
            result = subprocess.run([sys.executable, 'test.py', '--failfast', '--driver', drv_path, *classes],
                                    cwd=target, stdin=subprocess.DEVNULL, capture_output=True, timeout=300,
                                    env=environment, start_new_session=True)
            return result.returncode != 0
        except subprocess.TimeoutExpired:
            return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--shard-index', type=int, default=0)
    parser.add_argument('--shard-count', type=int, default=1)
    args = parser.parse_args()
    if args.shard_count < 1 or not (0 <= args.shard_index < args.shard_count):
        sys.exit(f'invalid shard specification: index={args.shard_index} count={args.shard_count}')

    for number, (name, old, _, _) in enumerate(MUTANTS):
        source = (HERE / name).read_text(encoding='utf-8')
        if old not in source:
            sys.exit(f'mutant {number} does not apply to {name}: {old}')

    selected = [(number, mutant) for number, mutant in enumerate(MUTANTS) if number % args.shard_count == args.shard_index]
    need_present = any('PresentProbe' in m[3] or 'CardProbe' in m[3] for _, m in selected)
    need_gpu = any('GpuProbe' in m[3] for _, m in selected)

    with tempfile.TemporaryDirectory() as obj_tmp:
        obj_dir = Path(obj_tmp)
        os.chmod(obj_dir, 0o755)
        try:
            base = precompile_base(obj_dir, need_present, need_gpu)
        except Broken as error:
            sys.exit(str(error))
        base_env = dict(os.environ, M19_SHIM_LIB=base['shim'], M19_SHIM_DRIVER=base['test_shim'], M19_GLFINISH_LIB=base['glfinish'])
        baseline = subprocess.run(
            [sys.executable, str(HERE / 'test.py'), '--failfast', '--driver', base['driver'], 'Static', 'Shim'],
            cwd=HERE, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120, env=base_env, start_new_session=True)
        if baseline.returncode != 0:
            sys.exit(f'baseline Static/Shim failed (rc={baseline.returncode}):\n{baseline.stdout}{baseline.stderr}')

        workers = max(1, min(6, (os.cpu_count() or 1) + 2))
        killed = {}
        with concurrent.futures.ThreadPoolExecutor(workers) as pool:
            future_to_num = {pool.submit(run, number, *mutant, base): number for number, mutant in selected}
            done = 0
            try:
                for future in concurrent.futures.as_completed(future_to_num):
                    number = future_to_num[future]
                    dead = future.result()
                    killed[number] = dead
                    done += 1
                    print(f'[{done}/{len(selected)}] mutant {number} ({MUTANTS[number][0]}) {"killed" if dead else "SURVIVED"}', flush=True)
            except Broken as error:
                for future in future_to_num:
                    future.cancel()
                sys.exit(str(error))

    survivors = [(number, name, old) for number, (name, old, _, _) in selected if not killed[number]]
    shard_note = f' (shard {args.shard_index + 1}/{args.shard_count})' if args.shard_count > 1 else ''
    print(f'{len(selected) - len(survivors)} of {len(selected)} R2 mutants killed{shard_note}, {workers} at a time')
    for survivor in survivors:
        print('SURVIVED', survivor)
    sys.exit(1 if survivors else 0)


if __name__ == '__main__':
    main()
