#!/usr/bin/env python3
"""Mutation check for R2 to R4: every mutant of the hand-off, the reporter, T9, the plans, PID 1 or the GPU probe must fail test.py."""
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
HANDOFF = ('Kthread', 'Sweep', 'Handoff')
MUTANTS = (
    ('handoff.c', 'if (left)\n        return fail(tty, h, "survivors", left);', 'if (0)\n        return fail(tty, h, "survivors", left);', HANDOFF),
    ('handoff.c', 'if (umount2(h->android, MNT_DETACH))', 'if (umount2(h->android, MNT_DETACH) && 0)', HANDOFF),
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
    ('report.c', 'desktop_ok = d.x_ok && d.session_ok && d.mode_ok && d.vblank_ok && d.touch_ok && guard_ok;', 'desktop_ok = d.x_ok;', ('Desktop',)),
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
    ('report.c', 'g->flips * 10 >= (long)c->present_frames * 9 && ', '', ('Gpu',)),
    ('report.c', ' &&\n                     g->flip_msc <= 1.10;', ';', ('Gpu',)),
    ('report.c', 'g->flip_ok = status == 0 && g->flip_done == (long)c->present_frames &&', 'g->flip_ok = g->flip_done == (long)c->present_frames &&', ('Gpu',)),
    ('report.c', 'g->flip_ok = status == 0 && g->flip_done == (long)c->present_frames &&', 'g->flip_ok = status == 0 &&', ('Gpu',)),
    ('report.c', '&& (!c->present_probe || g.flip_ok);', ';', ('Gpu',)),
    ('report.c', '    char *full[] = {(char *)c->glxgears, "-fullscreen", NULL};', '    char *full[] = {(char *)c->glxgears, NULL};', ('Gpu',)),
    ('report.c', '    snprintf(key, sizeof(key), "M19 PRESENT %s frames=", mode);', '    snprintf(key, sizeof(key), "M19 PRESENT copy frames=");', ('Gpu',)),
    ('present-probe.c', 'msc + 1, 0, 0, 0, NULL);', 'msc + 2, 0, 0, 0, NULL);', ('PresentProbe',)),
    ('present-probe.c', '        case XCB_PRESENT_COMPLETE_MODE_COPY: copies++; break;\n', '', ('PresentProbe',)),
    ('present-probe.c', '        msc = complete->msc;\n', '', ('PresentProbe',)),
    ('present-probe.c', 'if ((!flip && !copy) || frames < 2 || frames > 10000) {', 'if ((!flip && !copy) || frames > 10000) {', ('PresentProbe',)),
    ('t9-gpu', 'for probe in gpu-probe present-probe; do', 'for probe in gpu-probe; do', ('GpuScript',)),
    ('r4plan.py', '    return _swap(conf, \'    Option "PageFlip" "false"\\n\', \'    Option "PageFlip" "true"\\n\')', '    return conf', ('Plan4',)),
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
    ('r4plan.py', "f'Environment=LD_PRELOAD={r3plan.SHIM}\\nEnvironment=M19_SHIM_GBM=1 ' + ' '.join(GLAMOR_ENV) + '\\n')", "f'Environment=LD_PRELOAD={r3plan.SHIM}\\nEnvironment=' + ' '.join(GLAMOR_ENV) + '\\n')", ('Plan4',)),
    ('r4plan.py', '\'    Option "AccelMethod" "glamor"\\n    Option "DRI" "3"\\n\'', '\'    Option "AccelMethod" "none"\\n\'', ('Plan4',)),
    ('r4plan.py', "'Restart=no\\n', 'Restart=on-failure\\nRestartSec=2\\n')", "'Restart=no\\n', 'Restart=no\\n')", ('Plan4',)),
    ('r4plan.py', "/usr/bin/grep -q 'glamor initialized' /var/log/Xorg.0.log; then", 'true; then', ('SessionScript',)),
    ('r4plan.py', '[ "$(/usr/bin/systemctl is-active marble-xorg.service 2>/dev/null)" = active ] && ', '', ('SessionScript',)),
    ('r4plan.py', 'printf \'%s\\\\n\' "$profile" >/run/m19/gpu-profile\n', '', ('SessionScript',)),
    ('r4plan.py', ' case "$line" in \'\'|\'#\'*) ;; *=*) export "$line";; esac\n', ' :\n', ('SessionScript',)),
    ('t9-gpu', '$BB cp "$plan/xorg-glamor.conf" "$new/run/m19/xorg-glamor.conf" || fail xorg-glamor', ':', ('GpuScript',)),
    ('t9-gpu', 'printf \'%s\' /run/m19/firmware >"$param" || fail firmware-path', ':', ('GpuScript',)),
    ('t9-gpu', '[ "$count" -eq 7 ] || fail "firmware count $count"', ':', ('GpuScript',)),
    ('t9-gpu', '[ "$before" -eq 102 ] || fail "module count $before"', ':', ('GpuScript',)),
    ('t9-gpu', '[ "$after" -eq 110 ] || fail "module count $after"', ':', ('GpuScript',)),
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
    ('report.c', '!write_warning && desktop_ok && gpu_ok;', '!write_warning && desktop_ok;', ('Gpu',)),
    ('report.c', "if (*at == ' ' || *at == '\\t' || *at == '=')", "if (*at == '\\t' || *at == '=')", ('Gpu',)),
    ('report.c', 'g->node = !stat(c->kgsl_node, &node) && S_ISCHR(node.st_mode);', 'g->node = !stat(c->kgsl_node, &node);', ('Gpu',)),
    ('pid4.c', '"MESA_LOADER_DRIVER_OVERRIDE=zink", "LIBGL_KOPPER_DRI2=1", NULL};', '"MESA_LOADER_DRIVER_OVERRIDE=zink", NULL};', ('Static',)),
    ('pid4.c', '    {"T9-gpu", "/m19/t9-gpu", 90000, M19_STEP_REQUIRED},\n', '', ('Static',)),
    ('pid4.c', '.gpu = 1, ', '.gpu = 0, ', ('Static',)),
    ('gpu-probe.c', '    if (p->deviceType == VK_PHYSICAL_DEVICE_TYPE_CPU)\n        return allow_cpu;', '    if (p->deviceType == VK_PHYSICAL_DEVICE_TYPE_CPU)\n        return 1;', ('GpuProbe',)),
    ('gpu-probe.c', '    vkCmdFillBuffer(commands, buffer, 0, VK_WHOLE_SIZE, FILL_WORD);\n', '', ('GpuProbe',)),
)


def main():
    survivors = []
    for number, (name, old, new, classes) in enumerate(MUTANTS):
        source = (HERE / name).read_text(encoding='utf-8')
        if old not in source:
            sys.exit(f'mutant {number} does not apply to {name}: {old}')
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
            built = subprocess.run(['gcc', '-std=c11', '-O1', '-w', '../unlock/hash.c', 'wire.c', 'handoff.c', 'report.c', 'test-r2.c',
                                    '-Wl,--wrap=umount2,--wrap=mount,--wrap=chroot,--wrap=chdir,--wrap=execve,--wrap=stat,--wrap=ioctl', '-o', 'driver'],
                                   cwd=target, capture_output=True, timeout=120)
            if built.returncode:
                sys.exit(f'mutant {number} does not compile')
            environment = dict(os.environ)
            if 'PresentProbe' in classes:
                # The Present probe on Xvfb, as test.sh builds and runs it.
                xvfb = shutil.which('Xvfb')
                if not xvfb or subprocess.run(['gcc', '-std=c11', '-O2', '-w', 'present-probe.c', '-lxcb-present', '-lxcb', '-o', 'present-probe-test'],
                                              cwd=target, capture_output=True, timeout=120).returncode:
                    sys.exit(f'mutant {number}: no Xvfb or the Present probe does not compile')
                environment.update(M19_PRESENT_PROBE=str(target / 'present-probe-test'), M19_XVFB=xvfb)
            if 'GpuProbe' in classes:
                # The probe on lavapipe, as test.sh builds and runs it.
                icds = sorted(Path('/usr/share/vulkan/icd.d').glob('lvp_icd*.json'))
                if not icds or subprocess.run(['gcc', '-std=c11', '-O2', '-w', 'gpu-probe.c', '-ldl', '-o', 'gpu-probe-test'], cwd=target,
                                              capture_output=True, timeout=120).returncode:
                    sys.exit(f'mutant {number}: no lavapipe or the probe does not compile')
                environment.update(M19_GPU_PROBE=str(target / 'gpu-probe-test'), M19_LVP_ICD=str(icds[0]))
            if 'Shim' in classes:
                # The preload library on the fake libdrm, as test.sh builds them.
                for command in (['gcc', '-std=c11', '-O2', '-w', '-shared', '-fPIC', 'fake-drm.c', '-o', 'libfakedrm.so'],
                                ['gcc', '-std=c11', '-O2', '-w', '-shared', '-fPIC', 'xorg-shim.c', '-ldl', '-o', 'xorg-shim-test.so'],
                                ['gcc', '-std=c11', '-O0', '-w', '-rdynamic', 'test-shim.c', '-L.', '-lfakedrm', f'-Wl,-rpath,{target}', '-o', 'test-shim']):
                    if subprocess.run(command, cwd=target, capture_output=True, timeout=120).returncode:
                        sys.exit(f'mutant {number} does not compile: {command[-1]}')
                environment.update(M19_SHIM_LIB=str(target / 'xorg-shim-test.so'), M19_SHIM_DRIVER=str(target / 'test-shim'))
            try:
                result = subprocess.run([sys.executable, 'test.py', '--driver', 'driver', *classes], cwd=target, capture_output=True, timeout=300,
                                        env=environment)
                killed = result.returncode != 0
            except subprocess.TimeoutExpired:
                killed = True
        if not killed:
            survivors.append((number, name, old))
    print(f'{len(MUTANTS) - len(survivors)} of {len(MUTANTS)} R2 mutants killed')
    for survivor in survivors:
        print('SURVIVED', survivor)
    sys.exit(1 if survivors else 0)


if __name__ == '__main__':
    main()
