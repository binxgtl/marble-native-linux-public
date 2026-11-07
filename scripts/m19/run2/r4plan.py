#!/usr/bin/env python3
"""R4 on top of R3: the Adreno through the tree's own Mesa on KGSL, for the X server and for every program.

R4a proved the GPU layer and GL and Vulkan programs on the GPU through a CPU-drawn X server. R4b puts the X
server itself on the GPU: Xorg's glamor renders on KGSL through GBM on card0, with scan-out buffers handed to
card0 by the preload library's GBM bridge. The session picks one GPU profile from what the X server got, and
every program started in it, installed now or later, inherits that profile:

- dri3, when Xorg runs with glamor: GL through freedreno itself on KGSL and Vulkan through Turnip, both
  presenting through DRI3 without a copy through the CPU;
- copy, when it does not: R4a's proven path, GL through zink and Vulkan presenting through the CPU.

If glamor's Xorg fails, the CPU Xorg R3c proved takes over and the session restarts on it. The tree is never
written.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import r3plan  # noqa: E402

# The modules M9's 110-module closure has and R2's 102 lack, in load order: KGSL's suppliers, then KGSL.
GPU_MODULES = ('qcom_llcc_pmu.ko', 'qcom-pmu-lib.ko', 'dcvs_fp.ko', 'qcom-dcvs.ko', 'gpucc-waipio.ko', 'msm_performance.ko', 'nvmem_qfprom.ko',
               'msm_kgsl.ko')
# The firmware M9 Run-2W booted the GPU with: SQE microcode, GMU firmware and the signed zap shader.
FIRMWARE = ('a730_sqe.fw', 'gmu_gen70000.bin', 'a730_zap.mdt', 'a730_zap.mbn', 'a730_zap.b00', 'a730_zap.b01', 'a730_zap.b02')

VK_ICD = '/usr/share/vulkan/icd.d/freedreno_icd.aarch64.json'
# freedreno on KGSL for a DRM fd that is not KGSL (FD_FORCE_KGSL), shared and scan-out buffers from the
# dma-heap so they leave as dma-bufs (FD_KGSL_ENABLE_DMABUF). Xorg's glamor needs the same three.
GLAMOR_ENV = ('MESA_LOADER_DRIVER_OVERRIDE=kgsl', 'FD_FORCE_KGSL=1', 'FD_KGSL_ENABLE_DMABUF=1')
DRI3_ENV = GLAMOR_ENV + (f'VK_DRIVER_FILES={VK_ICD}',)
# R4a's proven path, for an X server without glamor.
COPY_ENV = (f'VK_DRIVER_FILES={VK_ICD}', 'MESA_VK_WSI_DEBUG=sw', 'MESA_LOADER_DRIVER_OVERRIDE=zink', 'LIBGL_KOPPER_DRI2=1')
PROFILES = {'dri3': DRI3_ENV, 'copy': COPY_ENV}


def _swap(text, old, new):
    assert text.count(old) == 1, old
    return text.replace(old, new)


def xorg_glamor_conf():
    """R3's 120 Hz configuration with glamor and DRI3, and (R4c) page flips for programs that cover the screen;
    everything else, the writeback Ignore included, as R3c ran."""
    conf = _swap(r3plan.xorg_conf(r3plan.MODE_120), '    Option "AccelMethod" "none"\n', '    Option "AccelMethod" "glamor"\n    Option "DRI" "3"\n')
    return _swap(conf, '    Option "PageFlip" "false"\n', '    Option "PageFlip" "true"\n')


GLAMOR_CONF = '/run/m19/xorg-glamor.conf'
# glamor's Xorg first; on failure, R3c's CPU Xorg at 120 Hz. The 60 Hz configuration stays staged, unused.
XORG = _swap(r3plan.xorg_unit('M19 R4 Xorg on DSI-1 at 120 Hz drawing on the GPU (glamor)', GLAMOR_CONF, '/var/log/Xorg.0.log', True),
             f'Environment=LD_PRELOAD={r3plan.SHIM}\n', f'Environment=LD_PRELOAD={r3plan.SHIM}\nEnvironment=M19_SHIM_GBM=1 ' + ' '.join(GLAMOR_ENV) + '\n')
XORG_FALLBACK = r3plan.xorg_unit('M19 R4 Xorg on DSI-1 at 120 Hz on the CPU, after glamor failed', '/run/m19/xorg.conf', '/var/log/Xorg.cpu.log',
                                 False)

# Every program in the session inherits one profile, chosen once X answers.
SESSION = '''#!/bin/sh
# M19 R4: the session's GPU profile, from what the X server got. Every program started in the session,
# installed now or later, inherits it: dri3 when Xorg runs with glamor, copy (R4a's path) otherwise.
set -u
i=0
until /usr/bin/xdpyinfo >/dev/null 2>&1; do
 i=$((i+1)); [ "$i" -lt 300 ] || exit 1; sleep 0.2
done
profile=copy
if [ "$(/usr/bin/systemctl is-active marble-xorg.service 2>/dev/null)" = active ] && /usr/bin/grep -q 'glamor initialized' /var/log/Xorg.0.log; then
 profile=dri3
fi
while IFS= read -r line; do
 case "$line" in ''|'#'*) ;; *=*) export "$line";; esac
done </etc/m19/gpu-$profile.env
printf '%s\\n' "$profile" >/run/m19/gpu-profile
# R4d: on glamor, xfwm4 composites on the GPU in step with vblank, so no window tears; on the CPU it must not.
compositor=off
[ "$profile" != dri3 ] || compositor=on
printf '[Desktop Entry]\\nType=Application\\nName=M19 GPU compositor\\nExec=/bin/sh /etc/m19/gpu-compositor %s\\n' "$compositor" \\
 >"$HOME/.config/autostart/m19-compositor.desktop"
exec /usr/bin/dbus-run-session -- /usr/bin/startxfce4
'''

# R4d: xfwm4's compositor through xfconf, in the session's RAM home. On, every window is drawn into one
# frame that xfwm4 presents through the Present extension at vblank (vblank_mode xpresent): no window tears,
# and that frame covers the screen, so it can page-flip. A window that itself covers the screen is left
# uncomposited (unredirect_overlays), so a game or a video can flip on its own.
COMPOSITOR = '''#!/bin/sh
# M19 R4d: xfwm4's compositor, on with the dri3 profile and off otherwise.
set -u
case "${1:-}" in
 on)
  /usr/bin/xfconf-query -c xfwm4 -p /general/vblank_mode -n -t string -s xpresent
  /usr/bin/xfconf-query -c xfwm4 -p /general/unredirect_overlays -n -t bool -s true
  /usr/bin/xfconf-query -c xfwm4 -p /general/use_compositing -n -t bool -s true;;
 off)
  /usr/bin/xfconf-query -c xfwm4 -p /general/use_compositing -n -t bool -s false;;
 *) exit 64;;
esac
'''

_EXEC = 'ExecStart=/usr/bin/dbus-run-session -- /usr/bin/startxfce4\n'
# The session restarts when its X server goes, so a glamor failure lands on the CPU Xorg with the copy profile.
XFCE = _swap(_swap(_swap(r3plan.XFCE, 'Description=M19 R3 XFCE session as root', 'Description=M19 R4 XFCE session as root, GL and Vulkan on the GPU'),
                   _EXEC, 'ExecStart=/bin/sh /etc/m19/gpu-session\n'), 'Restart=no\n', 'Restart=on-failure\nRestartSec=2\n')
TARGET = _swap(_swap(r3plan.TARGET, 'Description=M19 R3: XFCE on the read-only Ubuntu root',
                     'Description=M19 R4: XFCE and the GPU on the read-only Ubuntu root'), 'm19-r3-report.service', 'm19-r4-report.service')
REPORT = _swap(r3plan.REPORT, 'M19 R3 evidence over USB', 'M19 R4 evidence over USB')

FILES = {name: text for name, text in r3plan.FILES.items() if name not in ('systemd/system/m19-r3.target', 'systemd/system/m19-r3-report.service')}
FILES.update({'systemd/system/m19-r4.target': TARGET, 'systemd/system/m19-r4-report.service': REPORT, 'systemd/system/marble-xfce.service': XFCE,
              'systemd/system/marble-xorg.service': XORG, 'systemd/system/marble-xorg-fallback.service': XORG_FALLBACK,
              'm19/gpu-session': SESSION, 'm19/gpu-compositor': COMPOSITOR, **{f'm19/gpu-{name}.env': ''.join(f'{item}\n' for item in env) for name, env in PROFILES.items()}})


def render():
    """R3's files with R4's target, report, Xorg and session units, and the GPU plan under m19/r4."""
    assert len(set(GPU_MODULES)) == len(GPU_MODULES) == 8 and len(set(FIRMWARE)) == len(FIRMWARE) == 7
    out = {name: data for name, data in r3plan.render().items() if not name.startswith('m19/r2/etc/')}
    out['m19/r2/default'] = b'm19-r4.target\n'
    out['m19/r2/files'] = ''.join(f'{name}\n' for name in FILES).encode()
    out.update({f'm19/r2/etc/{name}': text.encode() for name, text in FILES.items()})
    out.update({'m19/r4/modules': ''.join(f'{name}\n' for name in GPU_MODULES).encode(),
                'm19/r4/firmware': ''.join(f'{name}\n' for name in FIRMWARE).encode(),
                'm19/r4/xorg-glamor.conf': xorg_glamor_conf().encode()})
    return out


if __name__ == '__main__':
    for name, data in render().items():
        print(f'{len(data):6d} {name}')
