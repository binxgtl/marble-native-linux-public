#!/usr/bin/env python3
"""R4 on top of R3: the Adreno through the tree's own Mesa on KGSL. The X server and the desktop stay as R3
proved them. T9-gpu loads the GPU layer M9 proved, the firmware lands in RAM, and the session's GL and
Vulkan programs draw on the GPU: Vulkan through Turnip, GL through zink on Turnip, both presenting through
the CPU because this X server has no DRI3. The tree is never written.
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
VK_ENV = (f'VK_DRIVER_FILES={VK_ICD}', 'MESA_VK_WSI_DEBUG=sw')
GL_ENV = VK_ENV + ('MESA_LOADER_DRIVER_OVERRIDE=zink', 'LIBGL_KOPPER_DRI2=1')
EGL_ENV = ('MESA_LOADER_DRIVER_OVERRIDE=kgsl',)


def _swap(text, old, new):
    assert text.count(old) == 1, old
    return text.replace(old, new)


_SESSION = 'Environment=DISPLAY=:0 HOME=/run/m19/session XDG_RUNTIME_DIR=/run/m19/xdg XDG_SESSION_TYPE=x11\n'
# The session's GL and Vulkan programs get the same variables the reporter tests with.
XFCE = _swap(_swap(r3plan.XFCE, 'Description=M19 R3 XFCE session as root', 'Description=M19 R4 XFCE session as root, GL and Vulkan on the GPU'),
             _SESSION, _SESSION + 'Environment=' + ' '.join(GL_ENV) + '\n')
TARGET = _swap(_swap(r3plan.TARGET, 'Description=M19 R3: XFCE on the read-only Ubuntu root',
                     'Description=M19 R4: XFCE and the GPU on the read-only Ubuntu root'), 'm19-r3-report.service', 'm19-r4-report.service')
REPORT = _swap(r3plan.REPORT, 'M19 R3 evidence over USB', 'M19 R4 evidence over USB')

FILES = {name: text for name, text in r3plan.FILES.items() if name not in ('systemd/system/m19-r3.target', 'systemd/system/m19-r3-report.service')}
FILES.update({'systemd/system/m19-r4.target': TARGET, 'systemd/system/m19-r4-report.service': REPORT, 'systemd/system/marble-xfce.service': XFCE})


def render():
    """R3's files with R4's target, report and session, and the GPU plan under m19/r4."""
    assert len(set(GPU_MODULES)) == len(GPU_MODULES) == 8 and len(set(FIRMWARE)) == len(FIRMWARE) == 7
    out = {name: data for name, data in r3plan.render().items() if not name.startswith('m19/r2/etc/')}
    out['m19/r2/default'] = b'm19-r4.target\n'
    out['m19/r2/files'] = ''.join(f'{name}\n' for name in FILES).encode()
    out.update({f'm19/r2/etc/{name}': text.encode() for name, text in FILES.items()})
    out.update({'m19/r4/modules': ''.join(f'{name}\n' for name in GPU_MODULES).encode(),
                'm19/r4/firmware': ''.join(f'{name}\n' for name in FIRMWARE).encode()})
    return out


if __name__ == '__main__':
    for name, data in render().items():
        print(f'{len(data):6d} {name}')
