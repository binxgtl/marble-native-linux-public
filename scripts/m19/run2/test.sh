#!/usr/bin/env bash
set -euo pipefail
out=${1:?output}; mkdir -p "$out"
src=scripts/m19/run2
hash=scripts/m19/unlock/hash.c
wraps=-Wl,--wrap=umount2,--wrap=mount,--wrap=chroot,--wrap=chdir,--wrap=execve,--wrap=stat,--wrap=ioctl
# The Xorg preload library on a fake libdrm. Never sanitized: ASan must come first in a process, a preload cannot.
out_abs=$(cd "$out" && pwd)
lvp=$(ls /usr/share/vulkan/icd.d/lvp_icd*.json 2>/dev/null | head -n 1 || true)
[[ -n $lvp ]] || { echo "lavapipe ICD missing: install mesa-vulkan-drivers" >&2; exit 1; }
command -v Xvfb >/dev/null || { echo "Xvfb missing: install xvfb" >&2; exit 1; }

gcc -std=c11 -O2 -Wall -Wextra -Werror -shared -fPIC "$src/fake-drm.c" -o "$out/libfakedrm.so"
test_build_pids=()
gcc -std=c11 -O2 -Wall -Wextra -Werror -shared -fPIC "$src/xorg-shim.c" -ldl -o "$out/xorg-shim-test.so" &
test_build_pids+=("$!")
gcc -std=c11 -O0 -Wall -Wextra -Werror -rdynamic "$src/test-shim.c" -L"$out" -lfakedrm -Wl,-rpath,"$out_abs" -o "$out/test-shim" &
test_build_pids+=("$!")
# R4k: the glFinish preload library, on the same driver.
gcc -std=c11 -O2 -Wall -Wextra -Werror -shared -fPIC "$src/glfinish.c" -ldl -o "$out/glfinish-test.so" &
test_build_pids+=("$!")
# The GPU probe needs Vulkan's headers to build. Lavapipe, the runner's only Vulkan device, runs it.
gcc -std=c11 -O2 -Wall -Wextra -Werror "$src/gpu-probe.c" -ldl -o "$out/gpu-probe-test" &
test_build_pids+=("$!")
# The Present probe needs libxcb-present's headers; Xvfb, with its fake 60 Hz vblank, runs it.
gcc -std=c11 -O2 -Wall -Wextra -Werror "$src/present-probe.c" -lxcb-dri3 -lxcb-present -lxcb -ldl -o "$out/present-probe-test" &
test_build_pids+=("$!")
# Its vblank and crtc modes run on a fake DRM card, preloaded. Test-only, like the fake libdrm.
gcc -std=c11 -O2 -Wall -Wextra -Werror -shared -fPIC "$src/fake-card.c" -ldl -o "$out/libfakecard.so" &
test_build_pids+=("$!")
for variant in normal sanitize; do
  flags=(-std=c11 -O2 -Wall -Wextra -Werror)
  if [[ $variant == sanitize ]]; then
    flags+=(-O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer)
  fi
  gcc "${flags[@]}" "$hash" "$src/wire.c" "$src/handoff.c" "$src/report.c" "$src/test-r2.c" "$wraps" -o "$out/test-r2-$variant" &
  test_build_pids+=("$!")
done
for pid in "${test_build_pids[@]}"; do
  wait "$pid"
done

export M19_SHIM_LIB="$out_abs/xorg-shim-test.so" M19_SHIM_DRIVER="$out_abs/test-shim" M19_GLFINISH_LIB="$out_abs/glfinish-test.so"
export M19_GPU_PROBE="$out_abs/gpu-probe-test" M19_LVP_ICD="$lvp"
export M19_PRESENT_PROBE="$out_abs/present-probe-test" M19_XVFB="$(command -v Xvfb)" M19_FAKE_CARD="$out_abs/libfakecard.so"

python3 "$src/test.py" --driver "$out/test-r2-normal" >"$out/run-normal.txt" 2>&1 &
pid_normal=$!
python3 "$src/test.py" --driver "$out/test-r2-sanitize" >"$out/run-sanitize.txt" 2>&1 &
pid_sanitize=$!
rc_normal=0
wait "$pid_normal" || rc_normal=$?
rc_sanitize=0
wait "$pid_sanitize" || rc_sanitize=$?
cat "$out/run-normal.txt" "$out/run-sanitize.txt"
# Not "test A && test B": under set -e a false A in an AND list does not stop the script.
if [ "$rc_normal" -ne 0 ] || [ "$rc_sanitize" -ne 0 ]; then
  echo "tests failed: normal=$rc_normal sanitize=$rc_sanitize" >&2
  exit 1
fi

# Mutants depend on the tests, not on the CPU: CI runs them once, in a job of their own.
if [[ ${M19_MUTANTS:-1} == 1 ]]; then
  python3 "$src/mutate.py" | tee "$out/mutants.txt"
fi
# Reviewable binaries only, never a boot image. Independent outputs must match.
artifact_pids=()
for copy in a b; do
  flags=(-std=c11 -Os -Wall -Wextra -Werror -static -Wl,--build-id=none)
  for pid in pid2 pid3 pid4 pid5 pid6 pid7; do
    gcc "${flags[@]}" "$hash" scripts/m19/run1/r1.c "$src/wire.c" "$src/handoff.c" "$src/report.c" "$src/$pid.c" -o "$out/$pid-$copy" &
    artifact_pids+=("$!")
  done
  gcc -std=c11 -Os -Wall -Wextra -Werror -shared -fPIC -Wl,--build-id=none "$src/xorg-shim.c" -ldl -o "$out/xorg-shim-$copy.so" &
  artifact_pids+=("$!")
  gcc -std=c11 -Os -Wall -Wextra -Werror -shared -fPIC -Wl,--build-id=none "$src/glfinish.c" -ldl -o "$out/glfinish-$copy.so" &
  artifact_pids+=("$!")
  # Dynamic on purpose: it opens the tree's own Vulkan loader. Built on the tree's Ubuntu release.
  gcc -std=c11 -Os -Wall -Wextra -Werror -Wl,--build-id=none "$src/gpu-probe.c" -ldl -o "$out/gpu-probe-$copy" &
  artifact_pids+=("$!")
  gcc -std=c11 -Os -Wall -Wextra -Werror -Wl,--build-id=none "$src/present-probe.c" -lxcb-dri3 -lxcb-present -lxcb -ldl -o "$out/present-probe-$copy" &
  artifact_pids+=("$!")
done
for pid in "${artifact_pids[@]}"; do
  wait "$pid"
done
for pid in pid2 pid3 pid4 pid5 pid6 pid7; do
  cmp "$out/$pid-a" "$out/$pid-b"
  sha256sum "$out/$pid-a"
done | tee "$out/run2-binaries.txt"
cmp "$out/xorg-shim-a.so" "$out/xorg-shim-b.so"
sha256sum "$out/xorg-shim-a.so" | tee -a "$out/run2-binaries.txt"
cmp "$out/glfinish-a.so" "$out/glfinish-b.so"
sha256sum "$out/glfinish-a.so" | tee -a "$out/run2-binaries.txt"
cmp "$out/gpu-probe-a" "$out/gpu-probe-b"
sha256sum "$out/gpu-probe-a" | tee -a "$out/run2-binaries.txt"
cmp "$out/present-probe-a" "$out/present-probe-b"
sha256sum "$out/present-probe-a" | tee -a "$out/run2-binaries.txt"
