#!/usr/bin/env bash
# R5a + R5b: the audio helper on a fake kernel, the Run31 session speaker holder over stand-in nodes and
# QRTR/ALSA/ADSP fixtures, normal and ASan/UBSan, the audio stage, T3-audio and T9-audio on synthetic trees,
# the mutants, and the reviewable static helpers built twice. No device, no module and no image from the phone.
set -euo pipefail
out=${1:?output}; mkdir -p "$out"
src=scripts/m19/run5
hash=scripts/m19/unlock/hash.c
repair=scripts/m11/qualification/runtime-repair
own=scripts/m11/qualification/ownership
native=scripts/m11/anchor-native

spk_srcs=("$hash")
for u in m11_gpr_engine m11_shmem m11_apm_protocol m11_aw_protection m11_strict_mock; do
  spk_srcs+=("$repair/$u.c")
done
for u in m11_custodian m11_pid1_anchor m11_anchor_linux m11_anchor_owner; do
  spk_srcs+=("$own/$u.c")
done
for u in gpr_transport_native shmem_backend_native dmabuf_pool_native heap_node_native intent_journal_native \
         pdr_loop_native terminal_native custodian_runner_native custodian_boot_native pd_session_native \
         custodian_entry_native snd_backend_native speaker_plan_native speaker_session_native; do
  spk_srcs+=("$native/$u.c")
done
spk_srcs+=("$src/speaker.c" "$src/test-speaker.c")

for variant in normal sanitize; do
  flags=(-std=c11 -O2 -Wall -Wextra -Werror)
  extra_py=()
  if [[ $variant == sanitize ]]; then
    flags+=(-O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer)
    extra_py+=(--no-root-speaker)
  fi
  gcc "${flags[@]}" -DM19_AUDIO_TEST "$hash" "$src/audio.c" "$src/test-audio.c" -o "$out/test-audio-$variant"
  gcc "${flags[@]}" -DM11_ANCHOR_NATIVE -DM11_CUSTODIAN_NATIVE -DM11_ANCHOR_NATIVE_ION \
    -I"$own" -I"$repair" -I"$native" -I"$src" \
    "${spk_srcs[@]}" -o "$out/test-speaker-$variant"
  python3 "$src/test.py" --driver "$out/test-audio-$variant" --speaker-driver "$out/test-speaker-$variant" \
    "${extra_py[@]}" 2>&1 | tee "$out/run-$variant.txt"
done
# Mutants depend on the tests, not on the CPU: CI runs them once, in a job of their own.
if [[ ${M19_MUTANTS:-1} == 1 ]]; then
  python3 "$src/mutate.py" | tee "$out/mutants.txt"
fi
# Reviewable binaries only, never a boot image. Independent outputs must match.
for copy in a b; do
  gcc -std=c11 -Os -Wall -Wextra -Werror -static -Wl,--build-id=none "$hash" "$src/audio.c" -o "$out/m19-audio-$copy"
done
cmp "$out/m19-audio-a" "$out/m19-audio-b"
sha256sum "$out/m19-audio-a" | tee "$out/run5-binaries.txt"
bash "$src/build-speaker.sh" "$out"
