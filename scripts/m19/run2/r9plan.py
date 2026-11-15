#!/usr/bin/env python3
"""R9 on top of R8d: the desktop's sound without breaks, and a log of it in the tree (docs/m19-r9.md).

- PulseAudio runs with real-time and high priority. Its pipe sink's thread then keeps marble-sink's FIFO filled while
  a browser decodes video on every core. R6 to R8 ran it with --realtime=no --high-priority=no. marble-sink runs at
  the same nice level, -11, as PulseAudio's main thread. Neither is a real-time busy loop: PulseAudio's I/O thread
  waits on the pipe, and marble-sink waits on the speaker's PCM.
- marble-audio-log.service appends marble-sink's counters to /var/lib/m19/sink-status.log in the tree. It writes a
  line when the sound starts or stops or a count of short buffers moves, at most one every 5 s. The file stays under
  1 MiB, with one older file beside it. Android reads it back after Shut Down: a video played in the session leaves
  its gaps there.
Everything else is R8d's: the plan keeps R8's layout under m19/r8, which run8's T9-root reads, with R9's target as
the default.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import r4plan  # noqa: E402
import r8plan  # noqa: E402

CONTROL = 'run/systemd/system.control/'
PULSE_ARGS = ('--realtime=no --high-priority=no', '--realtime=yes --high-priority=yes')
SINK_NICE = ('OOMScoreAdjust=-900\n', 'OOMScoreAdjust=-900\nNice=-11\n')

SINK_LOG = '''# M19 R9: marble-sink's counters, kept in the tree for reading back from Android after the session. A line when the
# sound starts or stops or a count of short buffers moves, polled every 5 s; under 1 MiB, then one older file.
dir=/var/lib/m19
log=$dir/sink-status.log
mkdir -p "$dir" || exit 1
echo "boot $(cat /proc/sys/kernel/random/boot_id)" >>"$log" || exit 1
last=
while sleep 5; do
  status=$(cat /run/m19/sink.status 2>/dev/null) || continue
  key=$(printf '%s\\n' "$status" | grep -E '^(amp_on|underruns|gaps)=')
  [ -n "$key" ] && [ "$key" != "$last" ] || continue
  last=$key
  size=$(stat -c %s "$log" 2>/dev/null || echo 0)
  [ "$size" -lt 1048576 ] || mv -f "$log" "$log.1"
  line=$(printf '%s\\n' "$status" | grep -E '^(streaming|amp_on|buffers|bytes_in|underruns|gaps)=' | tr '\\n' ' ')
  printf '%s %s\\n' "$(cut -d' ' -f1 /proc/uptime)" "$line" >>"$log"
done
'''

AUDIO_LOG = '''[Unit]
Description=M19 R9 marble-sink's counters into /var/lib/m19 for reading back from Android
DefaultDependencies=no
IgnoreOnIsolate=yes
After=local-fs.target

[Service]
Type=simple
ExecStart=/bin/sh /run/m19/etc/sink-log
Restart=no
Nice=10
LimitCORE=0
StandardInput=null
StandardOutput=journal
StandardError=journal
'''

TARGET = r4plan._swap(r4plan._swap(r4plan._swap(r8plan.TARGET, "Description=M19 R8: R7a's session on the read-write Ubuntu root, with the battery on the panel",
                                                "Description=M19 R9: R8d's session with the desktop's sound held to whole buffers"),
                                   'm19-r8-report.service', 'm19-r9-report.service'),
                      ' marble-xfce.service\n', ' marble-xfce.service marble-audio-log.service\n')
REPORT = r4plan._swap(r8plan.REPORT, 'M19 R8 evidence over USB', 'M19 R9 evidence over USB')


def files():
    """R8d's files with R9's target, report, sound priorities and the sink's log."""
    out = {}
    for where, text in r8plan.files().items():
        if where in (CONTROL + 'm19-r8.target', CONTROL + 'm19-r8-report.service'):
            continue
        if where == CONTROL + 'marble-pulse.service':
            text = r4plan._swap(text, *PULSE_ARGS)
        if where == CONTROL + 'marble-sink.service':
            text = r4plan._swap(text, *SINK_NICE)
        out[where] = text
    out[CONTROL + 'm19-r9.target'] = TARGET
    out[CONTROL + 'm19-r9-report.service'] = REPORT
    out[CONTROL + 'marble-audio-log.service'] = AUDIO_LOG
    out['run/m19/etc/sink-log'] = SINK_LOG
    return out


def render():
    """R8d's plan with R9's files under m19/r8/root and R9's target as the default."""
    r8 = r8plan.render()
    placed = files()
    assert not any('/etc/m19/' in text for text in placed.values())
    out = {name: data for name, data in r8.items() if not name.startswith('m19/r8/root/')}
    out['m19/r8/default'] = b'm19-r9.target\n'
    out['m19/r8/files'] = ''.join(f'{where}\n' for where in placed).encode()
    out.update({f'm19/r8/root/{where}': text.encode() for where, text in placed.items()})
    return out


if __name__ == '__main__':
    for name, data in render().items():
        print(f'{len(data):6d} {name}')
