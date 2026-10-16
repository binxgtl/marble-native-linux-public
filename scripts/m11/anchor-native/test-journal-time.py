"""Run22 strict-evidence defect, end to end: the actual journal.sh (BusyBox) opens the journal,
the C writer appends runner-format records, journal.sh's journal_finish closes it, and the
unmodified evidence.inspect_journal judges it. CI only (Linux, busybox).

cs (journal_time.h) must pass every round; ns (Run22's format) must reproduce the
'monotonic timestamp regressed' rejection in at least one round, so the harness discriminates."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'instrumentation'))
from evidence import CONDITIONS, inspect_journal  # noqa: E402

N, I = '1' * 32, '2' * 64
BB = shutil.which('busybox')
WRITER = Path(sys.argv[1]).resolve()
ROUNDS = 60


def journal(mode):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp); run = root / 'run'; run.mkdir(); work = run / 'm11-instrumentation'
        text = (HERE.parent / 'instrumentation/journal.sh').read_text()
        text = text.replace('/run/m11-instrumentation', str(work)).replace('stat -f -c %T /run', 'stat -f -c %T ' + str(run))
        script = root / 'journal.sh'; script.write_text(text)
        wrapper = root / 'bb'
        wrapper.write_text(f'#!/bin/sh\nif [ "$1" = stat ]; then echo tmpfs; exit 0; fi\nexec {BB} "$@"\n')
        wrapper.chmod(0o755)
        cmds = f'BB={wrapper}; . {script}; journal_init {N} {I} || exit 10;'
        for condition in CONDITIONS:
            cmds += f'journal_record {condition} unsupported metadata 95 not_implemented || exit 11;'
        # The runner's records, then control's journal_finish right after (as in Run22).
        cmds += f'{WRITER} append {work}/journal $J_SEQ 8 {mode} || exit 12; J_SEQ=$((J_SEQ + 8));'
        cmds += 'journal_finish || exit 13; exit 0'
        proc = subprocess.run([BB, 'sh', '-c', cmds], capture_output=True, timeout=20)
        assert proc.returncode == 0, (proc.returncode, proc.stderr)
        return (work / 'journal').read_bytes()


def main():
    assert BB, 'busybox required'
    for _ in range(ROUNDS):
        data = journal('cs')
        result = inspect_journal(data, N, I)
        assert result['event_stream_complete'], result
    rejected = 0
    for _ in range(ROUNDS):
        try:
            inspect_journal(journal('ns'), N, I)
        except ValueError as error:
            assert str(error) == 'monotonic timestamp regressed', error
            rejected += 1
    assert rejected >= 1, 'the Run22 ns format was never rejected: the harness does not discriminate'
    print(f'PASS journal.sh + C records + journal_finish: {ROUNDS}/{ROUNDS} centisecond journals accepted by '
          f'the unmodified evidence rule; Run22 ns format rejected in {rejected}/{ROUNDS} rounds')


if __name__ == '__main__':
    main()
