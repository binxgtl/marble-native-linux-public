# M11 Run21 evidence protocol v3 (transport unchanged from Run20)

Software only; no phone authorization. Run19 stays consumed FAIL/INCONCLUSIVE and Run20 is
not booted. Run21 reuses the Run20 M11I3 sender-sealed transport; see
`scripts/m11/run21/SPEC.md` ("Transport") for the interface contract. Only the relay's
runtime paths, the START run tag and the two capacity constants differ from Run20:

- runtime directory `/run/m11-instrumentation/` (`logger.stop`, `logger.ready`, `usb.ready`,
  `logger.done`); the E-stream source file is `/run/m11-instrumentation/journal`;
- S payload `run=M11R21 nonce=<32 lowercase hex>\n`;
- `EVENT_RESERVE` = 1 MiB + 64 KiB (`journal.sh` caps the journal at 1 MiB) and `CAP` = 4 MiB;
  K frames may only fill `CAP - EVENT_RESERVE`, so the E stream can always be queued; a
  `logger.stop` byte boundary above `EVENT_RESERVE` is rejected by the relay;
- write-only tty (`O_WRONLY`), no host ACK, identical SHA seal and F frame.

The E stream is the runner journal: `M11I1 <seq> <time> session ...` records with hex
payloads, ending with `M11I1 END <seq> <sha256>`. The host qualifies it with
`scripts/m11/instrumentation/evidence.py` `inspect_journal` using the on-device
`/m11/instrumentation/nonce` and `identity` values (`check-capture.py --journal-nonce
--journal-identity`; missing values fail closed). The Run20 `[M11R19 event] FINAL_EVIDENCE`
terminal rule no longer applies.

Wire: `M11I3 <kind> <sequence> <payload_bytes>\n` followed by exactly that many
bytes. Canonical decimal (no leading zeros), sequence starts at zero, contiguous.
Kinds S, K, E, W, F. S is first, unique: `run=M11R21 nonce=<32 lowercase hex>\n`.
Production nonce uses getrandom; failure aborts. K is one complete devkmsg record;
kernel sequence must be contiguous. E is the bounded runner journal (up to
`EVENT_RESERVE` bytes). W is loss evidence and always disqualifies. Payloads are 1..16384 bytes.

SHA-256 covers the exact serialized S/K/E/W headers AND payloads from byte zero
through the byte immediately before F, followed by the virtual domain suffix
`M11I3 SEAL\n` and canonical metadata
`frames=N bytes=B events=E kernel_drops=D\n`. The suffix binds EVERY final counter,
including terminal kernel loss; it is not counted as physical wire/tty bytes.
F hash fields are excluded from their own digest; no circular self-hash. F has the next sequence and canonical payload:
`frames=N bytes=B events=E kernel_drops=D sha256=H tty_sha256=T\n`.
N counts covered physical frames, B counts covered wire bytes (excluding the virtual suffix), E counts event bytes.
H hashes atomically constructed/enqueued frames; T independently hashes bytes
accepted by positive tty writes. F is built only after all covered bytes have
drained, and only if B equals accepted bytes and H equals T. Short writes advance
only the returned byte count; EAGAIN/EINTR do not advance. Impossible write counts
are fatal. Zero writes are bounded by the existing stop deadline.

The host recomputes SHA with Python hashlib over received covered bytes and
checks BOTH hashes, all counts, sequence, a complete valid runner journal and complete F.
No resynchronization, no repaired captures. Receiver receipt independently seals
the complete raw file including F with SHA-256 and byte count. Qualification also
requires terminal-frame termination, clean flush/close, and an explicit empty
serial-error list. Missing receipt, disconnect, deadline, framing/overrun, sink
failure or trailing bytes FAIL even if diagnostic suffixes look successful.

Positive tty writes prove FIFO acceptance, not physical USB delivery. Only a
complete matching host capture proves receipt of the covered bytes at the host;
there is no device-side physical-delivery ACK (the host is receive-only). SHA detects
accidental corruption, not an adversarial sender or forged receipt. The final scope stops
at the journal boundary published by `journal_finish`, before later cleanup/color/reboot; it
cannot qualify those later operations. A missing F remains incomplete.

Tests (`scripts/m11/run21/test-transport.sh`, `test-protocol.py`, `test-elf.py`,
`test-host-reader.ps1`): production framing/SHA/partial-write code, actual relay lifecycle with
syscall fixtures, the Run20 131072-byte event boundary now accepted, a stop boundary above
`EVENT_RESERVE` rejected, a journal-bearing E stream that passes, a journal with a broken END
digest that fails, all EOF cuts/deletions/sequence faults, loss and `kernel_drops` corruption,
receipt fail-closed cases, and an actual pinned ARM64 ELF over a private PTY.

The provisional M11I2 freeze is superseded/NEVER BOOT: its unbound final drop counter could be corrupted from1 to0 without altering the prefix hash. V3 regression rejects that case.
