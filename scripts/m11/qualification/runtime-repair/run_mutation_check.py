#!/usr/bin/env python3
"""Mutation check for the M11 runtime hardening (P1..P6).

Each mutant re-introduces ONE of the defects the hardening removed (or breaks one of its
safety rules) in a private copy of the production sources, rebuilds, and runs the regression
suite. A compiled mutant is KILLED when the suite reports FAIL / crashes, or when the
known event-deadline mutant demonstrably stalls in its directed endless-event case.
A build failure or unattributed harness timeout is INVALID, never KILLED. A SURVIVOR
means the suite cannot see that defect, which is a test gap, and this script exits non-zero.

usage: run_mutation_check.py <out-dir> [--cc gcc] [--sanitize]
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROD = ["m11_gpr_engine.c", "m11_shmem.c", "m11_apm_protocol.c", "m11_aw_protection.c",
        "m11_offline_sim.c"]
SUPPORT = ["m11_strict_mock.c", "test_runtime_hardening.c"]
HEADERS = sorted(p.name for p in HERE.glob("*.h"))


@dataclass(frozen=True)
class Mutant:
    mid: str
    finding: str
    file: str
    old: str
    new: str
    what: str
    # further (file, old, new) edits applied together with the first one
    extra: tuple = ()


MUTANTS = [
    # ---- P1: deadline wait ------------------------------------------------------------------
    Mutant("M01", "P1", "m11_gpr_engine.c",
           "        if (slot->completed) return 0;\n\n        uint64_t now = engine_now_ms(eng);",
           "        if (slot->completed) return 0;\n        if (++stalled > 64u) return -ETIMEDOUT; /* MUTANT: iteration cap */\n\n        uint64_t now = engine_now_ms(eng);",
           "re-introduce the 64-iteration cap"),
    Mutant("M02", "P1", "m11_gpr_engine.c",
           "        int prc = m11_gpr_engine_pump_once(eng, (uint32_t)remaining);",
           "        int prc = m11_gpr_engine_pump_once(eng, timeout_ms); /* MUTANT: full timeout per poll */",
           "give every poll the full timeout instead of the remaining time"),
    Mutant("M03", "P1", "m11_gpr_engine.c",
           "        now = engine_now_ms(eng);\n        if (now >= deadline) return -ETIMEDOUT;",
           "        now = engine_now_ms(eng);\n        if (now >= deadline + 1000000u) return -ETIMEDOUT; /* MUTANT: deadline never fires */",
           "events can extend the transaction indefinitely"),
    Mutant("M04", "P1", "m11_gpr_engine.c",
           "        if (prc < 0 && eng->last_rx_status == M11_GPR_RX_TRANSPORT_ERR) {\n"
           "            /*\n"
           "             * Real transport/fd error (or poll timeout) from poll_read_fn or engine state\n"
           "             * (-ETIMEDOUT, -ENETRESET, -EIO, -EBADF, -ENODEV, -EPIPE, -EFAULT, ...):\n"
           "             * surface the exact errno instead of masking it.\n"
           "             */\n"
           "            return prc;",
           "        if (prc < 0 && eng->last_rx_status == M11_GPR_RX_TRANSPORT_ERR) {\n"
           "            return -ETIMEDOUT; /* MUTANT: transport errno masked as a timeout */",
           "mask transport errnos as timeouts"),
    Mutant("M05", "P1", "m11_gpr_engine.c",
           "        if (hdr.token == 0) {\n"
           "        eng->rx_unsolicited_events++;" if False else
           "    if (hdr.src_port != slot->dst_port) {",
           "    if (false && hdr.src_port != slot->dst_port) { /* MUTANT: peer port check removed */",
           "drop the response peer-port check"),
    # ---- P2: orphan tracking ----------------------------------------------------------------
    Mutant("M06", "P2", "m11_gpr_engine.c",
           "    return opcode == M11_APM_CMD_SHARED_MEM_MAP_REGIONS ||\n           opcode == M11_APM_CMD_SHARED_MEM_UNMAP_REGIONS;",
           "    (void)opcode;\n    return false; /* MUTANT: nothing is retained */",
           "do not retain timed-out ownership-bearing requests"),
    Mutant("M07", "P2", "m11_gpr_engine.c",
           "        if (cand != 0u && !token_in_use(eng, cand)) {",
           "        if (cand != 0u || token_in_use(eng, cand)) { /* MUTANT: reuse tokens still reserved */",
           "hand out a token that a reserved slot still owns"),
    Mutant("M08", "P2", "m11_shmem.c",
           "        /* The late MAP ACK is the DSP's answer to our request: adopt the handle. */\n        mgr->active_dsp_maps++;\n        region->dsp_mapped = true;\n        region->mem_map_handle = rsp.mem_map_handle;",
           "        /* MUTANT: late ACK ignored */\n        (void)rsp;\n        mgr->active_dsp_maps++;\n        region->dsp_mapped = true;\n        region->mem_map_handle = 0xDEADu;",
           "adopt a wrong handle from a late MAP ACK"),
    Mutant("M09", "P2", "m11_shmem.c",
           "        /*\n         * Timeout, transport error or PDR AFTER 0x0100100C was transmitted: the ADSP may have\n         * created the mapping. The engine kept the token reserved (orphan) except after PDR.\n         */",
           "        if (rc == -ETIMEDOUT) { /* MUTANT: free on timeout */\n            out_region->remote_inactive = true;\n            out_region->last_error = rc;\n            (void)release_local_handles(mgr, out_region);\n            return rc;\n        }\n        /* unreachable comment */",
           "free the buffer when the MAP times out"),
    Mutant("M10", "P2", "m11_shmem.c",
           "            if (rc == -EREMOTEIO && dsp_status != 0u) {\n                mark_unresolved(mgr, region, M11_SHMEM_CAUSE_UNMAP_NACK, rc,\n                                M11_SHMEM_ORPHAN_NONE, 0u, B_UNMAP_NACK);\n                return rc;\n            }",
           "            if (rc == -EREMOTEIO && dsp_status != 0u) {\n                region->remote_inactive = true; /* MUTANT: UNMAP NACK taken as 'unmapped' */\n                return release_local_handles(mgr, region);\n            }",
           "treat an UNMAP NACK as proof the mapping is gone"),
    Mutant("M11", "P2", "m11_shmem.c",
           "    if (rc == -ENETRESET) {\n        clear_orphan(region);\n        region->cause = is_map ? M11_SHMEM_CAUSE_MAP_PDR : M11_SHMEM_CAUSE_UNMAP_PDR;\n        region->blocker = B_PDR;\n        return -ENETRESET;\n    }",
           "    if (rc == -ENETRESET) {\n        clear_orphan(region); /* MUTANT: PDR taken as 'mapping vanished' */\n        region->remote_inactive = true;\n        return release_local_handles(mgr, region);\n    }",
           "infer that a mapping disappeared after PDR"),
    Mutant("M12", "P2", "m11_shmem.c",
           "            m11_shmem_cause_t cause = M11_SHMEM_CAUSE_UNMAP_TRANSPORT_ERR;\n",
           "            { uint32_t tok2 = 0; (void)m11_gpr_engine_submit_ex(mgr->gpr, M11_GPR_CLIENT_DATA_DEFAULT, M11_APM_MODULE_IID, M11_APM_CMD_SHARED_MEM_UNMAP_REGIONS, &cmd, sizeof(cmd), &tok2); } /* MUTANT: blind UNMAP resend after a timeout */\n"
           "            m11_shmem_cause_t cause = M11_SHMEM_CAUSE_UNMAP_TRANSPORT_ERR;\n",
           "blindly resend UNMAP after it timed out"),
    Mutant("M12b", "P2", "m11_shmem.c",
           "        /* -ETIMEDOUT (still outstanding) or a transport errno: the orphan stays tracked. */\n",
           "        if (!is_map && rc == -ETIMEDOUT) { m11_apm_cmd_shared_mem_unmap_regions_t c2 = { .mem_map_handle = region->mem_map_handle }; uint32_t t2 = 0; (void)m11_gpr_engine_submit_ex(mgr->gpr, M11_GPR_CLIENT_DATA_DEFAULT, M11_APM_MODULE_IID, M11_APM_CMD_SHARED_MEM_UNMAP_REGIONS, &c2, sizeof(c2), &t2); } /* MUTANT: reconcile resends UNMAP */\n"
           "        /* -ETIMEDOUT (still outstanding) or a transport errno: the orphan stays tracked. */\n",
           "reconcile resends the UNMAP it is waiting for"),
    Mutant("M12c", "P2", "m11_shmem.c",
           "        /* -ETIMEDOUT (still outstanding) or a transport errno: the orphan stays tracked. */\n",
           "        if (is_map && rc == -ETIMEDOUT) { uint8_t z[20] = {0}; uint32_t t2 = 0; (void)m11_gpr_engine_submit_ex(mgr->gpr, M11_GPR_CLIENT_DATA_DEFAULT, M11_APM_MODULE_IID, M11_APM_CMD_SHARED_MEM_MAP_REGIONS, z, sizeof(z), &t2); } /* MUTANT: reconcile resends MAP */\n"
           "        /* -ETIMEDOUT (still outstanding) or a transport errno: the orphan stays tracked. */\n",
           "reconcile resends the MAP it is waiting for"),
    Mutant("M12d", "P2", "m11_shmem.c",
           "    region->remote_inactive = true;\n    uncount_unresolved(mgr, region);\n    region->blocker = NULL;\n    region->cause = M11_SHMEM_CAUSE_NONE;\n    region->state = M11_SHMEM_STATE_DSP_UNMAP_ACKNOWLEDGED;",
           "    region->remote_inactive = false; /* MUTANT: a late UNMAP ACK does not count */\n    uncount_unresolved(mgr, region);\n    region->blocker = NULL;\n    region->cause = M11_SHMEM_CAUSE_NONE;\n    region->state = M11_SHMEM_STATE_DSP_UNMAP_ACKNOWLEDGED;",
           "ignore a late UNMAP ACK"),
    # ---- P4: remote vs local ----------------------------------------------------------------
    Mutant("M13", "P4", "m11_shmem.c",
           "        if (!region->remote_inactive) {\n            /* Inconsistent: LOCAL_RELEASE_PENDING must carry the remote-inactive proof. */\n            mark_unresolved(mgr, region, M11_SHMEM_CAUSE_LOCAL_RELEASE_FAILED, -EPROTO,\n                            M11_SHMEM_ORPHAN_NONE, 0u, B_NO_PROOF);\n            return -EPROTO;\n        }\n",
           "        (void)B_NO_PROOF; /* MUTANT: inconsistent-record gate removed */\n",
           "no quarantine for a LOCAL_RELEASE_PENDING record without the remote-inactive proof"),
    Mutant("M13b", "P4", "m11_shmem.c",
           "        if (!region->remote_inactive) {\n            /* Inconsistent: LOCAL_RELEASE_PENDING must carry the remote-inactive proof. */\n            mark_unresolved(mgr, region, M11_SHMEM_CAUSE_LOCAL_RELEASE_FAILED, -EPROTO,\n                            M11_SHMEM_ORPHAN_NONE, 0u, B_NO_PROOF);\n            return -EPROTO;\n        }\n",
           "        (void)B_NO_PROOF; /* MUTANT: inconsistent-record gate removed */\n",
           "release local handles without the remote-inactive proof (both gates removed)",
           extra=(("m11_shmem.c", "    if (!region->remote_inactive) {\n        /* Defence in depth: refuse, touch nothing. */\n        return -EBUSY;\n    }\n", "    /* MUTANT: defence-in-depth gate removed */\n"),)),
    Mutant("M14", "P4", "m11_shmem.c",
           "        if (rc < 0) {\n            mark_local_pending(mgr, region, rc);\n            return rc;\n        }\n        region->dma_buf_fd = -1;",
           "        if (rc < 0) {\n            mark_unresolved(mgr, region, M11_SHMEM_CAUSE_LOCAL_RELEASE_FAILED, rc, M11_SHMEM_ORPHAN_NONE, 0u, B_NO_PROOF); /* MUTANT: old behaviour */\n            return rc;\n        }\n        region->dma_buf_fd = -1;",
           "close failure sends the region back to UNRESOLVED (old defect)"),
    Mutant("M15", "P4", "m11_shmem.c",
           "static void count_unresolved(m11_shmem_mgr_t *mgr, m11_shmem_region_t *region) {\n    if (!region->counted_unresolved) {",
           "static void count_unresolved(m11_shmem_mgr_t *mgr, m11_shmem_region_t *region) {\n    if (true) { /* MUTANT: counter not deduplicated */",
           "count one region several times"),
    Mutant("M16", "P4", "m11_shmem.c",
           "        region->ion_imported = false;\n        if (mgr->active_ion_imports > 0) mgr->active_ion_imports--;",
           "        if (mgr->active_ion_imports > 0) mgr->active_ion_imports--; /* MUTANT: handle flag kept */",
           "forget to record that the ion import was released"),
    Mutant("M17", "P4", "m11_shmem.c",
           "    if (region->state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED ||\n        region->state == M11_SHMEM_STATE_DSP_MAP_REQUESTED ||\n        region->state == M11_SHMEM_STATE_DSP_UNMAP_REQUESTED) {\n        return -EBUSY;\n    }",
           "    if (region->state == M11_SHMEM_STATE_DSP_MAP_REQUESTED ||\n        region->state == M11_SHMEM_STATE_DSP_UNMAP_REQUESTED) {\n        return -EBUSY;\n    }\n    if (region->state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED) { /* MUTANT: free unresolved */\n        region->remote_inactive = true;\n        return release_local_handles(mgr, region);\n    }",
           "unmap_and_free releases an UNRESOLVED region"),
    # ---- P5: bracket ------------------------------------------------------------------------
    Mutant("M18", "P5", "m11_apm_protocol.c",
           "        if (opened_here) {\n            int crc = m11_shmem_end_cpu_access(shmem_mgr, region);\n            region->last_error = rc;\n            if (crc < 0) region->cleanup_error = crc;\n        } else {",
           "        if (opened_here && false) { /* MUTANT: bracket leaked */\n"
           "            int crc = m11_shmem_end_cpu_access(shmem_mgr, region);\n"
           "            region->last_error = rc;\n"
           "            if (crc < 0) region->cleanup_error = crc;\n"
           "        } else {",
           "do not close the bracket after a build failure"),
    Mutant("M19", "P5", "m11_apm_protocol.c",
           "    rc = m11_shmem_end_cpu_access(shmem_mgr, region);\n    if (rc < 0) return rc;\n\n    if (region->cpu_access_active",
           "    rc = m11_shmem_end_cpu_access(shmem_mgr, region);\n    (void)rc; /* MUTANT: END failure ignored */\n\n    if (region->cpu_access_active",
           "ignore a failing END_RW and carry on"),
    Mutant("M19b", "P5", "m11_apm_protocol.c",
           "    rc = m11_shmem_end_cpu_access(shmem_mgr, region);\n    if (rc < 0) return rc;\n",
           "    rc = m11_shmem_end_cpu_access(shmem_mgr, region);\n    (void)rc; /* MUTANT: END failure ignored */\n",
           "send GRAPH_OPEN although END_RW failed (both guards removed)",
           extra=(("m11_apm_protocol.c", "    if (region->cpu_access_active || !region->cpu_cache_clean_for_dsp) {\n        return -EIO;\n    }\n", "    /* MUTANT: second guard removed */\n"),)),
    Mutant("M20", "P5", "m11_apm_protocol.c",
           "            int crc = m11_shmem_end_cpu_access(shmem_mgr, region);\n            region->last_error = rc;\n            if (crc < 0) region->cleanup_error = crc;\n        } else {",
           "            int crc = m11_shmem_end_cpu_access(shmem_mgr, region);\n            region->last_error = rc;\n            if (crc < 0) { region->cleanup_error = crc; return crc; } /* MUTANT: primary error replaced */\n        } else {",
           "let the cleanup END error replace the primary build error"),
    Mutant("M21", "P5", "m11_shmem.c",
           "        region->cpu_cache_clean_for_dsp = false;\n        region->sync_end_failures++;\n        region->last_error = rc;\n        return rc;",
           "        region->cpu_access_active = false; /* MUTANT: claims the bracket closed */\n        region->cpu_cache_clean_for_dsp = true;\n        region->last_error = rc;\n        return rc;",
           "claim a cache sync although END_RW failed"),
    # ---- P6: IBASIC vs data -----------------------------------------------------------------
    Mutant("M22", "P6", "m11_gpr_engine.c",
           "        if (ib.status == 0u && slot->expected_rsp_opcode != M11_GPR_IBASIC_RSP_RESULT) {",
           "        if (false && ib.status == 0u && slot->expected_rsp_opcode != M11_GPR_IBASIC_RSP_RESULT) {",
           "complete a data-bearing request on a bare IBASIC ACK"),
    Mutant("M23", "P6", "m11_gpr_engine.c",
           "        if (ib.status == 0u && slot->expected_rsp_opcode != M11_GPR_IBASIC_RSP_RESULT) {",
           "        if (ib.status == 0u) { /* MUTANT: ACK-only commands also stall */",
           "treat every IBASIC success as 'ACK without data'"),
    # ---- P3: per-channel report -------------------------------------------------------------
    Mutant("M24", "P3", "m11_aw_protection.c",
           "    rep->primary_error = err;\n    rep->primary_channel = (int)ch;\n}",
           "    rep->primary_error = err;\n    rep->primary_channel = (int)ch;\n    rep->pair_re_readback_verified = (rep->ch[0].stage == M11_AW_STAGE_READBACK_VERIFIED); /* MUTANT: claim on failure */\n}",
           "claim the pair verified on a failure path after channel 0 succeeded"),
    Mutant("M28", "P3", "m11_aw_protection.c",
           "        if (get_rsp.env.q12_re != cal->q12_re[ch]) {",
           "        if (false && get_rsp.env.q12_re != cal->q12_re[ch]) { /* MUTANT */",
           "accept a read-back that differs from what was written"),
    Mutant("M25", "P3", "m11_aw_protection.c",
           "        if (handed) {\n            c->stage = M11_AW_STAGE_SET_SENT;\n            c->dsp_state_may_have_changed = true;\n            rep->dsp_state_may_have_changed = true;\n        }",
           "        if (handed) {\n            c->stage = M11_AW_STAGE_SET_SENT;\n        } /* MUTANT: state change not recorded */",
           "forget that a sent SET_CFG may have changed DSP state"),
    Mutant("M26", "P3", "m11_aw_protection.c",
           "        if (rc < 0) {\n            aw_fail_channel(rep, ch, M11_AW_OP_SET_CFG, rc);\n            return rc;\n        }\n        c->stage = M11_AW_STAGE_SET_ACKED;",
           "        if (rc < 0) {\n            aw_fail_channel(rep, ch, M11_AW_OP_SET_CFG, rc);\n            continue; /* MUTANT: carry on with the next channel after a failure */\n        }\n        c->stage = M11_AW_STAGE_SET_ACKED;",
           "keep writing the other channel after a failure (no fail-stop)"),
    Mutant("M27", "P3", "m11_aw_protection.c",
           "    rep->safety_ctx_is_hardware_evidence = false;",
           "    rep->safety_ctx_is_hardware_evidence = true; /* MUTANT */",
           "treat the caller-asserted context as hardware evidence"),
    # ---- post-MAP hold (CP2 criterion 5): the simulator teardown and the PD-down record ------
    Mutant("M29", "HOLD", "m11_offline_sim.c",
           "    if (!hold && (all_cleanup_acked || gpr->pdr_down) &&",
           "    if ((!hold || gpr->pdr_down) && (all_cleanup_acked || gpr->pdr_down) && /* MUTANT */",
           "enter the UNMAP call on a latched PDR under the hold (quiet only through the engine latch)"),
    Mutant("M30", "HOLD", "m11_shmem.c",
           "    mark_unresolved(mgr, region, M11_SHMEM_CAUSE_MAP_PDR, -ENETRESET, M11_SHMEM_ORPHAN_NONE, 0u, B_PDR);",
           "    (void)0; /* MUTANT: PD down while held not recorded */",
           "leave a held region DSP_MAP_ACKNOWLEDGED after PD down"),
    # ---- P7: shared-memory end point data commands (P5 speaker session) -----------------------
    Mutant("M31", "P7", "m11_gpr_engine.c",
           "            if (!want || pl_len != want) {",
           "            if (!want) { /* MUTANT: any payload length */",
           "accept a data completion of the wrong size"),
    Mutant("M32", "P7", "m11_gpr_engine.c",
           "            slot->dsp_status = st;",
           "            slot->dsp_status = 0u; (void)st; /* MUTANT: data status ignored */",
           "report a failed buffer, EOS or read as success"),
    Mutant("M33", "P7", "m11_gpr_engine.c",
           "            return M11_DATA_CMD_RSP_WR_SH_MEM_EP_DATA_BUFFER_DONE_V2;",
           "            return M11_GPR_IBASIC_RSP_RESULT; /* MUTANT: buffer done not correlated */",
           "never complete a write buffer on its BUFFER_DONE"),
]


def run(cmd: list[str], cwd: Path, timeout: int = 300) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, text=True, capture_output=True, timeout=timeout)


def build_and_run(work: Path, cc: str, sanitize: bool, exe: Path) -> tuple[str, str]:
    flags = ["-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror", f"-I{work}"]
    if sanitize:
        flags += ["-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                  "-fno-omit-frame-pointer"]
    srcs = [str(work / n) for n in PROD + SUPPORT]
    b = run([cc, *flags, *srcs, "-o", str(exe)], work)
    if b.returncode != 0:
        print(b.stderr, file=sys.stderr)
        return "BUILD_FAIL", b.stderr.strip().splitlines()[-1] if b.stderr.strip() else ""
    try:
        r = run([str(exe)], work, timeout=30)
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or b""
        if isinstance(stdout, bytes): stdout = stdout.decode("utf-8", "replace")
        (work / "timeout-stdout.log").write_text(stdout, encoding="utf-8")
        active = [line[6:] for line in stdout.splitlines() if line.startswith("[RUN] ")]
        return "TIMEOUT", active[-1] if active else "unattributed"
    tail = [ln for ln in r.stdout.splitlines() if ln.startswith("[FAIL]")]
    if r.returncode == 0 and "HARDENING RESULT: PASS" in r.stdout:
        return "PASS", ""
    if r.returncode < 0 or "AddressSanitizer" in r.stderr or "runtime error" in r.stderr:
        return "CRASH", (r.stderr.strip().splitlines() or [""])[0]
    return "FAIL", f"{len(tail)} case(s) failed: " + ", ".join(t[7:] for t in tail[:3])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("out", type=Path)
    ap.add_argument("--cc", default="gcc")
    ap.add_argument("--sanitize", action="store_true")
    ap.add_argument("--only", default="", help="comma separated mutant ids")
    args = ap.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)

    only = {m for m in args.only.split(",") if m}
    base = out / "mutant-base"
    if base.exists():
        shutil.rmtree(base)
    base.mkdir()
    for n in PROD + SUPPORT + HEADERS:
        shutil.copy2(HERE / n, base / n)

    status, detail = build_and_run(base, args.cc, args.sanitize, out / "mutant-ref")
    print(f"reference (unmutated): {status} {detail}")
    if status != "PASS":
        print("the unmutated tree must pass before mutants mean anything", file=sys.stderr)
        return 2

    survivors, killed, invalid = [], [], []
    for m in MUTANTS:
        if only and m.mid not in only:
            continue
        work = out / m.mid
        if work.exists():
            shutil.rmtree(work)
        shutil.copytree(base, work)
        edits = [(m.file, m.old, m.new), *m.extra]
        bad = None
        for fname, old, new in edits:
            target = work / fname
            text = target.read_text(encoding="utf-8")
            if text.count(old) != 1:
                bad = f"pattern matched {text.count(old)} times in {fname}"
                break
            target.write_text(text.replace(old, new), encoding="utf-8")
        if bad:
            invalid.append((m, bad))
            print(f"{m.mid} [{m.finding}] INVALID  {m.what}: {bad}")
            continue
        status, detail = build_and_run(work, args.cc, args.sanitize, work / "exe")
        if status == "PASS":
            survivors.append(m)
            print(f"{m.mid} [{m.finding}] SURVIVED {m.what}")
        elif status == "TIMEOUT" and not (
            m.mid == "M03" and detail == "p1_endless_event_stream_cannot_extend_the_deadline_real_time"
        ):
            invalid.append((m, f"unqualified timeout in {detail}"))
            print(f"{m.mid} [{m.finding}] INVALID unqualified harness timeout: {detail}")
        elif status == "BUILD_FAIL":
            # A mutant that does not compile is not evidence about the tests.
            invalid.append((m, f"does not compile: {detail}"))
            print(f"{m.mid} [{m.finding}] INVALID  {m.what}: does not compile: {detail}")
        else:
            killed.append((m, status))
            print(f"{m.mid} [{m.finding}] killed ({status}) {m.what} -- {detail}")

    print(f"\nmutants: {len(killed)} killed, {len(survivors)} survived, {len(invalid)} invalid")
    if survivors or invalid:
        for m in survivors:
            print(f"  SURVIVOR {m.mid}: {m.what}", file=sys.stderr)
        for m, why in invalid:
            print(f"  INVALID  {m.mid}: {why}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
