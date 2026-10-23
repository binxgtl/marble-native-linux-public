"""Independent Python oracle for M11 stock-compatible GPR/DMA/APM/Protection runtime repair."""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[4]
REPAIR_DIR = Path(__file__).resolve().parent
ARGON_ROOT: Path | None = None


def pack_gpr_v0(
    *,
    dst_domain_id: int,
    src_domain_id: int,
    client_data: int,
    src_port: int,
    dst_port: int,
    token: int,
    opcode: int,
    payload: bytes = b"",
) -> bytes:
    """Packs a canonical 24-byte v0 GPR packet matching scripts/m11/runtime/gpr_native.c."""
    total_len = 24 + len(payload)
    word0 = ((total_len & 0xFFFFFF) << 8) | (6 << 4) | 0
    hdr = struct.pack(
        "<IBBBBI I I I",
        word0,
        dst_domain_id,
        src_domain_id,
        client_data,
        0,
        src_port,
        dst_port,
        token,
        opcode,
    )
    return hdr + payload


class RuntimeRepairOracleTests(unittest.TestCase):
    def test_repaired_gpr_header_matches_canonical_oracle(self) -> None:
        gpr_native_c = (ROOT / "scripts" / "m11" / "runtime" / "gpr_native.c").read_text(
            encoding="utf-8"
        )
        # Verify canonical gpr_native.c serializer offsets:
        # tx[4]=2 (dst_domain_id), tx[5]=3 (src_domain_id), tx+8 (src_port), tx+12 (dst_port),
        # tx+16 (token), tx+20 (opcode)
        self.assertIn("put(tx,(24u<<8)|0x60u); tx[4]=2; tx[5]=3;", gpr_native_c)
        self.assertIn(
            "put(tx+8,M11_GPR_SOURCE_PORT); put(tx+12,1); put(tx+16,token); put(tx+20,M11_GPR_GET_SPF);",
            gpr_native_c,
        )

        hdr_text = (REPAIR_DIR / "m11_gpr_engine.h").read_text(encoding="utf-8")
        m = re.search(
            r"typedef\s+struct\s+__attribute__\(\(packed\)\)\s*\{([^}]+)\}\s*m11_gpr_hdr_t\s*;",
            hdr_text,
            re.S,
        )
        self.assertIsNotNone(m)
        fields = [
            (t, name)
            for t, name in re.findall(r"(uint(?:8|16|32)_t)\s+([A-Za-z0-9_]+)\s*;", m.group(1))
        ]
        self.assertEqual(
            fields,
            [
                ("uint32_t", "header"),
                ("uint8_t", "dst_domain_id"),
                ("uint8_t", "src_domain_id"),
                ("uint8_t", "client_data"),
                ("uint8_t", "reserved"),
                ("uint32_t", "src_port"),
                ("uint32_t", "dst_port"),
                ("uint32_t", "token"),
                ("uint32_t", "opcode"),
            ],
        )

        pkt = pack_gpr_v0(
            dst_domain_id=2,
            src_domain_id=3,
            client_data=0,
            src_port=0x2001,
            dst_port=1,
            token=0x11223344,
            opcode=0x01001021,
        )
        self.assertEqual(
            pkt.hex(),
            "601800000203000001200000010000004433221121100001",
        )
        w0, dst_dom, src_dom, cdata, rsv, src_p, dst_p, tok, op = struct.unpack(
            "<IBBBBIIII", pkt
        )
        self.assertEqual(w0, (24 << 8) | 0x60)
        self.assertEqual((dst_dom, src_dom, cdata, rsv), (2, 3, 0, 0))
        self.assertEqual((src_p, dst_p, tok, op), (0x2001, 1, 0x11223344, 0x01001021))

    def test_repaired_dma_ion_offset_mode_and_10_states(self) -> None:
        shmem_h = (REPAIR_DIR / "m11_shmem.h").read_text(encoding="utf-8")
        self.assertIn("#define M11_APM_MEMORY_MAP_SHMEM8_4K_POOL 3u", shmem_h)
        for state_name in (
            "M11_SHMEM_STATE_NOT_ALLOCATED",
            "M11_SHMEM_STATE_ALLOCATED",
            "M11_SHMEM_STATE_KERNEL_IMPORT_ESTABLISHED",
            "M11_SHMEM_STATE_DSP_MAP_REQUESTED",
            "M11_SHMEM_STATE_DSP_MAP_ACKNOWLEDGED",
            "M11_SHMEM_STATE_DSP_UNMAP_REQUESTED",
            "M11_SHMEM_STATE_DSP_UNMAP_ACKNOWLEDGED",
            "M11_SHMEM_STATE_RELEASED",
            "M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED",
            "M11_SHMEM_STATE_LOCAL_RELEASE_PENDING",
        ):
            self.assertIn(state_name, shmem_h)
        # Verify ion_import_fd_fn does not return a physical address to userspace
        self.assertNotIn("out_paddr_lsw", shmem_h)

        map_payload = struct.pack("<HHIIII", 3, 1, 0x4, 100, 0, 20480)
        map_pkt = pack_gpr_v0(
            dst_domain_id=2,
            src_domain_id=3,
            client_data=1,
            src_port=0x2002,
            dst_port=1,
            token=1,
            opcode=0x0100100C,
            payload=map_payload,
        )
        self.assertEqual(len(map_pkt), 44)
        self.assertEqual(
            map_pkt.hex(),
            "602c0000020301000220000001000000010000000c100001"
            "0300010004000000640000000000000000500000",
        )

    def test_repaired_apm_cfg_and_graph_serialization(self) -> None:
        aw_c = (REPAIR_DIR / "m11_aw_protection.c").read_text(encoding="utf-8")
        # Verify SET_CFG and GET_CFG route to sp_rx_module_iid (0x42D3), not port 1
        self.assertIn("safety_ctx->sp_rx_module_iid, M11_APM_CMD_SET_CFG", aw_c)
        self.assertIn("safety_ctx->sp_rx_module_iid, M11_APM_CMD_GET_CFG", aw_c)
        self.assertNotIn("M11_APM_MODULE_IID, M11_APM_CMD_SET_CFG", aw_c)
        self.assertNotIn("M11_APM_MODULE_IID, M11_APM_CMD_GET_CFG", aw_c)

        # Verify in-band GRAPH_PREPARE / START / STOP / CLOSE payload sizes
        vi_sgs = (0xB00000D5, 0xB00000CE)
        vi_block = struct.pack("<IIII I 2I I", 1, 0x08001005, 12, 0, 2, *vi_sgs, 0)
        self.assertEqual(len(vi_block), 32)
        vi_cmd_hdr = struct.pack("<IIII", 0, 0, 0, len(vi_block))
        vi_pkt = pack_gpr_v0(
            dst_domain_id=2,
            src_domain_id=3,
            client_data=0,
            src_port=0x2001,
            dst_port=1,
            token=5,
            opcode=0x01001001,
            payload=vi_cmd_hdr + vi_block,
        )
        self.assertEqual(len(vi_pkt), 72)

        rx_sgs = (0xB0000023, 0xB0000024, 0xB0000025, 0xB0000002)
        rx_block = struct.pack("<IIII I 4I I", 1, 0x08001005, 20, 0, 4, *rx_sgs, 0)
        self.assertEqual(len(rx_block), 40)
        rx_cmd_hdr = struct.pack("<IIII", 0, 0, 0, len(rx_block))
        rx_pkt = pack_gpr_v0(
            dst_domain_id=2,
            src_domain_id=3,
            client_data=0,
            src_port=0x2001,
            dst_port=1,
            token=6,
            opcode=0x01001002,
            payload=rx_cmd_hdr + rx_block,
        )
        self.assertEqual(len(rx_pkt), 80)

    def test_stock_binary_graph_and_shmem_instructions(self) -> None:
        stock_gsl = Path(
            "D:/idk.omg/ghidra-projects/marble-stock/extracted/vendor/vendor_a/lib64/libar-gsl.so"
        )
        stock_osal_probe = Path(
            "D:/idk.omg/ghidra-projects/marble-stock/extracted/vendor/vendor_a/lib64/liblx-osal.so"
        )
        if not stock_gsl.exists() and not stock_osal_probe.exists():
            # Without the proprietary binaries this checks nothing; say so instead of passing.
            self.skipTest("stock binaries are local-only and not present here (NOT a pass)")
        self.assertTrue(stock_gsl.exists() and stock_osal_probe.exists(),
                        "partial stock input cannot qualify both GSL and OSAL instruction checks")
        if stock_gsl.exists():
            gsl = stock_gsl.read_bytes()
            self.assertEqual(hashlib.sha256(gsl).hexdigest(),
                             "d46402219e582856b03d84972cef5ebb1687193c916d8ca7cc697a2b3b2120ad")
            self.assertEqual(len(gsl), 224440)
            # .rodata @ 0x09ec0: apm_module_param_data_t prefix (module_instance_id=1, param_id=0x08001005)
            self.assertEqual(struct.unpack_from("<II", gsl, 0x09EC0), (1, 0x08001005))
            # gsl_graph_prepare.cfi @ 0x1cbe4..0x1cbec: (num_sgs * 4 + 0x2b) & ~7
            self.assertEqual(
                struct.unpack_from("<III", gsl, 0x1CBE4),
                (0x531E76E9, 0x1100AD29, 0x121D7123),
            )
            # gsl_shmem_map_page_to_spf @ 0x25424: mov w8, #3 (APM_MEMORY_MAP_SHMEM8_4K_POOL)
            self.assertEqual(struct.unpack_from("<I", gsl, 0x25424)[0], 0x52800068)

        stock_osal = Path(
            "D:/idk.omg/ghidra-projects/marble-stock/extracted/vendor/vendor_a/lib64/liblx-osal.so"
        )
        if stock_osal.exists():
            osal = stock_osal.read_bytes()
            self.assertEqual(hashlib.sha256(osal).hexdigest(),
                             "b2565a4a84f8cf9bf4bb4b487f4e416d4c77ae6cdbdef9eb7a7cbf9286257a51")
            # ar_shmem_alloc @ 0xc39c..0xc3a8: DMA_BUF_IOCTL_SYNC (0x40086200) with flags = 0x3
            self.assertEqual(
                struct.unpack_from("<4I", osal, 0xC39C),
                (0x528C4001, 0x52800068, 0x910063E2, 0x72A80101),
            )
            # ar_shmem_free @ 0xc5e4..0xc5f0: DMA_BUF_IOCTL_SYNC (0x40086200) with flags = 0x7
            self.assertEqual(
                struct.unpack_from("<4I", osal, 0xC5E4),
                (0x528000E8, 0xF90003E8, 0xB9400260, 0x528C4001),
            )

    def test_hardening_source_shape(self) -> None:
        """Structural pins for the P1..P6 hardening.

        These are SOURCE-SHAPE checks only: they stop someone from deleting a guard while the
        behavioural proof lives in test_runtime_hardening.c (and its mutation run). A passing
        pin is not evidence that the behaviour is right.
        """
        gpr_h = (REPAIR_DIR / "m11_gpr_engine.h").read_text(encoding="utf-8")
        gpr_c = (REPAIR_DIR / "m11_gpr_engine.c").read_text(encoding="utf-8")
        shmem_h = (REPAIR_DIR / "m11_shmem.h").read_text(encoding="utf-8")
        shmem_c = (REPAIR_DIR / "m11_shmem.c").read_text(encoding="utf-8")
        apm_c = (REPAIR_DIR / "m11_apm_protocol.c").read_text(encoding="utf-8")
        aw_c = (REPAIR_DIR / "m11_aw_protection.c").read_text(encoding="utf-8")
        sim_c = (REPAIR_DIR / "m11_offline_sim.c").read_text(encoding="utf-8")

        self.assertIn("#define M11_RUNTIME_HARDENING_API_VERSION", gpr_h)

        # Only TX_NOT_ATTEMPTED proves that nothing reached the wire.
        for sym in ("M11_GPR_TX_NOT_ATTEMPTED", "M11_GPR_TX_WRITE_ERROR",
                    "M11_GPR_TX_SHORT_WRITE", "M11_GPR_TX_SENT"):
            self.assertIn(sym, gpr_h)
        self.assertIn("if (mgr->gpr->last_tx_status == M11_GPR_TX_NOT_ATTEMPTED)", shmem_c)

        # P1: the wait is bounded by an absolute deadline, not by an iteration count.
        self.assertIn("static int wait_slot_deadline(", gpr_c)
        body = gpr_c[gpr_c.index("static int wait_slot_deadline("):gpr_c.index("static int consume_slot_result(")]
        self.assertIn("deadline", body)
        self.assertIn("engine_now_ms", body)
        self.assertIn("M11_GPR_RX_TRANSPORT_ERR", body)
        self.assertNotRegex(body, r"for\s*\(\s*(int|unsigned|uint\d+_t|size_t)\s+\w+\s*=\s*0\s*;\s*\w+\s*<\s*64")
        self.assertNotIn("if (prc == -ETIMEDOUT || prc == -ENETRESET || prc == -EIO)", gpr_c)

        # P2: only ownership-bearing requests are retained, and a retained token is never reissued.
        self.assertIn("m11_gpr_opcode_retains_on_timeout", gpr_c)
        self.assertIn("M11_APM_CMD_SHARED_MEM_MAP_REGIONS", gpr_c)
        self.assertIn("M11_APM_CMD_SHARED_MEM_UNMAP_REGIONS", gpr_c)
        self.assertIn("token_in_use(", gpr_c)
        self.assertIn("m11_shmem_reconcile", shmem_h)

        # P4: the only place that can reach RELEASED sits behind the remote-inactive proof.
        self.assertEqual(len(re.findall(r"->state\s*=\s*M11_SHMEM_STATE_RELEASED\s*;", shmem_c)), 1)
        rel = shmem_c[shmem_c.index("static int release_local_handles("):shmem_c.index("int m11_shmem_alloc_and_map(")]
        self.assertIn("region->remote_inactive", rel)
        self.assertLess(rel.index("region->remote_inactive"), rel.index("dma_buf_sync_fn"))
        self.assertIn("M11_SHMEM_STATE_RELEASED", rel)
        self.assertIn("m11_shmem_mgr_audit", shmem_h)

        # Post-MAP hold (CP2 criterion 5, L3): the single release path refuses, first of all, a
        # region whose MAP may have been transmitted; only TX_NOT_ATTEMPTED sets the unsent proof,
        # and both flags are set exactly once (monotonic, nothing clears them).
        self.assertIn("#define M11_SHMEM_POST_MAP_HOLD 1", shmem_h)
        self.assertIn("if (region->map_tx_started && !region->map_tx_unsent_proof) return -EPERM;", rel)
        self.assertLess(rel.index("map_tx_started"), rel.index("region->remote_inactive"))
        self.assertEqual(len(re.findall(r"map_tx_started\s*=\s*true\s*;", shmem_c)), 1)
        self.assertEqual(len(re.findall(r"map_tx_unsent_proof\s*=\s*true\s*;", shmem_c)), 1)
        self.assertEqual(len(re.findall(r"map_tx_(started|unsent_proof)\s*=\s*false\s*;", shmem_c)), 0)
        amap = shmem_c[shmem_c.index("int m11_shmem_alloc_and_map("):shmem_c.index("int m11_shmem_unmap_and_free(")]
        self.assertLess(amap.index("map_tx_started = true;"), amap.index("m11_gpr_engine_submit_ex("))
        proof = amap.index("map_tx_unsent_proof = true;")
        self.assertLess(amap.index("if (mgr->gpr->last_tx_status == M11_GPR_TX_NOT_ATTEMPTED)"), proof)
        self.assertNotIn("release_local_handles", amap[amap.index("write_fn() was invoked"):])

        # P5: the CPU-access bracket this call opened is closed on every error path. The
        # END-before-GRAPH_OPEN order itself is a PROPOSED design (see m11_shmem.h), not stock.
        self.assertIn("m11_apm_transact_graph_open_region", apm_c)
        self.assertIn("opened_here", apm_c)
        self.assertIn("m11_shmem_end_cpu_access(shmem_mgr, region)", apm_c)
        self.assertIn("#define M11_DMA_BUF_IOCTL_SYNC      0x40086200u", shmem_h)
        self.assertIn("m11_apm_transact_graph_open_region(gpr, shmem, &shmem_reg, 0u,", sim_c)
        self.assertIn("m11_apm_transact_graph_open_region(gpr, shmem, &shmem_reg, 64u,", sim_c)

        # P3: per-channel report; the safety context is never reported as hardware evidence.
        self.assertIn("m11_aw_apply_and_verify_re_dsp_ex", aw_c)
        self.assertIn("rep->safety_ctx_is_hardware_evidence = false;", aw_c)
        self.assertIn("rep->rollback_attempted = false;", aw_c)
        self.assertIn("rep->amp_enabled = false;", aw_c)
        self.assertIn("m11_aw_apply_and_verify_re_dsp_ex(", sim_c)

        # P6: a bare IBASIC success does not complete a request whose answer carries data.
        self.assertIn("ack_without_data", gpr_c)

    def test_c_wire_layout_matches_independent_python_builders(self) -> None:
        """The packets the C packers emit must equal packets rebuilt here from the layout.

        The Python builders below are written from the documented field order (apm_api,
        libar-gsl/liblx-osal disassembly notes in the headers), not from the C code. This catches
        packing, endianness, size and alignment slips. It cannot catch a misreading of the
        shared specification, and it is not hardware evidence.
        """
        # The native oracle is executed by the Linux qualification jobs. MinGW on Windows is not
        # a supported build environment for these Linux runtime sources, so there it is opt-in.
        if os.name == "nt" and os.environ.get("M11_REQUIRE_NATIVE_ORACLE") != "1":
            self.skipTest("native C wire oracle is not supported on Windows; the Linux jobs run it "
                          "with M11_REQUIRE_NATIVE_ORACLE=1 (NOT a pass here)")
        cc = shutil.which(os.environ.get("CC", "gcc")) or shutil.which("clang")
        if cc is None:
            if os.environ.get("M11_REQUIRE_NATIVE_ORACLE") == "1":
                self.fail("no C compiler, but M11_REQUIRE_NATIVE_ORACLE=1")
            self.skipTest("no C compiler available (NOT a pass)")
        srcs = [REPAIR_DIR / n for n in ("m11_gpr_engine.c", "m11_shmem.c", "m11_apm_protocol.c",
                                         "m11_aw_protection.c", "dump_wire_vectors.c")]
        with tempfile.TemporaryDirectory() as tmp:
            exe = Path(tmp) / "dump_wire_vectors"
            build = subprocess.run([cc, "-std=c11", "-O1", "-Wall", "-Wextra", "-Werror", f"-I{REPAIR_DIR}",
                                    *map(str, srcs), "-o", str(exe)], capture_output=True, text=True)
            if build.returncode != 0:
                self.fail("native wire-layout oracle compilation failed:\n"
                          f"stdout:\n{build.stdout}\nstderr:\n{build.stderr}")
            run = subprocess.run([str(exe)], capture_output=True, text=True)
            if run.returncode != 0:
                self.fail(f"wire-vector dumper failed (rc={run.returncode}):\n{run.stderr}")
            out = run.stdout
        got = {}
        for line in out.splitlines():
            name, _, value = line.partition(" ")
            got[name] = value

        def env(ch: int, mohm: int, with_value: bool = True) -> bytes:
            q12 = ((mohm << 12) // 1000) & 0xFFFFFFFF if with_value else 0
            return struct.pack("<12I", 0x42D3, 0x10013D2A, 28, 0, 0, 0x10013D1B + ch, 1, 0, 0, 0, q12, 0)

        def cmd_hdr(payload_size: int, lsw: int = 0, msw: int = 0, handle: int = 0) -> bytes:
            return struct.pack("<IIII", lsw, msw, handle, payload_size)

        def sg_block(ids: tuple[int, ...]) -> bytes:
            raw = struct.pack("<IIII I", 1, 0x08001005, 4 + 4 * len(ids), 0, len(ids)) + struct.pack(
                f"<{len(ids)}I", *ids)
            total = (len(ids) * 4 + 0x1B) & ~7
            self.assertGreaterEqual(total, len(raw))
            return raw + b"\x00" * (total - len(raw))

        vi = (0xB00000D5, 0xB00000CE)
        rx = (0xB0000023, 0xB0000024, 0xB0000025, 0xB0000002)
        want = {
            "get_spf_state": pack_gpr_v0(dst_domain_id=2, src_domain_id=3, client_data=0, src_port=0x2001,
                                         dst_port=1, token=0x11223344, opcode=0x01001021),
            "map_regions": pack_gpr_v0(dst_domain_id=2, src_domain_id=3, client_data=1, src_port=0x2002,
                                       dst_port=1, token=1, opcode=0x0100100C,
                                       payload=struct.pack("<HHIIII", 3, 1, 0x4, 100, 0, 20480)),
            "unmap_regions": pack_gpr_v0(dst_domain_id=2, src_domain_id=3, client_data=0, src_port=0x2002,
                                         dst_port=1, token=2, opcode=0x0100100D,
                                         payload=struct.pack("<I", 0xA0001234)),
            "set_cfg_ch0_6372": pack_gpr_v0(dst_domain_id=2, src_domain_id=3, client_data=0, src_port=0x2001,
                                            dst_port=0x42D3, token=3, opcode=0x01001006,
                                            payload=cmd_hdr(48) + env(0, 6372)),
            "set_cfg_ch1_7001": pack_gpr_v0(dst_domain_id=2, src_domain_id=3, client_data=0, src_port=0x2001,
                                            dst_port=0x42D3, token=4, opcode=0x01001006,
                                            payload=cmd_hdr(48) + env(1, 7001)),
            "get_cfg_ch1": pack_gpr_v0(dst_domain_id=2, src_domain_id=3, client_data=0, src_port=0x2001,
                                       dst_port=0x42D3, token=5, opcode=0x01001007,
                                       payload=cmd_hdr(48) + env(1, 0, with_value=False)),
            "get_cfg_rsp_ch1_7001": pack_gpr_v0(dst_domain_id=3, src_domain_id=2, client_data=0,
                                                src_port=0x42D3, dst_port=0x2001, token=5,
                                                opcode=0x02001000,
                                                payload=struct.pack("<I", 0) + env(1, 7001)),
            "graph_prepare_vi": pack_gpr_v0(dst_domain_id=2, src_domain_id=3, client_data=0, src_port=0x2001,
                                            dst_port=1, token=5, opcode=0x01001001,
                                            payload=cmd_hdr(len(sg_block(vi))) + sg_block(vi)),
            "graph_start_rx": pack_gpr_v0(dst_domain_id=2, src_domain_id=3, client_data=0, src_port=0x2001,
                                          dst_port=1, token=6, opcode=0x01001002,
                                          payload=cmd_hdr(len(sg_block(rx))) + sg_block(rx)),
            "graph_open_cmd_hdr": cmd_hdr(len(sg_block(rx)), lsw=64, handle=0xA0001234),
            "graph_open_shm_block_at_64": sg_block(rx),
        }
        for name, expected in want.items():
            self.assertIn(name, got, f"vector {name} was not produced")
            self.assertEqual(got[name], expected.hex(), name)
        self.assertEqual(got["graph_open_shm_written"], str(len(sg_block(rx))))
        self.assertEqual(got["graph_open_outside_block_untouched"], "1")
        self.assertEqual(len(want["set_cfg_ch0_6372"]), 88)
        self.assertEqual(len(want["get_cfg_rsp_ch1_7001"]), 76)

    def test_native_compiler_failure_reports_stderr(self) -> None:
        # Execute the failure path on every host without invoking any compiler.
        failed = subprocess.CompletedProcess([], 1, "compiler stdout marker", "compiler stderr marker")
        with mock.patch.dict(os.environ, {"M11_REQUIRE_NATIVE_ORACLE": "1"}), \
             mock.patch.object(shutil, "which", return_value="synthetic-cc"), \
             mock.patch.object(subprocess, "run", return_value=failed) as run:
            with self.assertRaisesRegex(AssertionError, "compiler stderr marker"):
                self.test_c_wire_layout_matches_independent_python_builders()
            self.assertEqual(run.call_count, 1)

    def test_old_argon_vs_repaired_contrast(self) -> None:
        if ARGON_ROOT is None:
            self.skipTest("Argon checkout not supplied; contrast was NOT exercised")
        old_gpr_h = (
            ARGON_ROOT / "scripts" / "m11" / "argon-sprint" / "gpr-engine" / "m11_gpr_engine.h"
        ).read_text(encoding="utf-8")
        old_shmem_h = (
            ARGON_ROOT / "scripts" / "m11" / "argon-sprint" / "shmem" / "m11_shmem.h"
        ).read_text(encoding="utf-8")
        self.assertIn("#define M11_APM_MEMORY_MAP_SHMEM8_4K_POOL 4u", old_shmem_h)
        self.assertIn("uint32_t dst_port;\n    uint32_t src_port;\n    uint8_t  dst_domain_id;", old_gpr_h)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--argon-root", type=Path, default=None)
    args, remaining = parser.parse_known_args()
    if args.argon_root is not None:
        ARGON_ROOT = args.argon_root.resolve()
    elif Path("D:/idk.omg/m11-argon-sprint-wt").exists():
        ARGON_ROOT = Path("D:/idk.omg/m11-argon-sprint-wt").resolve()
    unittest.main(argv=[sys.argv[0], *remaining])
