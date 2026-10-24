"""Synthetic inputs only (no stock ACDB, XML or calibration in CI): speaker_plan payloads, order and refusals."""
import hashlib
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import graph_plan as gp  # noqa: E402
import speaker_plan as sp  # noqa: E402


def w(*v):
    return struct.pack('<' + str(len(v)) + 'I', *v)


def pad8(b):
    return b + b'\0' * (-len(b) % 8)


SG_STR, SG_DEV, SG_VIS, SG_VID = 0xB0000023, 0xB0000002, 0xB00000CE, 0xB00000D5
LL = {0xA1000000: 0xA100000E, 0xA2000000: 0xA2000001, 0xAB000000: 1, 0xAC000000: 0xAC000002}
VI = {0xA3000000: 0xA3000009, 0xB1000000: 0xB1000009}
WR, DEC, CNV, SPR, VOL = 0x40BD, 0x40BF, 0x40C0, 0x4165, 0x4008
HW, SPM, MUX = 0x428F, 0x42D3, 0x4006
RD, ENC, VCNV, HWT, VIM = 0x4547, 0x4545, 0x4544, 0x4308, 0x42D4
TDM_BASE_RX = struct.pack('<IIHHIHHHHHH', 0, 2, 1, 1, 7, 4, 32, 0, 0, 1, 0)
TDM_BASE_TX = struct.pack('<IIHHIHHHHHH', 0, 2, 1, 1, 3, 4, 32, 0, 0, 1, 0)

XML = """<?xml version="1.0" encoding="iso-8859-1"?>
<graph_key_value_pair_info>
 <streams>
  <stream type="PAL_STREAM_LOW_LATENCY">
   <keys_and_values Direction="TX" Instance="1"><graph_kv key="0xB1000000" value="0xB1000009"/></keys_and_values>
   <keys_and_values Direction="RX" Instance="1"><graph_kv key="0xA1000000" value="0xA100000E"/><graph_kv key="0xAB000000" value="0x1"/></keys_and_values>
  </stream>
  <stream type="PAL_STREAM_DEEP_BUFFER">
   <keys_and_values Direction="RX" Instance="1"><graph_kv key="0xA1000000" value="0xA1000001"/><graph_kv key="0xAB000000" value="0x1"/></keys_and_values>
  </stream>
 </streams>
 <devices>
  <device id="PAL_DEVICE_OUT_SPEAKER"><keys_and_values><graph_kv key="0xA2000000" value="0xA2000001"/></keys_and_values></device>
  <device id="PAL_DEVICE_IN_VI_FEEDBACK"><keys_and_values><graph_kv key="0xA3000000" value="0xA3000009"/></keys_and_values></device>
 </devices>
 <devicepps>
  <devicepp id="PAL_DEVICE_OUT_SPEAKER">
   <keys_and_values StreamType="PAL_STREAM_DEEP_BUFFER,PAL_STREAM_LOW_LATENCY"><graph_kv key="0xA2000000" value="0xA2000001"/><graph_kv key="0xAC000000" value="0xAC000002"/></keys_and_values>
  </devicepp>
 </devicepps>
</graph_key_value_pair_info>
"""


class Fixture:
    """A small ACDB in the canonical chunk layout, with the speaker and VI graphs."""

    def __init__(self, offloaded=(), extra_volume_row=False, dup_sp_tag=False, no_mux_row=False):
        self.pool = bytearray()
        self.offloaded = offloaded
        self.extra_volume_row = extra_volume_row
        self.dup_sp_tag = dup_sp_tag
        self.no_mux_row = no_mux_row

    def put(self, b):
        off = len(self.pool)
        self.pool.extend(b)
        return off

    def item(self, payload):
        return self.put(w(len(payload)) + payload)

    @staticmethod
    def spf(miid, pid, payload):
        return w(miid, pid, len(payload)) + pad8(payload)

    def sg_obj(self, sgid, marker):
        drv = w(sgid, 1, 0x08000001, 4, 0xFEEDFACE)
        spf = self.spf(1, gp.PID_SUB_GRAPH_CONFIG, w(1, sgid, 1, 0x0800100F, 4, 2)) + self.spf(1, 0x08001003, w(marker))
        body = w(len(drv)) + drv + w(len(spf)) + spf
        return w(sgid, len(body)) + body

    def build(self):
        put = self.put
        # graph tables: RX = stream -> device, VI = device -> stream
        rx_list = put(w(24, 2, SG_STR, 1, SG_DEV, SG_DEV, 0))
        rx_objs = self.sg_obj(SG_STR, 0x51) + self.sg_obj(SG_DEV, 0x52)
        rx_props = put(w(len(rx_objs) + 4, 2) + rx_objs)
        vi_list = put(w(24, 2, SG_VID, 1, SG_VIS, SG_VIS, 0))
        vi_objs = self.sg_obj(SG_VID, 0x61) + self.sg_obj(SG_VIS, 0x62)
        vi_props = put(w(len(vi_objs) + 4, 2) + vi_objs)
        conn = self.item(w(1, SPR, 1, MUX, 2))
        vconn = self.item(w(1, VIM, 1, VCNV, 2))

        def rows(kv, sg_list, props):
            return w(*[v for _, v in sorted(kv.items())], sg_list, props)

        gkvl = w(4, 1) + rows(LL, rx_list, rx_props)
        gkvl_vi = len(gkvl)
        gkvl += w(2, 1) + rows(VI, vi_list, vi_props)
        # calibration: stream keyless + volume table (levels 7, 8); device keyless + an unused-key table
        cdde, cddo = bytearray(), bytearray()

        def defdot(params):
            d, o = len(cdde), len(cddo)
            cdde.extend(w(len(params), *[x for m, p, _ in params for x in (m, p)]))
            cddo.extend(w(len(params), *[self.item(b) for _, _, b in params]))
            return d, o

        cakt, cdlu = bytearray(), bytearray()

        def table(keys, entries):
            k, l = len(cakt), len(cdlu)
            cakt.extend(w(len(keys), *keys))
            cdlu.extend(w(len(keys), len(entries)))
            for vals, params in entries:
                d, o = defdot(params)
                cdlu.extend(w(*vals, d, o, 0))
            return k, l

        str_keyless = table([], [([], [(VOL, 0x08001035, w(0x2000)), (DEC, 0x08001999, b'\x01\x02\x03')])])
        vol_rows = [([7], [(VOL, 0x08001038, w(1, 0x7E, 0, 7))]), ([8], [(VOL, 0x08001038, w(1, 0x7E, 0, 8))])]
        if self.extra_volume_row:
            vol_rows.append(([8], [(VOL, 0x08001038, w(9))]))
        str_vol = table([0xA4000000], vol_rows)
        dev_keyless = table([], [([], [(SPM, 0x10013D11, w(1)), (SPM, 0x10013D25, b'\xAA' * 20),
                                      (HW, 0x08001017, w(1))])])
        dev_mode = table([0x04800000], [([0], [(SPM, 0x10013D11, w(0))])])
        vi_keyless = table([], [([], [(VIM, 0x10013D13, w(5))])])
        cslu = w(3, SG_STR, 2, *str_keyless, *str_vol, SG_DEV, 2, *dev_keyless, *dev_mode, SG_VID, 1, *vi_keyless)
        # tagged modules
        tmde = bytearray()

        def tmod(*pairs):
            off = len(tmde)
            tmde.extend(w(len(pairs), *[x for p in pairs for x in p]))
            return off

        sp_pairs = [(0x10013D01, SPM)] + ([(0x10013D01, 0x42D9)] if self.dup_sp_tag else [])
        tm = [
            (SG_DEV, sp.TAG_DEVICE_HW_EP_RX, tmod((0x0700100E, HW))),
            (SG_DEV, sp.TAG_MODULE_SP, tmod(*sp_pairs)),
            (SG_DEV, sp.TAG_SLOT_MASK, tmod((0x07001098, MUX))),
            (SG_STR, sp.TAG_SH_EP, tmod((0x07001000, WR))),
            (SG_STR, sp.TAG_STREAM_INPUT_MEDIA_FORMAT, tmod((0x07001000, WR))),
            (SG_STR, sp.TAG_STREAM_VOLUME, tmod((0x0700101B, VOL))),
            (SG_STR, sp.TAG_STREAM_PCM_DECODER, tmod((0x07001005, DEC))),
            (SG_STR, sp.TAG_STREAM_PCM_CONVERTER, tmod((0x07001003, CNV))),
            (SG_STR, sp.TAG_STREAM_SPR, tmod((0x07001032, SPR))),
            (SG_VIS, sp.TAG_SH_EP, tmod((0x07001001, RD))),
            (SG_VIS, sp.TAG_STREAM_PCM_ENCODER, tmod((0x07001004, ENC))),
            (SG_VIS, sp.TAG_STREAM_PCM_CONVERTER, tmod((0x07001003, VCNV))),
            (SG_VID, sp.TAG_DEVICE_HW_EP_TX, tmod((0x0700100F, HWT))),
            (SG_VID, sp.TAG_MODULE_VI, tmod((0x10013D00, VIM))),
        ]
        tm.sort()
        tmlu = w(len(tm)) + b''.join(w(*e) for e in tm)
        # tag data
        mtde, mtdo, mtlu = bytearray(), bytearray(), bytearray()

        def tagdata(keys_n, rows_):
            off = len(mtlu)
            mtlu.extend(w(keys_n, len(rows_)))
            for vals, params in rows_:
                d, o = len(mtde), len(mtdo)
                mtde.extend(w(len(params), *[x for m, p, _ in params for x in (m, p)]))
                mtdo.extend(w(len(params), *[self.item(b) for _, _, b in params]))
                mtlu.extend(w(*vals, d, o))
            return off

        mux_rows = [] if self.no_mux_row else [([7], [(MUX, 0x080011BD, b'\x07' * 52), (MUX, 0x080011BE, b'\x08' * 24)])]
        mux_rows.insert(0, ([3], [(MUX, 0x080011BD, w(0)), (MUX, 0x080011BE, w(0))]))
        mt = [
            (SG_DEV, sp.TAG_DEVICE_HW_EP_RX, tagdata(1, [([2], [(HW, sp.PID_TDM_INTF_CFG, b'\x00' * 28)]),
                                                         ([3], [(HW, sp.PID_TDM_INTF_CFG, TDM_BASE_RX)])])),
            (SG_DEV, sp.TAG_SLOT_MASK, tagdata(1, mux_rows)),
            (SG_VID, sp.TAG_DEVICE_HW_EP_TX, tagdata(1, [([2], [(HWT, sp.PID_TDM_INTF_CFG, TDM_BASE_TX)])])),
        ]
        mt.sort()
        mtkt = w(len(mt)) + b''.join(w(*e) for e in mt)
        gpro = b''
        if self.offloaded:
            off = self.item(w(len(self.offloaded), *self.offloaded))
            gpro = w(1, sp.GPROP_OFFLOADED_PARAM_INFO, off)
        chunks = {
            'HEAD': w(1),
            'GKVT': w(2, 4, 1, *sorted(LL), 0, 2, 1, *sorted(VI), gkvl_vi),
            'GKVL': gkvl,
            'SGIT': w(4, SG_STR, 1, 16, 2, 1, 0x07001000, WR, SG_DEV, 1, 16, 2, 1, 0x0700100E, HW,
                      SG_VIS, 1, 16, 2, 1, 0x07001001, RD, SG_VID, 1, 16, 2, 1, 0x0700100F, HWT),
            'SCLU': w(2, SG_STR, SG_DEV, 0, 0, SG_VID, SG_VIS, 12, 8),
            'SCDE': w(1, 1, gp.PID_MODULE_CONN, 1, 1, gp.PID_MODULE_CONN), 'SCDO': w(1, conn, 1, vconn),
            'CSLU': cslu, 'CAKT': bytes(cakt), 'CDLU': bytes(cdlu), 'CDDE': bytes(cdde), 'CDDO': bytes(cddo),
            'PPTC': w(1, 0x080011D4),
            'TMLU': tmlu, 'TMDE': bytes(tmde),
            'MTKT': mtkt, 'MTLU': bytes(mtlu), 'MTDE': bytes(mtde), 'MTDO': bytes(mtdo),
            'POOL': bytes(self.pool),
        }
        if gpro:
            chunks['GPRO'] = gpro
        payload = b''.join(k.encode('ascii') + w(len(v)) + v for k, v in chunks.items())
        return w(0x42444341, 0, len(payload)) + payload


SIGNAL = dict(duration_ms=200, fade_ms=10, peak_mdbfs=-10000, tones_hz=[440, 880])
RE = (6372, 7003)


def sections(plan):
    magic, ver, total, n, hsize, sha = sp.HEADER.unpack_from(plan)
    p, out = hsize, []
    for _ in range(n):
        t, ln = struct.unpack_from('<2I', plan, p)
        out.append((t, plan[p + 8:p + 8 + ln]))
        p += 8 + ln + (-ln % 8)
    assert p == total == len(plan)
    return out


def graph(body):
    g, nsg = struct.unpack_from('<2I', body)
    sgs = list(struct.unpack_from('<%dI' % nsg, body, 8))
    q = 8 + 4 * nsg
    ol = struct.unpack_from('<I', body, q)[0]
    open_ = body[q + 4:q + 4 + ol]
    q += 4 + ol + (-ol % 8)
    cl = struct.unpack_from('<I', body, q)[0]
    cal = body[q + 4:q + 4 + cl]
    q += 4 + cl + (-cl % 8)
    n = struct.unpack_from('<I', body, q)[0]
    q += 4
    cfgs = []
    for _ in range(n):
        ln = struct.unpack_from('<I', body, q)[0]
        cfgs.append(body[q + 4:q + 4 + ln])
        q += 4 + ln + (-ln % 8)
    assert q == len(body)
    return g, sgs, open_, cal, cfgs


def headers(blob):
    out, p = [], 0
    while p < len(blob):
        m, pid, size, err = struct.unpack_from('<4I', blob, p)
        assert err == 0
        out.append((m, pid, size))
        p += 16 + size + (-size % 8)
    assert p == len(blob)
    return out


class Plan(unittest.TestCase):
    def build(self, fx=None, level=8, signal=SIGNAL):
        return sp.build((fx or Fixture()).build(), XML, RE, level, signal)

    def test_layout_and_order(self):
        plan, summary = self.build()
        self.assertEqual(plan[:8], sp.MAGIC)
        secs = sections(plan)
        self.assertEqual([t for t, _ in secs], [sp.SEC_GRAPH, sp.SEC_GRAPH, sp.SEC_IDS, sp.SEC_BACKEND,
                                                 sp.SEC_CONTROL, sp.SEC_RE, sp.SEC_SIGNAL, sp.SEC_PCM])
        self.assertEqual(summary['plan_sha256'], hashlib.sha256(plan).hexdigest())
        self.assertEqual(self.build()[0], plan)  # deterministic

    def test_graph_open_is_acdb_spf_data_then_connections(self):
        secs = sections(self.build()[0])
        g, sgs, open_, cal, cfgs = graph(secs[1][1])
        self.assertEqual((g, sgs), (sp.GRAPH_RX, [SG_STR, SG_DEV]))
        hs = headers(open_)
        # per subgraph in graph order: SUB_GRAPH_CONFIG then the marker property, then the connection
        self.assertEqual([h[:2] for h in hs], [(1, gp.PID_SUB_GRAPH_CONFIG), (1, 0x08001003),
                                               (1, gp.PID_SUB_GRAPH_CONFIG), (1, 0x08001003),
                                               (1, gp.PID_MODULE_CONN)])
        self.assertEqual(open_[16 + 24 + 16:16 + 24 + 16 + 4], w(0x51))
        g, sgs, open_, cal, cfgs = graph(secs[0][1])
        self.assertEqual((g, sgs), (sp.GRAPH_VI, [SG_VID, SG_VIS]))
        self.assertEqual(headers(open_)[-1][:2], (1, gp.PID_MODULE_CONN))

    def test_calibration_sorted_keyless_plus_selected_level(self):
        g, sgs, open_, cal, cfgs = graph(sections(self.build(level=8)[0])[1][1])
        hs = headers(cal)
        # SG_DEV (0xB0000002) before SG_STR (0xB0000023); the 0x04800000 table is not selected
        self.assertEqual([h[:2] for h in hs], [(SPM, 0x10013D11), (SPM, 0x10013D25), (HW, 0x08001017),
                                               (VOL, 0x08001035), (DEC, 0x08001999), (VOL, 0x08001038)])
        self.assertTrue(cal.endswith(w(1, 0x7E, 0, 8)))
        self.assertEqual(hs[4][2], 3)  # 3-byte payload padded to 8 in the blob
        g, sgs, open_, cal7, cfgs = graph(sections(self.build(level=7)[0])[1][1])
        self.assertTrue(cal7.endswith(w(1, 0x7E, 0, 7)))

    def test_prepare_configs_stock_layout(self):
        g, sgs, open_, cal, cfgs = graph(sections(self.build()[0])[1][1])
        self.assertEqual([headers(c)[0][:2] for c in cfgs],
                         [(DEC, sp.PID_PCM_OUTPUT_FORMAT_CFG), (CNV, sp.PID_PCM_OUTPUT_FORMAT_CFG),
                          (WR, sp.PID_MEDIA_FORMAT), (SPR, sp.PID_SPR_DELAY_PATH_END),
                          (HW, sp.PID_HW_EP_MF_CFG), (HW, sp.PID_TDM_INTF_CFG), (MUX, 0x080011BD)])
        # WR EP media format: stock libagm layout (48 kHz, 16 bit, LSB aligned, 2 ch, map 1 2)
        self.assertEqual(cfgs[2], w(WR, sp.PID_MEDIA_FORMAT, 30, 0, 1, sp.MEDIA_FMT_ID_PCM, 18)
                         + struct.pack('<IHBBHHHH', 48000, 16, 1, 0, 16, 15, 1, 2) + b'\x01\x02' + b'\0' * 2)
        self.assertEqual(cfgs[0], w(DEC, sp.PID_PCM_OUTPUT_FORMAT_CFG, 30, 0, 1, sp.MEDIA_FMT_ID_PCM, 18)
                         + struct.pack('<8h', 16, 1, 16, 15, 1, 0, 0, 2) + b'\x01\x02' + b'\0' * 2)
        self.assertEqual(cfgs[3], w(SPR, sp.PID_SPR_DELAY_PATH_END, 4, 0, HW, 0))
        self.assertEqual(cfgs[4], w(HW, sp.PID_HW_EP_MF_CFG, 12, 0) + struct.pack('<IHHI', 96000, 32, 3, 1) + b'\0' * 4)
        tdm = struct.unpack_from('<IIHHIHHHHHH', cfgs[5], 16)
        self.assertEqual((tdm[0], tdm[1], tdm[4], tdm[5], tdm[6]), (sp.LPAIF, sp.INTF_IDX_TERTIARY, 7, 4, 32))
        self.assertEqual(headers(cfgs[6]), [(MUX, 0x080011BD, 52), (MUX, 0x080011BE, 24)])
        g, sgs, open_, cal, vcfgs = graph(sections(self.build()[0])[0][1])
        self.assertEqual([headers(c)[0][:2] for c in vcfgs],
                         [(ENC, sp.PID_PCM_OUTPUT_FORMAT_CFG), (VCNV, sp.PID_PCM_OUTPUT_FORMAT_CFG),
                          (HWT, sp.PID_HW_EP_MF_CFG), (HWT, sp.PID_TDM_INTF_CFG)])
        self.assertEqual(struct.unpack_from('<I', vcfgs[3], 16 + 12)[0], 3)  # TX keeps the ACDB slot mask

    def test_ids_backend_controls_re_signal(self):
        secs = dict((t, b) for t, b in sections(self.build()[0]) if t != sp.SEC_GRAPH)
        self.assertEqual(struct.unpack('<14I', secs[sp.SEC_IDS]),
                         (WR, RD, SPM, VIM, HW, HWT, VOL, 48000, 2, 2, 48000, 2, 2, 8))
        be = secs[sp.SEC_BACKEND]
        self.assertEqual(struct.unpack_from('<6I', be, 0), (0, 96000, 3, 10, 682, 2))
        self.assertEqual(be[24:24 + 64].rstrip(b'\0'), b'TDM-LPAIF-RX-TERTIARY-VIRT-2')
        self.assertEqual(struct.unpack_from('<6I', be, 88), (1, 96000, 2, 10, 1024, 2))
        self.assertEqual(be[88 + 24:88 + 88].rstrip(b'\0'), b'TDM-LPAIF-TX-TERTIARY')
        self.assertEqual(len(secs[sp.SEC_CONTROL]), 128)
        self.assertEqual(struct.unpack('<ii', secs[sp.SEC_RE]), RE)
        pcm = secs[sp.SEC_PCM]
        self.assertEqual(len(pcm), 48000 * 200 // 1000 // 2 * 2 * 2 * 2)
        samples = struct.unpack('<%dh' % (len(pcm) // 2), pcm)
        peak = int(32767 * 10 ** (-10000 / 1000 / 20))
        self.assertLessEqual(max(abs(s) for s in samples), peak)
        self.assertGreater(max(abs(s) for s in samples), peak * 0.95)
        self.assertEqual(samples[0], 0)

    def test_refusals(self):
        with self.assertRaisesRegex(ValueError, 'matches 2 calibration rows'):
            self.build(Fixture(extra_volume_row=True))
        with self.assertRaisesRegex(ValueError, 'matches 0 calibration rows'):
            self.build(level=9)
        with self.assertRaisesRegex(ValueError, 'offloaded parameter'):
            self.build(Fixture(offloaded=(0x10013D25,)))
        with self.assertRaisesRegex(ValueError, 'module_sp: 2 tagged modules'):
            self.build(Fixture(dup_sp_tag=True))
        with self.assertRaisesRegex(ValueError, r'no row for \[7\]'):
            self.build(Fixture(no_mux_row=True))
        with self.assertRaisesRegex(ValueError, 'volume level'):
            self.build(level=16)

    def test_unused_ckv_key_refused(self):
        acdb = sp.Acdb(Fixture().build())
        with self.assertRaisesRegex(ValueError, 'select no calibration table'):
            acdb.calibration_blob([SG_DEV], {0xA4000000: 8}, set(), set())

    def test_parse_re(self):
        self.assertEqual(sp.parse_re(struct.pack('<ii', 6372, 7003)), (6372, 7003))
        for bad in (b'\0' * 7, struct.pack('<ii', 0, 7003), struct.pack('<ii', 6372, 524288)):
            with self.assertRaises(ValueError):
                sp.parse_re(bad)

    def test_tdm_base_size_checked(self):
        with self.assertRaisesRegex(ValueError, '28 B'):
            sp.tdm_cfg(HW, b'\0' * 24)


if __name__ == '__main__':
    unittest.main()
