"""Synthetic inputs only (no stock ACDB or XML in CI): graph_plan derivation and bounds."""
import json
import struct
import unittest

import graph_plan as gp


def w(*v):
    return struct.pack('<' + str(len(v)) + 'I', *v)


SG_DEV, SG_STR = 0xB0000002, 0xB0000023
MARK_SPF, MARK_CAL, MARK_DRV = 0xDEADBEEF, 0xCAFEF00D, 0xFEEDFACE
LL = {0xA1000000: 0xA100000E, 0xA2000000: 0xA2000001, 0xAB000000: 1, 0xAC000000: 0xAC000002}
DB = {0xA1000000: 0xA1000001, 0xA2000000: 0xA2000001, 0xAB000000: 1, 0xAC000000: 0xAC000002}
VI = {0xA3000000: 0xA3000009, 0xB1000000: 0xB1000009}

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
  <device id="PAL_DEVICE_IN_HANDSET_MIC"><keys_and_values><graph_kv key="0xA3000000" value="0xA3000001"/></keys_and_values><keys_and_values><graph_kv key="0xA3000000" value="0xA3000002"/></keys_and_values></device>
 </devices>
 <devicepps>
  <devicepp id="PAL_DEVICE_OUT_SPEAKER">
   <keys_and_values StreamType="PAL_STREAM_DEEP_BUFFER,PAL_STREAM_LOW_LATENCY"><graph_kv key="0xA2000000" value="0xA2000001"/><graph_kv key="0xAC000000" value="0xAC000002"/></keys_and_values>
   <keys_and_values StreamType="PAL_STREAM_LOW_LATENCY" CustomConfig="speaker-safe"><graph_kv key="0xA2000000" value="0xA2000001"/><graph_kv key="0xAC000000" value="0xAC000009"/></keys_and_values>
  </devicepp>
 </devicepps>
</graph_key_value_pair_info>
"""


def pad8(b):
    return b + b'\0' * (-len(b) % 8)


def spf_prop(miid, pid, payload):
    return w(miid, pid, len(payload)) + pad8(payload)


def sg_object(sgid):
    drv = w(sgid, 1, 0x08000001, 4, MARK_DRV)
    spf = (spf_prop(1, gp.PID_MODULES_LIST, w(1, sgid, 0xE0000002, 1, 0x0700100E, sgid & 0xFFFF))
           + spf_prop(1, gp.PID_SUB_GRAPH_CONFIG, w(1, sgid, 1, 0x0800100F, 4, 2))
           + spf_prop(1, gp.PID_MODULE_PROP, w(MARK_SPF)))
    body = w(len(drv)) + drv + w(len(spf)) + spf
    return w(sgid, len(body)) + body


def fixture():
    pool = bytearray()

    def put(b):
        off = len(pool)
        pool.extend(b)
        return off

    sg_list = put(w(24, 2, SG_STR, 1, SG_DEV, SG_DEV, 0))
    objs = sg_object(SG_DEV) + sg_object(SG_STR)
    props = put(w(len(objs) + 4, 2) + objs)
    cal = put(w(4, MARK_CAL))
    conn = put(w(20, 1, 0x4165, 1, 0x40C8, 2))

    def rows(kvs):
        return b''.join(w(*[v for _, v in sorted(kv.items())], sg_list, props) for kv in kvs)

    gkvl = w(4, 2) + rows([LL, DB])
    gkvl_vi = len(gkvl)
    gkvl += w(2, 1) + rows([VI])
    return {
        'HEAD': w(1),
        'GKVT': w(2, 4, 1, *sorted(LL), 0, 2, 1, *sorted(VI), gkvl_vi),
        'GKVL': gkvl,
        'SGIT': w(2, SG_DEV, 1, 16, 2, 1, 0x10013D01, 0x42D3, SG_STR, 1, 16, 2, 1, 0x0700101B, 0x4008),
        'POOL': bytes(pool),
        'SCLU': w(1, SG_STR, SG_DEV, 0, 0), 'SCDE': w(1, 1, gp.PID_MODULE_CONN), 'SCDO': w(1, conn),
        'CSLU': w(2, SG_DEV, 0, SG_STR, 1, 0, 0),
        'CAKT': w(1, 0xA4000000), 'CDLU': w(1, 1, 5, 0, 0, 0),
        'CDDE': w(1, 0x4008, 0x08001035), 'CDDO': w(1, cal),
        'PPTC': w(1, 0x080011D4),
    }


def acdb(chunks):
    payload = b''.join(k.encode('ascii') + w(len(v)) + v for k, v in chunks.items())
    return w(0x42444341, 0, len(payload)) + payload


class Plan(unittest.TestCase):
    def test_gkv_union_and_default_devicepp(self):
        plans = gp.derive_gkvs(XML)
        self.assertEqual([p['gkv'] for p in plans], [LL, DB, VI])
        self.assertTrue(plans[2]['provenance'].startswith('INFERRED'))

    def test_full_plan_metadata_only(self):
        report = gp.build_plan(acdb(fixture()), XML)
        self.assertFalse(report['permits_graph_open'])
        ll = report['plans'][0]
        self.assertEqual(ll['subgraph_order_in_acdb'], ['0xB0000023', '0xB0000002'])
        s = ll['subgraphs'][0]
        self.assertEqual(s['destinations'], ['0xB0000002'])
        mods = s['properties']['spf'][0]['module_lists'][0]['modules']
        self.assertEqual(mods, [{'module_id': '0x0700100E', 'instance_id': '0x00000023'}])
        self.assertEqual(s['properties']['spf'][1]['sub_graphs'][0]['properties'],
                         {'0x0800100F': '0x00000002'})
        self.assertEqual(s['properties']['spf'][2]['bytes'], 4)
        cal = s['calibration'][0]
        self.assertEqual((cal['keys'], cal['entries'][0]['values']), (['0xA4000000'], ['0x00000005']))
        self.assertEqual(cal['entries'][0]['params'][0]['bytes'], 4)
        self.assertEqual(ll['subgraphs'][1]['calibration'], [])
        c = ll['subgraph_connections'][0]['params'][0]['connections'][0]
        self.assertEqual((c['src'], c['dst']), ('0x00004165', '0x000040C8'))
        self.assertEqual(report['persistent_param_ids'], ['0x080011D4'])
        text = json.dumps(report).upper()
        for marker in (MARK_SPF, MARK_CAL, MARK_DRV):
            self.assertNotIn(f'{marker:08X}', text)

    def test_every_truncation_rejected(self):
        b = acdb(fixture())
        for i in range(len(b)):
            with self.subTest(i=i), self.assertRaises((ValueError, KeyError, struct.error)):
                gp.build_plan(b[:i], XML)

    def test_inner_corruption_rejected(self):
        cases = {
            'cakt_cdlu_keys': lambda f: {**f, 'CDLU': w(2, 1, 5, 6, 0, 0, 0)},
            'scde_scdo_count': lambda f: {**f, 'SCDO': w(2, 0, 0)},
            'pool_item_overrun': lambda f: {**f, 'CDDO': w(1, len(f['POOL']) - 4)},
            'cal_def_overrun': lambda f: {**f, 'CDDE': w(9, 0x4008, 0x08001035)},
            'driver_sgid': lambda f: {**f, 'POOL': f['POOL'].replace(
                w(SG_DEV, 1, 0x08000001), w(SG_STR, 1, 0x08000001), 1)},
            'spf_misaligned': lambda f: {**f, 'POOL': f['POOL'].replace(
                w(1, gp.PID_MODULE_PROP, 4), w(1, gp.PID_MODULE_PROP, 12), 1)},
        }
        for name, mutate in cases.items():
            with self.subTest(name=name), self.assertRaises((ValueError, KeyError, struct.error)):
                gp.build_plan(acdb(mutate(fixture())), XML)

    def test_gkv_must_match_exactly_one_graph(self):
        f = fixture()
        f['GKVT'] = w(1, 4, 1, *sorted(LL), 0)
        with self.assertRaises(ValueError):
            gp.build_plan(acdb(f), XML)

    def test_xml_conflict_and_missing_devicepp(self):
        bad = XML.replace('<graph_kv key="0xA2000000" value="0xA2000001"/><graph_kv key="0xAC000000" value="0xAC000002"/>',
                          '<graph_kv key="0xA2000000" value="0xA2000004"/><graph_kv key="0xAC000000" value="0xAC000002"/>')
        with self.assertRaises(ValueError):
            gp.derive_gkvs(bad)
        none = XML.replace('StreamType="PAL_STREAM_DEEP_BUFFER,PAL_STREAM_LOW_LATENCY"',
                           'StreamType="PAL_STREAM_DEEP_BUFFER"')
        with self.assertRaises(ValueError):
            gp.derive_gkvs(none)


if __name__ == '__main__':
    unittest.main()
