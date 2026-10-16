"""Offline AudioReach speaker graph plan: GKV derivation, graph/subgraph/CKV metadata.

Never initializes ACDB, GSL, AGM or a device and never emits a payload byte. Inputs are
identity-bound local stock files (usecaseKvManager.xml, ACDB). The report holds only key
IDs/values, subgraph/container/module/instance IDs, parameter IDs and sizes, counts and
relationships, and always says permits_graph_open=false.

Format corroboration (not the stock implementation): AudioReach graphservices 3094583,
acdb_command.c BuildSubgraphDataRsp/BuildSpfPropertyBlob/BuildDriverPropertyBlob,
AcdbGetSubgraphConnectionData, AcdbCmdGetSubgraphCalDataNonPersist,
GetAllAudioCKVVariations; spf/api/apm/*.h for the APM parameter layouts.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'runtime'))
import inspect_acdb  # noqa: E402  canonical bounded GKVT/GKVL/SGIT/POOL parser

PID_CONTAINER_CONFIG = 0x08001000
PID_SUB_GRAPH_CONFIG = 0x08001001
PID_MODULES_LIST = 0x08001002
PID_MODULE_PROP = 0x08001003
PID_MODULE_CONN = 0x08001004
PID_MODULE_CTRL_LINK_CFG = 0x08001061
APM_PARAM_NAMES = {
    PID_CONTAINER_CONFIG: 'APM_PARAM_ID_CONTAINER_CONFIG',
    PID_SUB_GRAPH_CONFIG: 'APM_PARAM_ID_SUB_GRAPH_CONFIG',
    PID_MODULES_LIST: 'APM_PARAM_ID_MODULES_LIST',
    PID_MODULE_PROP: 'APM_PARAM_ID_MODULE_PROP',
    PID_MODULE_CONN: 'APM_PARAM_ID_MODULE_CONN',
    PID_MODULE_CTRL_LINK_CFG: 'APM_PARAM_ID_MODULE_CTRL_LINK_CFG',
}
# One budget for every count read from the file; the Forte file is far below it.
MAX_ITEMS = 1 << 16

# The speaker playback use cases this plan resolves (stock PAL names).
STREAMS = ('PAL_STREAM_LOW_LATENCY', 'PAL_STREAM_DEEP_BUFFER')
SPEAKER = 'PAL_DEVICE_OUT_SPEAKER'
VI_DEVICE = 'PAL_DEVICE_IN_VI_FEEDBACK'


def h(v):
    return f'0x{v:08X}'


def words(buf, off, n, end):
    if n < 0 or n > MAX_ITEMS or off < 0 or off + 4 * n > end:
        raise ValueError('truncated or excessive word read')
    return struct.unpack_from('<' + str(n) + 'I', buf, off)


# ---------------------------------------------------------------- usecaseKvManager.xml

def _kv(elem):
    out = {}
    for kv in elem.findall('graph_kv'):
        k, v = int(kv.get('key'), 0), int(kv.get('value'), 0)
        if k in out:
            raise ValueError(f'duplicate key {h(k)} in one keys_and_values')
        out[k] = v
    return out


def parse_usecase_kv(text):
    root = ET.fromstring(text)
    streams, devices, devicepps = {}, {}, {}
    for s in root.find('streams').findall('stream'):
        for kv in s.findall('keys_and_values'):
            streams[(s.get('type'), kv.get('Direction'), kv.get('Instance'))] = _kv(kv)
    for d in root.find('devices').findall('device'):
        for name in d.get('id').split(','):
            devices[name] = [_kv(kv) for kv in d.findall('keys_and_values')]
    for d in root.find('devicepps').findall('devicepp'):
        for name in d.get('id').split(','):
            for kv in d.findall('keys_and_values'):
                devicepps.setdefault(name, []).append(dict(
                    stream_types=kv.get('StreamType', '').split(','),
                    custom_config=kv.get('CustomConfig'), sub_type=kv.get('SubType'),
                    kv=_kv(kv)))
    return streams, devices, devicepps


def merge(*parts):
    out = {}
    for label, kv in parts:
        for k, v in kv.items():
            if out.get(k, v) != v:
                raise ValueError(f'{label}: key {h(k)} conflicts ({h(out[k])} vs {h(v)})')
            out[k] = v
    return out


def derive_gkvs(text):
    """Union of stream, device and default devicepp key sets, as AGM merges metadata."""
    streams, all_devices, devicepps = parse_usecase_kv(text)
    devices = {}
    for name in (SPEAKER, VI_DEVICE):
        if len(all_devices[name]) != 1:
            raise ValueError(f'device {name} has {len(all_devices[name])} key sets')
        devices[name] = all_devices[name][0]
    plans = []
    for stream in STREAMS:
        skv = streams[(stream, 'RX', '1')]
        pp = [e for e in devicepps[SPEAKER] if stream in e['stream_types']
              and e['custom_config'] is None and e['sub_type'] is None]
        if len(pp) != 1:
            raise ValueError(f'{stream}: expected one default speaker devicepp, got {len(pp)}')
        gkv = merge(('stream', skv), ('device', devices[SPEAKER]), ('devicepp', pp[0]['kv']))
        plans.append(dict(usecase=f'{stream} RX instance 1 -> {SPEAKER}',
                          stream_kv=skv, device_kv=devices[SPEAKER], devicepp_kv=pp[0]['kv'],
                          gkv=gkv, provenance='PROVEN (stock XML)'))
    vi_stream = streams[('PAL_STREAM_LOW_LATENCY', 'TX', '1')]
    plans.append(dict(usecase=f'PAL_STREAM_LOW_LATENCY TX instance 1 -> {VI_DEVICE}',
                      stream_kv=vi_stream, device_kv=devices[VI_DEVICE], devicepp_kv={},
                      gkv=merge(('stream', vi_stream), ('device', devices[VI_DEVICE])),
                      provenance='INFERRED (stream type of the VI session not proven here)'))
    return plans


# ---------------------------------------------------------------- ACDB metadata

class Acdb:
    def __init__(self, data):
        self.data = data
        self.report = inspect_acdb.inspect(data)  # validates the core structure first
        self.chunks = {k: (v['offset'], v['bytes']) for k, v in self.report['chunks'].items()}

    def span(self, name):
        start, n = self.chunks[name]
        return start, start + n

    def at(self, name, off, n):
        start, end = self.span(name)
        return words(self.data, start + off, n, end)

    def pool_size(self, off):
        start, end = self.span('POOL')
        size = words(self.data, start + off, 1, end)[0]
        if start + off + 4 + size > end:
            raise ValueError('POOL item overruns chunk')
        return size

    def graph(self, gkv):
        want = {(k, v) for k, v in gkv.items()}
        hits = [g for g in self.report['graphs']
                if {(e['key'], e['value']) for e in g['keys']} == want]
        if len(hits) != 1:
            raise ValueError(f'GKV matches {len(hits)} ACDB graphs')
        return hits[0]

    # Subgraph property data: <total, num_sg> then per SG <sgid, size><drv_size><drv><spf_size><spf>.
    def subgraph_properties(self, offset):
        start, end = self.span('POOL')
        p = start + offset
        total, nsg = words(self.data, p, 2, end)
        stop = p + 4 + total
        if stop > end:
            raise ValueError('subgraph property data overruns POOL')
        p += 8
        out = {}
        for _ in range(nsg):
            sgid, size = words(self.data, p, 2, stop)
            body, body_end = p + 8, p + 8 + size
            if body_end > stop or sgid in out:
                raise ValueError('bad subgraph property object')
            drv_size = words(self.data, body, 1, body_end)[0]
            drv = self._driver_props(body + 4, body + 4 + drv_size, sgid)
            q = body + 4 + drv_size
            spf_size = words(self.data, q, 1, body_end)[0]
            if q + 4 + spf_size != body_end:
                raise ValueError(f'{h(sgid)}: driver/SPF sizes do not fill the object')
            out[sgid] = dict(driver_properties=drv, spf=self._spf_props(q + 4, body_end))
            p = body_end
        if p != stop:
            raise ValueError('trailing bytes in subgraph property data')
        return out

    def _driver_props(self, p, end, sgid):
        if end > len(self.data):
            raise ValueError('driver property overrun')
        got, n = words(self.data, p, 2, end)
        if got != sgid:
            raise ValueError('driver property subgraph mismatch')
        p += 8
        props = []
        for _ in range(n):
            pid, size = words(self.data, p, 2, end)
            p += 8 + size
            if p > end:
                raise ValueError('driver property payload overrun')
            props.append(dict(property_id=h(pid), bytes=size))
        if p != end:
            raise ValueError('trailing driver property bytes')
        return props

    def _spf_props(self, p, end):
        props = []
        while p < end:
            miid, pid, size = words(self.data, p, 3, end)
            body = p + 12
            padded = size + (-size % 8)
            if body + padded > end:
                raise ValueError('SPF property overrun')
            entry = dict(module_instance_id=h(miid), param_id=h(pid),
                         name=APM_PARAM_NAMES.get(pid, 'UNKNOWN'), bytes=size)
            entry.update(self._decode_apm(pid, body, body + size))
            props.append(entry)
            p = body + padded
        if p != end:
            raise ValueError('SPF property misaligned')
        return props

    def _decode_apm(self, pid, p, end):
        """Structural IDs only for the four topology parameters; every other payload: size."""
        d = self.data
        if pid == PID_SUB_GRAPH_CONFIG:
            n = words(d, p, 1, end)[0]
            p += 4
            sgs = []
            for _ in range(n):
                sgid, nprop = words(d, p, 2, end)
                p += 8
                props = {}
                for _ in range(nprop):
                    prop, size = words(d, p, 2, end)
                    val = words(d, p + 8, 1, end)[0] if size == 4 else None
                    props[h(prop)] = val if val is None else h(val)
                    p += 8 + size
                sgs.append(dict(sub_graph_id=h(sgid), properties=props))
            return dict(sub_graphs=sgs, consumed=p == end)
        if pid == PID_CONTAINER_CONFIG:
            n = words(d, p, 1, end)[0]
            p += 4
            conts = []
            for _ in range(n):
                cid, nprop = words(d, p, 2, end)
                p += 8
                props = {}
                for _ in range(nprop):
                    prop, size = words(d, p, 2, end)
                    vals = words(d, p + 8, size // 4, end) if size % 4 == 0 else ()
                    props[h(prop)] = [h(v) for v in vals]
                    p += 8 + size
                conts.append(dict(container_id=h(cid), properties=props))
            return dict(containers=conts, consumed=p == end)
        if pid == PID_MODULES_LIST:
            n = words(d, p, 1, end)[0]
            p += 4
            lists = []
            for _ in range(n):
                sgid, cid, nmod = words(d, p, 3, end)
                pairs = words(d, p + 12, 2 * nmod, end)
                p += 12 + 8 * nmod
                lists.append(dict(sub_graph_id=h(sgid), container_id=h(cid), modules=[
                    dict(module_id=h(pairs[i]), instance_id=h(pairs[i + 1]))
                    for i in range(0, len(pairs), 2)]))
            return dict(module_lists=lists, consumed=p == end)
        if pid == PID_MODULE_CONN:
            n = words(d, p, 1, end)[0]
            c = words(d, p + 4, 4 * n, end)
            return dict(connections=[dict(src=h(c[i]), src_port=h(c[i + 1]),
                                          dst=h(c[i + 2]), dst_port=h(c[i + 3]))
                                     for i in range(0, len(c), 4)],
                        consumed=p + 4 + 16 * n == end)
        return {}

    # Subgraph connections: SCLU <count> then <src, dst, def_off, dot_off>.
    def connection(self, src, dst):
        count = self.at('SCLU', 0, 1)[0]
        rows = self.at('SCLU', 4, 4 * count)
        for i in range(0, len(rows), 4):
            if rows[i] == src and rows[i + 1] == dst:
                return self._def_dot('SCDE', 'SCDO', rows[i + 2], rows[i + 3], decode=True)
        return None

    def _def_dot(self, def_chunk, dot_chunk, def_off, dot_off, decode=False):
        n = self.at(def_chunk, def_off, 1)[0]
        if self.at(dot_chunk, dot_off, 1)[0] != n:
            raise ValueError(f'{def_chunk}/{dot_chunk} entry counts differ')
        pairs = self.at(def_chunk, def_off + 4, 2 * n)
        offs = self.at(dot_chunk, dot_off + 4, n)
        params = []
        start, end = self.span('POOL')
        for i in range(n):
            miid, pid = pairs[2 * i], pairs[2 * i + 1]
            size = self.pool_size(offs[i])
            e = dict(module_instance_id=h(miid), param_id=h(pid),
                     name=APM_PARAM_NAMES.get(pid, 'UNKNOWN'), bytes=size)
            if decode:
                e.update(self._decode_apm(pid, start + offs[i] + 4, start + offs[i] + 4 + size))
            params.append(e)
        return params

    def persistent_pids(self):
        if 'PPTC' not in self.chunks:
            return set()
        start, end = self.span('PPTC')
        n = words(self.data, start, 1, end)[0]
        return set(words(self.data, start + 4, n, end))

    # Calibration: CSLU <num_sg> then <sgid, n_ckv> + n_ckv * <CAKT off, CDLU off>.
    def calibration(self, sgid, persistent):
        start, end = self.span('CSLU')
        p = start
        count = words(self.data, p, 1, end)[0]
        p += 4
        for _ in range(count):
            sg, n = words(self.data, p, 2, end)
            offs = words(self.data, p + 8, 2 * n, end)
            p += 8 + 8 * n
            if sg != sgid:
                continue
            tables = []
            for i in range(n):
                tables.append(self._ckv_table(offs[2 * i], offs[2 * i + 1], persistent))
            return tables
        return None

    def _ckv_table(self, key_off, lut_off, persistent):
        nkeys = self.at('CAKT', key_off, 1)[0]
        keys = self.at('CAKT', key_off + 4, nkeys)
        lk, nentries = self.at('CDLU', lut_off, 2)
        if lk != nkeys:
            raise ValueError('CAKT/CDLU key count mismatch')
        width = nkeys + 3  # values + <def, dot, dot2>
        rows = self.at('CDLU', lut_off + 8, width * nentries)
        entries = []
        for i in range(nentries):
            row = rows[i * width:(i + 1) * width]
            params = self._def_dot('CDDE', 'CDDO', row[nkeys], row[nkeys + 1])
            for prm in params:
                prm['persistent'] = int(prm['param_id'], 16) in persistent
            entries.append(dict(values=[h(v) for v in row[:nkeys]], params=params,
                                total_bytes=sum(p['bytes'] for p in params)))
        return dict(keys=[h(k) for k in keys], entries=entries)


# ---------------------------------------------------------------- plan

def build_plan(acdb_bytes, usecase_text):
    acdb = Acdb(acdb_bytes)
    persistent = acdb.persistent_pids()
    plans = []
    for p in derive_gkvs(usecase_text):
        g = acdb.graph(p['gkv'])
        sgs = [e['subgraph_id'] for e in g['subgraphs']]
        props = acdb.subgraph_properties(g['property_offset'])
        if set(props) != set(sgs):
            raise ValueError('property data subgraphs differ from the graph subgraph list')
        edges = [(e['subgraph_id'], d) for e in g['subgraphs'] for d in e['destinations']]
        subgraphs = []
        for sgid in sgs:
            domains = acdb.report['subgraphs'][sgid]
            subgraphs.append(dict(
                subgraph_id=h(sgid),
                destinations=[h(d) for s, d in edges if s == sgid],
                sgit=[dict(domain=x['domain'], modules=[
                    dict(module_id=h(m['module_id']), instance_id=h(m['instance_id']))
                    for m in x['modules']]) for x in domains],
                properties=props[sgid],
                calibration=acdb.calibration(sgid, persistent)))
        # Each parameter goes out as apm_module_param_data_t (16 B incl. error code), 8-B padded.
        open_payload = sum(16 + x['bytes'] + (-x['bytes'] % 8)
                           for s in subgraphs for x in s['properties']['spf'])
        conns = []
        for s, d in edges:
            params = acdb.connection(s, d)
            conns.append(dict(src=h(s), dst=h(d), params=params))
            if params:
                open_payload += sum(16 + x['bytes'] + (-x['bytes'] % 8) for x in params)
        plans.append(dict(
            usecase=p['usecase'], provenance=p['provenance'],
            stream_kv={h(k): h(v) for k, v in p['stream_kv'].items()},
            device_kv={h(k): h(v) for k, v in p['device_kv'].items()},
            devicepp_kv={h(k): h(v) for k, v in p['devicepp_kv'].items()},
            gkv={h(k): h(v) for k, v in sorted(p['gkv'].items())},
            subgraph_order_in_acdb=[h(s) for s in sgs],
            subgraphs=subgraphs, subgraph_connections=conns,
            graph_open_param_bytes_estimate=open_payload))
    return dict(schema=1, scope='offline metadata only; no payload bytes',
                permits_graph_open=False, acdb_sha256=hashlib.sha256(acdb_bytes).hexdigest(),
                persistent_param_ids=sorted(h(x) for x in persistent), plans=plans)


def main():
    a = argparse.ArgumentParser(description=__doc__)
    a.add_argument('--acdb', type=Path, required=True)
    a.add_argument('--acdb-sha256', required=True)
    a.add_argument('--usecase-kv', type=Path, required=True)
    a.add_argument('--usecase-kv-sha256', required=True)
    a.add_argument('--output', type=Path, required=True)
    args = a.parse_args()
    acdb = args.acdb.read_bytes()
    ukv = args.usecase_kv.read_bytes()
    for name, data, want in (('ACDB', acdb, args.acdb_sha256),
                             ('usecaseKvManager.xml', ukv, args.usecase_kv_sha256)):
        if hashlib.sha256(data).hexdigest() != want.lower():
            raise SystemExit(f'{name} identity mismatch')
    report = build_plan(acdb, ukv.decode('iso-8859-1'))
    args.output.write_text(json.dumps(report, indent=1) + '\n', encoding='utf-8')
    for p in report['plans']:
        print(f"{p['usecase']}: {len(p['subgraphs'])} subgraphs, "
              f"~{p['graph_open_param_bytes_estimate']} B GRAPH_OPEN params; graph open forbidden")


if __name__ == '__main__':
    main()
