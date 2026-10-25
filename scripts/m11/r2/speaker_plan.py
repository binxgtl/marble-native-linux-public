#!/usr/bin/env python3
"""Local-only speaker session plan generator (W2, docs/m11-argon-speaker-run-design.md).

Reads the canonical ACDB and usecaseKvManager.xml (both SHA256-bound) and emits plan.bin: every payload the
native speaker session sends, in stock order and stock byte layout:
  - GRAPH_OPEN (out of band): the ACDB subgraph data of the graph's subgraphs, then their connections
    (public ACDB AcdbCmdGetSubgraphData / AcdbCmdGetSubgraphConnections: 16-B header with error code 0,
    payload padded to 8 B);
  - non-persistent calibration (out of band): AcdbCmdGetSubgraphCalDataNonPersist on a first open
    (subgraphs in ascending ID order; per subgraph the keyless table and the tables whose keys the CKV holds);
  - the prepare-time SET_CFGs AGM and PAL build (media formats, HW EP media format, TDM interface from the
    tag data, MUX_DEMUX slot mask, SPR delay path end, RD EP config), one SET_CFG each;
plus the module instance IDs, the back-end and amplifier control plan, the Re pair and the signal.

The output carries ACDB-derived bytes. It stays local (artifacts/, ignored) and is staged into the initramfs as
data; it never enters Git or CI. CI runs test_speaker_plan.py on a synthetic ACDB only.
"""
import argparse
import hashlib
import io
import json
import math
import struct
from pathlib import Path
import sys
import wave

sys.path.insert(0, str(Path(__file__).resolve().parent))
import graph_plan as gp  # noqa: E402  ACDB metadata walker (r2)

MAGIC = b'M11SPK01'
VERSION = 1
HEADER = struct.Struct('<8sIIII32s8x')          # magic, version, total, sections, header size, ACDB sha256
assert HEADER.size == 64

SEC_GRAPH, SEC_IDS, SEC_BACKEND, SEC_CONTROL, SEC_RE, SEC_SIGNAL, SEC_PCM = 1, 2, 3, 4, 5, 6, 7
GRAPH_VI, GRAPH_RX = 1, 2

# SPF parameter IDs (public graph services spf/api, pin 3094583)
PID_MEDIA_FORMAT = 0x0800100C
PID_PCM_OUTPUT_FORMAT_CFG = 0x08001008
PID_HW_EP_MF_CFG = 0x08001017
PID_TDM_INTF_CFG = 0x0800101B
PID_SPR_DELAY_PATH_END = 0x080010C4
MEDIA_FMT_ID_PCM = 0x09001000
DATA_FORMAT_FIXED_POINT = 1
PCM_INTERLEAVED = 1
PCM_DEINTERLEAVED_UNPACKED = 3

# Module tags (stock kvh2xml.xml) and tag keys
TAG_SH_EP = 0xC0000001
TAG_STREAM_INPUT_MEDIA_FORMAT = 0xC0000002
TAG_DEVICE_HW_EP_RX = 0xC0000004
TAG_DEVICE_HW_EP_TX = 0xC0000005
TAG_STREAM_VOLUME = 0xC000000D
TAG_STREAM_PCM_DECODER = 0xC000000E
TAG_STREAM_PCM_ENCODER = 0xC000000F
TAG_STREAM_PCM_CONVERTER = 0xC0000010
TAG_STREAM_SPR = 0xC0000013
TAG_MODULE_VI = 0xC0000028
TAG_MODULE_SP = 0xC0000029
TAG_SLOT_MASK = 0xC0000040            # PAL Session::setSlotMask, key KEY_SLOT_MASK
KEY_CHANNELS = 0xA9000000
KEY_VOLUME = 0xA4000000
KEY_SLOT_MASK = 0xE0000000

# Back-end interface (AGM device_hw_ep.c for "TDM-LPAIF-<dir>-TERTIARY")
LPAIF = 0
INTF_IDX_TERTIARY = 2
SNDRV_PCM_FORMAT_S16_LE, SNDRV_PCM_FORMAT_S32_LE = 2, 10
AGM_MAX_PERIOD_BUFFER, AGM_PERIOD_COUNT = 8192, 2       # AGM device.c

GPROP_OFFLOADED_PARAM_INFO = 0x000133B7    # ACDB_GPROP_OFFLOADED_PARAM_INFO (public acdb_parser.h)


def u32(*v):
    return struct.pack('<%dI' % len(v), *v)


def pad8(b):
    return b + b'\0' * (-len(b) % 8)


def param(miid, pid, payload):
    """apm_module_param_data_t: <miid, pid, size, error 0> + payload padded to 8 B."""
    return u32(miid, pid, len(payload), 0) + pad8(payload)


class Acdb(gp.Acdb):
    """graph_plan.Acdb plus the five ACDB queries GSL and AGM make for this session (raw bytes)."""

    def w(self, off):
        return struct.unpack_from('<I', self.data, off)[0]

    def pool(self, off):
        start, end = self.span('POOL')
        size = self.pool_size(off)
        return self.data[start + off + 4:start + off + 4 + size]

    def offloaded_pids(self):
        """ACDB_GPROP_OFFLOADED_PARAM_INFO: GPRO = count + <property id, POOL offset>; POOL = <size, count, pid*>."""
        if 'GPRO' not in self.chunks:
            return set()
        start, end = self.span('GPRO')
        n = self.w(start)
        if 4 + 8 * n != end - start:
            raise ValueError('GPRO size mismatch')
        for i in range(n):
            pid, off = struct.unpack_from('<2I', self.data, start + 4 + 8 * i)
            if pid == GPROP_OFFLOADED_PARAM_INFO:
                data = self.pool(off)
                count = struct.unpack_from('<I', data)[0]
                if 4 + 4 * count > len(data):
                    raise ValueError('offloaded parameter list overruns its POOL item')
                return set(struct.unpack_from('<%dI' % count, data, 4))
        return set()

    # ---- GET_SUBGRAPH_DATA: per requested subgraph, every SPF property, 12-B ACDB header -> 16-B header
    def subgraph_spf_blob(self, sg_ids, graph):
        start, end = self.span('POOL')
        p = start + graph['property_offset']
        total, nsg = struct.unpack_from('<2I', self.data, p)
        objs = {}
        q = p + 8
        for _ in range(nsg):
            sgid, size = struct.unpack_from('<2I', self.data, q)
            body = q + 8
            drv = self.w(body)
            spf_at = body + 4 + drv
            spf_size = self.w(spf_at)
            objs[sgid] = (spf_at + 4, spf_at + 4 + spf_size)
            q = body + size
        out = b''
        for sg in sg_ids:
            a, b = objs[sg]
            while a < b:
                miid, pid, size = struct.unpack_from('<3I', self.data, a)
                padded = size + (-size % 8)
                if a + 12 + padded > b:
                    raise ValueError('SPF property overrun')
                out += u32(miid, pid, size, 0) + self.data[a + 12:a + 12 + padded]
                a += 12 + padded
        return out

    # ---- GET_SUBGRAPH_CONNECTIONS: per (src, dst) edge in request order
    def connection_blob(self, edges):
        count = self.at('SCLU', 0, 1)[0]
        rows = self.at('SCLU', 4, 4 * count)
        lut = {(rows[i], rows[i + 1]): (rows[i + 2], rows[i + 3]) for i in range(0, len(rows), 4)}
        out = b''
        for edge in edges:
            if edge not in lut:
                continue
            def_off, dot_off = lut[edge]
            out += self._def_dot_blob('SCDE', 'SCDO', def_off, dot_off)
        return out

    def _def_dot_blob(self, def_chunk, dot_chunk, def_off, dot_off, as_list=False):
        n = self.at(def_chunk, def_off, 1)[0]
        if self.at(dot_chunk, dot_off, 1)[0] != n:
            raise ValueError(f'{def_chunk}/{dot_chunk} entry counts differ')
        pairs = self.at(def_chunk, def_off + 4, 2 * n)
        offs = self.at(dot_chunk, dot_off + 4, n)
        out = []
        for i in range(n):
            out.append((pairs[2 * i], pairs[2 * i + 1], self.pool(offs[i])))
        return out if as_list else b''.join(param(m, p, b) for m, p, b in out)

    # ---- GET_SUBGRAPH_CALIBRATION_DATA_NONPERSIST, first open (prior CKV empty)
    def calibration_blob(self, sg_ids, ckv, persistent, offloaded):
        start, end = self.span('CSLU')
        p = start
        count = self.w(p)
        p += 4
        tables = {}
        for _ in range(count):
            sg, n = struct.unpack_from('<2I', self.data, p)
            offs = struct.unpack_from('<%dI' % (2 * n), self.data, p + 8)
            p += 8 + 8 * n
            tables[sg] = [(offs[2 * i], offs[2 * i + 1]) for i in range(n)]
        out = b''
        used_keys = set()
        for sg in sorted(sg_ids):
            for key_off, lut_off in tables.get(sg, []):
                nkeys = self.at('CAKT', key_off, 1)[0]
                keys = self.at('CAKT', key_off + 4, nkeys)
                if any(k not in ckv for k in keys):
                    continue
                want = [ckv[k] for k in keys]
                lk, nent = self.at('CDLU', lut_off, 2)
                width = nkeys + 3
                rows = self.at('CDLU', lut_off + 8, width * nent)
                hits = [rows[i * width:(i + 1) * width] for i in range(nent)
                        if list(rows[i * width:i * width + nkeys]) == want]
                if len(hits) != 1:
                    raise ValueError(f'{gp.h(sg)}: CKV {want} matches {len(hits)} calibration rows')
                used_keys.update(keys)
                for miid, pid, body in self._def_dot_blob('CDDE', 'CDDO', hits[0][nkeys], hits[0][nkeys + 1],
                                                           as_list=True):
                    if pid in persistent:
                        continue
                    if pid in offloaded:
                        raise ValueError(f'{gp.h(pid)} is an offloaded parameter (not supported)')
                    out += param(miid, pid, body)
        unused = set(ckv) - used_keys
        if unused:
            raise ValueError(f'CKV keys {sorted(gp.h(k) for k in unused)} select no calibration table')
        return out

    # ---- GET_TAGGED_MODULES: TMLU <sg, tag, def> -> TMDE <n, (mid, iid)*>
    def tagged_modules(self, sg_ids, tag):
        start, end = self.span('TMLU')
        n = self.w(start)
        if 4 + 12 * n != end - start:
            raise ValueError('TMLU size mismatch')
        ds, de = self.span('TMDE')
        found = []
        for i in range(n):
            sg, t, off = struct.unpack_from('<3I', self.data, start + 4 + 12 * i)
            if sg in sg_ids and t == tag:
                cnt = self.w(ds + off)
                pairs = struct.unpack_from('<%dI' % (2 * cnt), self.data, ds + off + 4)
                found += [(sg, pairs[j], pairs[j + 1]) for j in range(0, len(pairs), 2)]
        return found

    # ---- GET_TAG_DATA: MTKT <sg, tag, lut> -> MTLU <nkeys, nent, (vals, def, dot)*> -> MTDE/MTDO
    def tag_data(self, sg, tag, tkv):
        start, end = self.span('MTKT')
        n = self.w(start)
        if 4 + 12 * n != end - start:
            raise ValueError('MTKT size mismatch')
        for i in range(n):
            s, t, off = struct.unpack_from('<3I', self.data, start + 4 + 12 * i)
            if (s, t) != (sg, tag):
                continue
            ls, _ = self.span('MTLU')
            nk, ne = struct.unpack_from('<2I', self.data, ls + off)
            if nk != len(tkv):
                raise ValueError(f'tag {gp.h(tag)}: {nk} keys, TKV has {len(tkv)}')
            want = [tkv[k] for k in sorted(tkv)]
            for j in range(ne):
                row = struct.unpack_from('<%dI' % (nk + 2), self.data, ls + off + 8 + 4 * (nk + 2) * j)
                if list(row[:nk]) == want:
                    return self._def_dot_blob('MTDE', 'MTDO', row[nk], row[nk + 1], as_list=True)
            raise ValueError(f'tag {gp.h(tag)} on {gp.h(sg)}: no row for {want}')
        raise ValueError(f'tag {gp.h(tag)} on {gp.h(sg)}: not in MTKT')


# ---- AGM / PAL payload builders (stock byte layout; libagm configure_pcm_shared_mem_ep checked in Ghidra)

def bits_of(fmt):
    return {SNDRV_PCM_FORMAT_S16_LE: 16, SNDRV_PCM_FORMAT_S32_LE: 32}[fmt]


def channel_map(ch):
    return bytes(range(1, ch + 1))


def pcm_media_format(miid, rate, fmt, ch):
    """WR_SHARED_MEM_EP PARAM_ID_MEDIA_FORMAT (AGM configure_pcm_shared_mem_ep)."""
    bw = bits_of(fmt)
    body = struct.pack('<IHBBHHHH', rate, bw, 1, 0, bw, bw - 1, 1, ch) + channel_map(ch)
    return param(miid, PID_MEDIA_FORMAT, u32(DATA_FORMAT_FIXED_POINT, MEDIA_FMT_ID_PCM, len(body)) + body)


def pcm_output_format(miid, fmt, ch, *, interleaving):
    """Stock AGM output format: RX=3, TX=1 at param offset 0x26.

    Exact libagm configure_output_media_format.cfi 0x11b0c0-0x11b0d8:
    session direction 1 selects 3, otherwise 1; zero is not a stock mode.
    This is module output layout, separate from the WR EP's host PCM layout.
    """
    if interleaving not in (PCM_INTERLEAVED, PCM_DEINTERLEAVED_UNPACKED):
        raise ValueError('unsupported PCM output interleaving')
    bw = bits_of(fmt)
    body = struct.pack('<8h', bw, 1, bw, bw - 1, 1, interleaving, 0, ch) + channel_map(ch)
    return param(miid, PID_PCM_OUTPUT_FORMAT_CFG, u32(DATA_FORMAT_FIXED_POINT, MEDIA_FMT_ID_PCM, len(body)) + body)


def hw_ep_mf(miid, rate, fmt, ch):
    return param(miid, PID_HW_EP_MF_CFG, struct.pack('<IHHI', rate, bits_of(fmt), ch, DATA_FORMAT_FIXED_POINT))


def tdm_cfg(miid, base, slot_mask=None):
    """PARAM_ID_TDM_INTF_CFG from the ACDB tag data, LPAIF type and index (and a group slot mask) overridden."""
    if len(base) != 28:
        raise ValueError('TDM interface config must be 28 B')
    b = bytearray(base)
    struct.pack_into('<II', b, 0, LPAIF, INTF_IDX_TERTIARY)
    if slot_mask is not None:
        struct.pack_into('<I', b, 12, slot_mask)
    return param(miid, PID_TDM_INTF_CFG, bytes(b))


def spr_delay_path_end(miid, end_miid):
    return param(miid, PID_SPR_DELAY_PATH_END, u32(end_miid))


# ---- plan

def one(found, what):
    if len(found) != 1:
        raise ValueError(f'{what}: {len(found)} tagged modules')
    return found[0]


def graph_section(acdb, plan_graph, gkv, ckv, configs_fn):
    g = acdb.graph(gkv)
    sgs = [e['subgraph_id'] for e in g['subgraphs']]
    edges = [(e['subgraph_id'], d) for e in g['subgraphs'] for d in e['destinations']]
    open_blob = acdb.subgraph_spf_blob(sgs, g) + acdb.connection_blob(edges)
    cal_blob = acdb.calibration_blob(sgs, ckv, acdb.persistent_pids(), acdb.offloaded_pids())
    ids, configs = configs_fn(acdb, set(sgs))
    body = u32(plan_graph, len(sgs), *sgs)
    body += u32(len(open_blob)) + pad8(open_blob)
    body += u32(len(cal_blob)) + pad8(cal_blob)
    body += u32(len(configs))
    for c in configs:
        body += u32(len(c)) + pad8(c)
    summary = dict(subgraphs=[gp.h(s) for s in sgs], graph_open_bytes=len(open_blob),
                   calibration_bytes=len(cal_blob), set_cfgs=[len(c) for c in configs],
                   sha256=dict(open=hashlib.sha256(open_blob).hexdigest(),
                               calibration=hashlib.sha256(cal_blob).hexdigest()))
    return body, ids, summary


def rx_configs(stream, group, slot_mask):
    def build(acdb, sgs):
        _, _, wr = one(acdb.tagged_modules(sgs, TAG_STREAM_INPUT_MEDIA_FORMAT), 'WR_SHARED_MEM_EP')
        _, _, dec = one(acdb.tagged_modules(sgs, TAG_STREAM_PCM_DECODER), 'PCM decoder')
        _, _, cnv = one(acdb.tagged_modules(sgs, TAG_STREAM_PCM_CONVERTER), 'PCM converter')
        _, _, spr = one(acdb.tagged_modules(sgs, TAG_STREAM_SPR), 'SPR')
        hw_sg, _, hw = one(acdb.tagged_modules(sgs, TAG_DEVICE_HW_EP_RX), 'HW EP RX')
        _, _, vol = one(acdb.tagged_modules(sgs, TAG_STREAM_VOLUME), 'stream volume')
        _, _, sp = one(acdb.tagged_modules(sgs, TAG_MODULE_SP), 'module_sp')
        mux_sg, _, mux = one(acdb.tagged_modules(sgs, TAG_SLOT_MASK), 'slot mask (MUX_DEMUX)')
        rate, fmt, ch = stream
        grate, gfmt, gch = group
        tdm = acdb.tag_data(hw_sg, TAG_DEVICE_HW_EP_RX, {KEY_CHANNELS: gch})
        if len(tdm) != 1 or tdm[0][:2] != (hw, PID_TDM_INTF_CFG):
            raise ValueError('HW EP RX tag data is not exactly the TDM interface config')
        mux_params = acdb.tag_data(mux_sg, TAG_SLOT_MASK, {KEY_SLOT_MASK: slot_mask})
        configs = [
            # AGM graph_prepare: stream_module_list order, then the HW EP (configure_hw_ep: MF, then TDM)
            pcm_output_format(dec, fmt, ch, interleaving=PCM_DEINTERLEAVED_UNPACKED),
            pcm_output_format(cnv, fmt, ch, interleaving=PCM_DEINTERLEAVED_UNPACKED),
            pcm_media_format(wr, rate, fmt, ch),
            spr_delay_path_end(spr, hw),
            hw_ep_mf(hw, grate, gfmt, gch),
            tdm_cfg(hw, tdm[0][2], slot_mask),
            # PAL Session::setSlotMask: tag C0000040 with the group slot mask
            b''.join(param(m, p, b) for m, p, b in mux_params),
        ]
        return dict(wr_ep=wr, sp_rx=sp, tdm_sink=hw, volume=vol), configs
    return build


def vi_configs(stream, device):
    def build(acdb, sgs):
        _, _, rd = one(acdb.tagged_modules(sgs, TAG_SH_EP), 'RD_SHARED_MEM_EP')
        _, _, enc = one(acdb.tagged_modules(sgs, TAG_STREAM_PCM_ENCODER), 'PCM encoder')
        _, _, cnv = one(acdb.tagged_modules(sgs, TAG_STREAM_PCM_CONVERTER), 'PCM converter')
        hw_sg, _, hw = one(acdb.tagged_modules(sgs, TAG_DEVICE_HW_EP_TX), 'HW EP TX')
        _, _, vi = one(acdb.tagged_modules(sgs, TAG_MODULE_VI), 'module_vi')
        rate, fmt, ch = stream
        drate, dfmt, dch = device
        tdm = acdb.tag_data(hw_sg, TAG_DEVICE_HW_EP_TX, {KEY_CHANNELS: dch})
        if len(tdm) != 1 or tdm[0][:2] != (hw, PID_TDM_INTF_CFG):
            raise ValueError('HW EP TX tag data is not exactly the TDM interface config')
        # The RD EP config (PARAM_ID_RD_SH_MEM_CFG) is not sent: stock libagm configure_rd_shared_mem_ep sends it
        # only with metadata flags or in mode 4. The encoder frame size is not sent: AGM sends it only when the
        # buffer size is not a whole number of milliseconds, and the native read buffers are.
        configs = [
            pcm_output_format(enc, fmt, ch, interleaving=PCM_INTERLEAVED),
            pcm_output_format(cnv, fmt, ch, interleaving=PCM_INTERLEAVED),
            hw_ep_mf(hw, drate, dfmt, dch),
            tdm_cfg(hw, tdm[0][2]),
        ]
        return dict(rd_ep=rd, vi_tx=vi, tdm_source=hw), configs
    return build


def synth_pcm(signal, rate, ch):
    """S16_LE interleaved: each tone for an equal share of the duration, raised-cosine fades, same on every
    channel; peak = signal['peak_mdbfs'] (rounded down)."""
    peak = int(32767 * 10 ** (signal['peak_mdbfs'] / 1000 / 20))
    total = rate * signal['duration_ms'] // 1000
    per = total // len(signal['tones_hz'])
    fade = rate * signal['fade_ms'] // 1000
    out = bytearray()
    for f in signal['tones_hz']:
        for n in range(per):
            g = 1.0
            if n < fade:
                g = 0.5 - 0.5 * math.cos(math.pi * n / fade)
            elif n >= per - fade:
                g = 0.5 - 0.5 * math.cos(math.pi * (per - 1 - n) / fade)
            v = int(peak * g * math.sin(2 * math.pi * f * n / rate))
            out += struct.pack('<h', v) * ch
    return bytes(out)


def backend_entry(direction, name, rate, fmt, ch):
    period = AGM_MAX_PERIOD_BUFFER // (ch * bits_of(fmt) // 8)
    nm = name.encode('ascii')
    if len(nm) >= 64:
        raise ValueError('back-end name too long')
    return u32(direction, rate, ch, fmt, period, AGM_PERIOD_COUNT) + nm.ljust(64, b'\0')


def control_entry(name, value):
    nm, val = name.encode('ascii'), value.encode('ascii')
    if len(nm) >= 44 or len(val) >= 20:
        raise ValueError('control name or value too long')
    return nm.ljust(44, b'\0') + val.ljust(20, b'\0')


def wav_pcm(data, duration_ms, *, rate=48000, channels=2, peak_mdbfs=-10000):
    """Strict local PCM import, no resampling/normalization. Original bytes remain local.
    Imported PCM uses SIGNAL kind1, zero tones, exact duration and a -10dBFS ceiling.
    Over-ceiling media is refused, never silently amplified or clipped."""
    if not 500 <= duration_ms <= 10000 or peak_mdbfs != -10000:
        raise ValueError('imported PCM outside reviewed duration/peak contract')
    try:
        with wave.open(io.BytesIO(data), 'rb') as w:
            if (w.getframerate(), w.getnchannels(), w.getsampwidth(), w.getcomptype()) != (rate, channels, 2, 'NONE'):
                raise ValueError('WAV must be uncompressed 48kHz stereo S16_LE')
            frames = w.getnframes()
            if frames * 1000 != duration_ms * rate:
                raise ValueError('WAV duration differs from the admitted duration')
            pcm = w.readframes(frames)
    except (wave.Error, EOFError) as exc:
        raise ValueError('malformed WAV') from exc
    if len(pcm) != frames * channels * 2:
        raise ValueError('truncated WAV PCM')
    peak = max(abs(v[0]) for v in struct.iter_unpack('<h', pcm))
    if peak > 10361:  # floor(32767 * 10**(-10/20)), also checked by the native parser
        raise ValueError('WAV peak exceeds -10dBFS ceiling')
    # Avoid adding an unreviewed discontinuity. The operator-provided clip is already faded.
    edge = struct.unpack('<' + str(channels) + 'h', pcm[:channels * 2]) + struct.unpack('<' + str(channels) + 'h', pcm[-channels * 2:])
    if any(abs(v) > 1 for v in edge):
        raise ValueError('WAV first/last frame must be at silence')
    return pcm, dict(source='local_wav', source_sha256=hashlib.sha256(data).hexdigest(), frames=frames,
                     peak_sample=peak, pcm_sha256=hashlib.sha256(pcm).hexdigest())


def build(acdb_bytes, usecase_text, re_pair, volume_level, signal, *, wav_bytes=None):
    acdb = Acdb(acdb_bytes)
    plans = {p['usecase']: p for p in gp.derive_gkvs(usecase_text)}
    ll = plans['PAL_STREAM_LOW_LATENCY RX instance 1 -> PAL_DEVICE_OUT_SPEAKER']
    vi = plans['PAL_STREAM_LOW_LATENCY TX instance 1 -> PAL_DEVICE_IN_VI_FEEDBACK']
    if not 0 <= volume_level <= 15:
        raise ValueError('volume level must be 0..15')
    stream = (48000, SNDRV_PCM_FORMAT_S16_LE, 2)      # the session's PCM stream (written by PID1)
    group = (96000, SNDRV_PCM_FORMAT_S32_LE, 3)       # TDM-LPAIF-RX-TERTIARY group (backend_conf.xml)
    vi_stream = (48000, SNDRV_PCM_FORMAT_S16_LE, 2)
    vi_device = (96000, SNDRV_PCM_FORMAT_S32_LE, 2)   # TDM-LPAIF-TX-TERTIARY
    slot_mask = 7
    vi_body, vi_ids, vi_sum = graph_section(acdb, GRAPH_VI, vi['gkv'], {},
                                            vi_configs(vi_stream, vi_device))
    rx_body, rx_ids, rx_sum = graph_section(acdb, GRAPH_RX, ll['gkv'], {KEY_VOLUME: volume_level},
                                            rx_configs(stream, group, slot_mask))
    ids = u32(rx_ids['wr_ep'], vi_ids['rd_ep'], rx_ids['sp_rx'], vi_ids['vi_tx'], rx_ids['tdm_sink'],
              vi_ids['tdm_source'], rx_ids['volume'], *stream, *vi_stream, volume_level)
    backend = (backend_entry(0, 'TDM-LPAIF-RX-TERTIARY-VIRT-2', *group)
               + backend_entry(1, 'TDM-LPAIF-TX-TERTIARY', *vi_device))
    controls = b''.join(control_entry(n, v) for n, v in (
        ('aw_dev_0_prof', 'Music'), ('aw_dev_1_prof', 'Music')))
    re_body = struct.pack('<ii', *re_pair)
    if wav_bytes is None:
        sig = struct.pack('<IIIii', signal['duration_ms'], signal['fade_ms'], len(signal['tones_hz']),
                          signal['peak_mdbfs'], 0) + u32(*signal['tones_hz'])
        pcm = synth_pcm(signal, stream[0], stream[2])
        media = None
    else:
        if signal['fade_ms'] or signal['tones_hz']:
            raise ValueError('imported PCM signal must have no synthesized tones/fades')
        pcm, media = wav_pcm(wav_bytes, signal['duration_ms'], peak_mdbfs=signal['peak_mdbfs'])
        sig = struct.pack('<IIIii', signal['duration_ms'], 0, 0, signal['peak_mdbfs'], 1)
    sections = [(SEC_GRAPH, vi_body), (SEC_GRAPH, rx_body), (SEC_IDS, ids), (SEC_BACKEND, backend),
                (SEC_CONTROL, controls), (SEC_RE, re_body), (SEC_SIGNAL, sig), (SEC_PCM, pcm)]
    body = b''.join(u32(t, len(b)) + pad8(b) for t, b in sections)
    total = HEADER.size + len(body)
    out = HEADER.pack(MAGIC, VERSION, total, len(sections), HEADER.size,
                      hashlib.sha256(acdb_bytes).digest()) + body
    summary = dict(schema=1, scope='local plan summary: IDs, sizes and hashes only', plan_bytes=total,
                   plan_sha256=hashlib.sha256(out).hexdigest(), acdb_sha256=hashlib.sha256(acdb_bytes).hexdigest(),
                   volume_level=volume_level, stream=stream, group=group, vi_stream=vi_stream,
                   vi_device=vi_device, slot_mask=slot_mask,
                   module_instances={k: gp.h(v) for k, v in {**rx_ids, **vi_ids}.items()},
                   vi=vi_sum, rx=rx_sum, signal=signal, pcm_bytes=len(pcm),
                   pcm_sha256=hashlib.sha256(pcm).hexdigest())
    if media is not None:
        summary['media'] = media
    return out, summary


def parse_re(data):
    if len(data) != 8:
        raise ValueError('aw_calr.bin must be 8 bytes')
    a, b = struct.unpack('<ii', data)
    if not (0 < a < 524288 and 0 < b < 524288):
        raise ValueError('Re out of the arithmetic range')
    return a, b


def main():
    a = argparse.ArgumentParser(description=__doc__)
    a.add_argument('--acdb', type=Path, required=True)
    a.add_argument('--acdb-sha256', required=True)
    a.add_argument('--usecase-kv', type=Path, required=True)
    a.add_argument('--usecase-kv-sha256', required=True)
    a.add_argument('--calr', type=Path, required=True, help='read-only copy of aw_calr.bin')
    a.add_argument('--calr-sha256', required=True)
    a.add_argument('--volume-level', type=int, default=8)
    a.add_argument('--peak-mdbfs', type=int, default=-10000, help='signal peak in milli-dBFS')
    a.add_argument('--duration-ms', type=int, default=5000)
    a.add_argument('--output', type=Path, required=True)
    a.add_argument('--summary', type=Path, required=True)
    args = a.parse_args()
    inputs = {}
    for name, path, want in (('ACDB', args.acdb, args.acdb_sha256),
                             ('usecaseKvManager.xml', args.usecase_kv, args.usecase_kv_sha256),
                             ('aw_calr.bin', args.calr, args.calr_sha256)):
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != want.lower():
            raise SystemExit(f'{name} identity mismatch')
        inputs[name] = data
    if not -40000 <= args.peak_mdbfs <= -6000 or not 500 <= args.duration_ms <= 10000:
        raise SystemExit('signal outside the reviewed envelope (peak -40..-6 dBFS, 0.5..10 s)')
    signal = dict(duration_ms=args.duration_ms, fade_ms=50, peak_mdbfs=args.peak_mdbfs,
                  tones_hz=[440, 554, 659, 880])
    plan, summary = build(inputs['ACDB'], inputs['usecaseKvManager.xml'].decode('iso-8859-1'),
                          parse_re(inputs['aw_calr.bin']), args.volume_level, signal)
    args.output.write_bytes(plan)
    args.summary.write_text(json.dumps(summary, indent=1) + '\n', encoding='utf-8')
    print(f"plan {len(plan)} B sha256 {summary['plan_sha256']}; RX open {summary['rx']['graph_open_bytes']} B, "
          f"cal {summary['rx']['calibration_bytes']} B; VI open {summary['vi']['graph_open_bytes']} B")


if __name__ == '__main__':
    main()
