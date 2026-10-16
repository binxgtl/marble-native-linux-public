"""Bounded offline ACDB v1 graph inventory; never initializes GSL or a device.

Format corroboration: AudioReach graphservices 3094583, acdb_parser.c,
DataProcSearchGkvKeyTable/Lut, DataProcGetSubgraphProcIidMap and
AcdbGetSubgraphList. This is a subset parser, not an ACDB implementation.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct


class Reader:
    def __init__(self, data, start=0, end=None):
        self.data, self.pos = data, start
        self.end = len(data) if end is None else end
        if not 0 <= start <= self.end <= len(data):
            raise ValueError('region outside file')

    def words(self, count):
        if count < 0 or count > (self.end - self.pos) // 4:
            raise ValueError('truncated or excessive word count')
        result = struct.unpack_from('<' + str(count) + 'I', self.data, self.pos)
        self.pos += count * 4
        return result

    def finish(self):
        if self.pos != self.end:
            raise ValueError('unexpected trailing bytes in table')


def inspect(data):
    if len(data) > 64 * 1024 * 1024:
        raise ValueError('ACDB exceeds inspection budget')
    r = Reader(data)
    magic, kind, size = r.words(3)
    if magic != 0x42444341 or kind != 0 or size != len(data) - 12:
        raise ValueError('invalid ACDB magic/type/size')
    chunks = {}
    while r.pos < r.end:
        chunk_id, n = r.words(2)
        name = struct.pack('<I', chunk_id).decode('ascii')
        if name in chunks or n > r.end - r.pos:
            raise ValueError('duplicate chunk or chunk overrun')
        chunks[name] = (r.pos, n)
        r.pos += n  # No alignment padding in this format.
    for name in ('HEAD', 'GKVT', 'GKVL', 'SGIT', 'POOL'):
        if name not in chunks:
            raise ValueError('missing required chunk: ' + name)

    def region(name, offset=0):
        start, n = chunks[name]
        return Reader(data, start + offset, start + n)

    if region('HEAD').words(1)[0] != 1:
        raise ValueError('only HEAD format version 1 is supported')

    # SGIT: subgraph -> processor domain -> (module ID, instance ID).
    sg = region('SGIT')
    subgraphs = {}
    count = sg.words(1)[0]
    if count > (sg.end - sg.pos) // 12:
        raise ValueError('excessive subgraph count')
    for _ in range(count):
        sgid, proc_count, n = sg.words(3)
        child = Reader(data, sg.pos, sg.pos + n)
        if sgid in subgraphs or proc_count > n // 8:
            raise ValueError('duplicate subgraph or excessive domain count')
        domains = []
        for _ in range(proc_count):
            proc, modules = child.words(2)
            pairs = child.words(modules * 2)
            domains.append(dict(domain=proc, modules=[
                dict(module_id=pairs[i], instance_id=pairs[i + 1])
                for i in range(0, len(pairs), 2)]))
        child.finish()
        subgraphs[sgid] = domains
        sg.pos += n
    sg.finish()

    def graph_list(offset):
        pool = region('POOL', offset)
        size, n = pool.words(2)
        # Size includes num_subgraphs but not the size word itself.
        end = pool.pos - 4 + size
        if size < 4 or end > pool.end or n > (size - 4) // 8:
            raise ValueError('invalid POOL subgraph list size/count')
        pool.end = end
        entries = []
        for _ in range(n):
            sgid, destinations = pool.words(2)
            dst = pool.words(destinations)
            if sgid not in subgraphs or any(d not in subgraphs for d in dst):
                raise ValueError('graph references missing SGIT subgraph')
            entries.append(dict(subgraph_id=sgid, destinations=list(dst)))
        pool.finish()
        return entries

    keys = region('GKVT')
    tables = keys.words(1)[0]
    if tables > (keys.end - keys.pos) // 8:
        raise ValueError('excessive key table count')
    graphs = []
    key_sets = set()
    seen_values = set()
    for _ in range(tables):
        num_keys, rows = keys.words(2)
        raw = keys.words(rows * (num_keys + 1))
        for i in range(rows):
            row = raw[i * (num_keys + 1):(i + 1) * (num_keys + 1)]
            ids, value_offset = row[:-1], row[-1]
            if len(set(ids)) != len(ids) or ids in key_sets:
                raise ValueError('duplicate key ID or key set')
            key_sets.add(ids)
            values = region('GKVL', value_offset)
            nkeys, nrows = values.words(2)
            if nkeys != num_keys:
                raise ValueError('GKVT/GKVL key count mismatch')
            words = values.words(nrows * (num_keys + 2))
            for j in range(nrows):
                v = words[j * (num_keys + 2):(j + 1) * (num_keys + 2)]
                kv = tuple(zip(ids, v[:-2]))
                if kv in seen_values:
                    raise ValueError('duplicate graph key vector')
                seen_values.add(kv)
                entries = graph_list(v[-2])
                # Property blob is deliberately opaque; only range check its pointer.
                region('POOL', v[-1]).words(1)
                graphs.append(dict(keys=[dict(key=k, value=w) for k, w in kv],
                                   subgraphs=entries, property_offset=v[-1]))
    keys.finish()
    occurrences = []
    for sgid, domains in subgraphs.items():
        for domain in domains:
            for module in domain['modules']:
                if module['instance_id'] == 0x42D3:
                    occurrences.append(dict(subgraph_id=sgid, domain=domain['domain'], **module))
    return dict(schema=1, scope='offline structural subset only',
                permits_playback=False, sha256=hashlib.sha256(data).hexdigest(),
                bytes=len(data), chunks={k: dict(offset=o, bytes=n) for k, (o, n) in chunks.items()},
                key_tables=tables, graph_count=len(graphs), subgraph_count=len(subgraphs),
                graphs=graphs, subgraphs=subgraphs, aw_instance_42d3=occurrences,
                runtime_graph_selected='UNKNOWN', protection_active='UNKNOWN')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('acdb', type=Path)
    p.add_argument('--expect-sha256', required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    with args.acdb.open('rb') as f:
        data = f.read(64 * 1024 * 1024 + 1)
    if hashlib.sha256(data).hexdigest() != args.expect_sha256:
        raise SystemExit('ACDB identity mismatch')
    report = inspect(data)
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(f"ACDB structural PASS: {report['graph_count']} graphs, {report['subgraph_count']} subgraphs; playback forbidden")


if __name__ == '__main__':
    main()
