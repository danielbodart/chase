package selector_test

import (
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// cyclicPack writes a pack of two objects, each a delta against the other, as
// a session can write into its own .git/objects: git chasing it never
// finishes, and its memory grows while it tries. It was
// tests/selector/cyclic-pack.py.
func cyclicPack(t *testing.T, oidA, oidB, packDir string) {
	t.Helper()
	a, err := hex.DecodeString(oidA)
	if err != nil {
		t.Fatal(err)
	}
	b, err := hex.DecodeString(oidB)
	if err != nil {
		t.Fatal(err)
	}
	header := func(kind, size int) []byte {
		var out []byte
		c := byte(kind<<4) | byte(size&15)
		size >>= 4
		for size != 0 {
			out = append(out, c|0x80)
			c = byte(size & 0x7f)
			size >>= 7
		}
		return append(out, c)
	}
	varint := func(n int) []byte {
		var out []byte
		for {
			c := byte(n & 0x7f)
			n >>= 7
			if n != 0 {
				out = append(out, c|0x80)
			} else {
				return append(out, c)
			}
		}
	}
	compress := func(p []byte) []byte {
		var buf bytes.Buffer
		w := zlib.NewWriter(&buf)
		w.Write(p)
		w.Close()
		return buf.Bytes()
	}
	delta := append(append(varint(10), varint(10)...), 0x80|0x10|0x01, 0, 10)
	var body []byte
	var offsets []uint32
	offset := 12
	// a against b, b against a: REF_DELTA, type 7.
	for _, base := range [][]byte{b, a} {
		offsets = append(offsets, uint32(offset))
		entry := append(append(header(7, len(delta)), base...), compress(delta)...)
		body = append(body, entry...)
		offset += len(entry)
	}
	pack := append([]byte("PACK"), 0, 0, 0, 2, 0, 0, 0, 2)
	pack = append(pack, body...)
	sum := sha1.Sum(pack)
	pack = append(pack, sum[:]...)

	type entry struct {
		name   []byte
		offset uint32
	}
	entries := []entry{{a, offsets[0]}, {b, offsets[1]}}
	sort.Slice(entries, func(i, j int) bool { return bytes.Compare(entries[i].name, entries[j].name) < 0 })
	var fanout [256]uint32
	for _, e := range entries {
		for i := int(e.name[0]); i < 256; i++ {
			fanout[i]++
		}
	}
	idx := []byte("\xfftOc")
	idx = binary.BigEndian.AppendUint32(idx, 2)
	for _, f := range fanout {
		idx = binary.BigEndian.AppendUint32(idx, f)
	}
	for _, e := range entries {
		idx = append(idx, e.name...)
	}
	for range entries {
		idx = binary.BigEndian.AppendUint32(idx, 0)
	}
	for _, e := range entries {
		idx = binary.BigEndian.AppendUint32(idx, e.offset)
	}
	idx = append(idx, sum[:]...)
	isum := sha1.Sum(idx)
	idx = append(idx, isum[:]...)
	name := hex.EncodeToString(sum[:])
	if err := os.WriteFile(filepath.Join(packDir, "pack-"+name+".pack"), pack, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packDir, "pack-"+name+".idx"), idx, 0o644); err != nil {
		t.Fatal(err)
	}
}
