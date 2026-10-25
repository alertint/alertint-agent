// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
)

// A Transition's briefing is stored apart from its row, zlib-compressed
// (migration 0048): the briefing is ~95% of a Transition's bytes and repeats
// most of the previous one, so it compresses about sevenfold. Only Go reads
// it; the SQL that inspects projection_json reads the fields that stay there.
const briefingEncoding = "zlib"

// maxBriefingBytes bounds what one stored briefing may expand to, so a
// corrupt or hostile row cannot exhaust memory on read. The largest briefing
// measured on a months-long Situation was about 660 KiB.
const maxBriefingBytes = 64 << 20

func compressBriefing(raw []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if _, err := w.Write(raw); err != nil {
		return nil, fmt.Errorf("store: compress briefing: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("store: compress briefing: %w", err)
	}
	return buf.Bytes(), nil
}

func decompressBriefing(blob []byte) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(blob))
	if err != nil {
		return nil, fmt.Errorf("store: decompress briefing: %w", err)
	}
	defer func() { _ = r.Close() }()
	raw, err := io.ReadAll(io.LimitReader(r, maxBriefingBytes+1))
	if err != nil {
		return nil, fmt.Errorf("store: decompress briefing: %w", err)
	}
	if len(raw) > maxBriefingBytes {
		return nil, fmt.Errorf("store: decompress briefing: exceeds %d bytes", maxBriefingBytes)
	}
	return raw, nil
}
