//go:build !js

// Stdlib + vendored Go codecs (flate, zstd). Excluded from GOOS=js builds, where the
// browser's CompressionStream supplies compression instead.

package main

import (
	"bytes"
	"compress/flate"
	"io"

	"github.com/klauspost/compress/zstd"
)

func init() {
	registerCodec(codecSpec{compFlateFast, "flate-fast", true,
		func(b []byte) ([]byte, error) { return flateCompress(b, flate.BestSpeed) }, flateDecompress})
	registerCodec(codecSpec{compFlateDefault, "flate-default", true,
		func(b []byte) ([]byte, error) { return flateCompress(b, flate.DefaultCompression) }, flateDecompress})
	registerCodec(codecSpec{compFlateBest, "flate-best", false, // explicit-only, not in auto
		func(b []byte) ([]byte, error) { return flateCompress(b, flate.BestCompression) }, flateDecompress})
	registerCodec(codecSpec{compZstdFast, "zstd-fast", true,
		func(b []byte) ([]byte, error) { return zstdCompress(b, zstd.SpeedFastest) }, zstdDecompress})
	registerCodec(codecSpec{compZstdDefault, "zstd-default", true,
		func(b []byte) ([]byte, error) { return zstdCompress(b, zstd.SpeedDefault) }, zstdDecompress})
}

func flateCompress(in []byte, level int) ([]byte, error) {
	var b bytes.Buffer
	w, err := flate.NewWriter(&b, level)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(in); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func flateDecompress(in []byte) ([]byte, error) {
	r := flate.NewReader(bytes.NewReader(in))
	defer r.Close()
	return io.ReadAll(r)
}

func zstdCompress(in []byte, level zstd.EncoderLevel) ([]byte, error) {
	enc, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(level))
	if err != nil {
		return nil, err
	}
	defer enc.Close()
	return enc.EncodeAll(in, nil), nil
}

func zstdDecompress(in []byte) ([]byte, error) {
	dec, err := zstd.NewReader(nil)
	if err != nil {
		return nil, err
	}
	defer dec.Close()
	return dec.DecodeAll(in, nil)
}
