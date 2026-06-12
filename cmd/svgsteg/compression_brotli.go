//go:build !nobrotli && !js

// Brotli codec. Dropped with `-tags nobrotli` (~0.6 MB) and from GOOS=js builds.

package main

import (
	"bytes"
	"io"

	"github.com/andybalholm/brotli"
)

func init() {
	registerCodec(codecSpec{compBrotli, "brotli", true,
		func(b []byte) ([]byte, error) { return brotliCompress(b, 4) }, brotliDecompress})
}

func brotliCompress(in []byte, level int) ([]byte, error) {
	var b bytes.Buffer
	w := brotli.NewWriterLevel(&b, level)
	if _, err := w.Write(in); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func brotliDecompress(in []byte) ([]byte, error) {
	r := brotli.NewReader(bytes.NewReader(in))
	return io.ReadAll(r)
}
