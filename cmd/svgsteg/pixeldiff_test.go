package main

import "testing"

func TestDiffPixels(t *testing.T) {
	// 2x1 image. Pixel 0 identical; pixel 1 differs by (10,20,30,0).
	a := []byte{100, 100, 100, 255, 100, 100, 100, 255}
	b := []byte{100, 100, 100, 255, 110, 120, 130, 255}
	changed, maxD, mean := diffPixels(a, b, 2, 1)
	if changed != 1 {
		t.Errorf("changed = %d, want 1", changed)
	}
	if maxD != 30 {
		t.Errorf("maxDelta = %d, want 30", maxD)
	}
	// sum of channel deltas = 10+20+30+0 = 60 over 2*1*4 = 8 channels.
	if want := 60.0 / 8.0; mean != want {
		t.Errorf("meanDelta = %v, want %v", mean, want)
	}
	// Identical buffers → zero.
	if c, m, mn := diffPixels(a, a, 2, 1); c != 0 || m != 0 || mn != 0 {
		t.Errorf("identical buffers: got (%d,%d,%v), want (0,0,0)", c, m, mn)
	}
	// Undersized buffer → safe zero, no panic.
	if c, m, mn := diffPixels([]byte{1, 2, 3}, []byte{4, 5, 6}, 2, 1); c != 0 || m != 0 || mn != 0 {
		t.Errorf("undersized buffer: got (%d,%d,%v), want (0,0,0)", c, m, mn)
	}
}
