package main

import (
	"slices"
	"testing"
	"unicode/utf16"
)

func TestSplitMultiSZ(t *testing.T) {
	enc := func(s string) []uint16 { return utf16.Encode([]rune(s)) }
	for in, want := range map[string][]string{
		"":                                nil,
		"\x00":                            nil,
		"SeChangeNotifyPrivilege\x00\x00": {"SeChangeNotifyPrivilege"},
		"SeA\x00SeB\x00\x00garbage":       {"SeA", "SeB"},
		"SeA\x00SeB":                      {"SeA", "SeB"}, // no terminator at the end of the buffer
	} {
		if got := splitMultiSZ(enc(in)); !slices.Equal(got, want) {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}
