package main

import "unicode/utf16"

// splitMultiSZ splits a REG_MULTI_SZ (each string NUL-terminated, the list ended by an empty one) as UTF-16.
func splitMultiSZ(u []uint16) []string {
	var out []string
	for start := 0; start < len(u); {
		end := start
		for end < len(u) && u[end] != 0 {
			end++
		}
		if end == start {
			break
		}
		out = append(out, string(utf16.Decode(u[start:end])))
		start = end + 1
	}
	return out
}
