package sts

import "testing"

func BenchmarkValidateSessionName(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		if err := ValidateSessionName("radosgw-assume-benchmark-session-123"); err != nil {
			b.Fatal(err)
		}
	}
}
