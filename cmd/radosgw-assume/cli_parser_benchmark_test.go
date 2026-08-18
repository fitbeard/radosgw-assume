package main

import "testing"

func BenchmarkParseCLIArguments(b *testing.B) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "version", args: []string{"version"}},
		{name: "interactive export"},
		{
			name: "profile export",
			args: []string{"--verbose", "--duration", "2h", "--session", "benchmark-session", "--profile", "benchmark-profile"},
		},
		{name: "environment export", args: []string{"--env"}},
		{
			name: "exec",
			args: []string{"exec", "--duration", "2h", "--profile", "benchmark-profile", "--", "aws", "s3", "ls", "--recursive"},
		},
		{
			name: "credential process",
			args: []string{"credential-process", "--duration", "2h", "--profile", "benchmark-profile"},
		},
	}

	for _, test := range tests {
		b.Run(test.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				options, err := parseCLIArguments("radosgw-assume", test.args)
				if err != nil {
					b.Fatal(err)
				}
				_ = options
			}
		})
	}
}
