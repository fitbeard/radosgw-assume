package config

import (
	"fmt"
	"strings"
	"testing"

	"gopkg.in/ini.v1"
)

func BenchmarkGetRadosGWProfiles(b *testing.B) {
	for _, profileCount := range []int{10, 100} {
		b.Run(fmt.Sprintf("%d profiles", profileCount), func(b *testing.B) {
			awsConfig := benchmarkAWSConfig(b, profileCount)
			if got := len(GetRadosGWProfiles(awsConfig)); got != profileCount {
				b.Fatalf("GetRadosGWProfiles() returned %d profiles, want %d", got, profileCount)
			}

			b.ReportAllocs()
			for b.Loop() {
				GetRadosGWProfiles(awsConfig)
			}
		})
	}
}

func BenchmarkResolveSourceProfile(b *testing.B) {
	for _, depth := range []int{1, 5, 10} {
		b.Run(fmt.Sprintf("depth %d", depth), func(b *testing.B) {
			awsConfig, profileConfig := benchmarkSourceProfileChain(b, depth)

			b.ReportAllocs()
			for b.Loop() {
				_, err := ResolveSourceProfile(profileConfig, awsConfig, false)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func benchmarkAWSConfig(b *testing.B, profileCount int) *ini.File {
	b.Helper()

	var content strings.Builder
	content.WriteString(`[profile profile-0]
endpoint_url = https://storage.example.com
radosgw_oidc_provider = https://idp.example.com/realms/benchmark
radosgw_oidc_client_id = benchmark-client
role_arn = arn:aws:iam::123456789012:role/Benchmark0
`)
	for index := 1; index < profileCount; index++ {
		_, _ = fmt.Fprintf(&content, `
[profile profile-%d]
source_profile = profile-0
role_arn = arn:aws:iam::123456789012:role/Benchmark%d
`, index, index)
	}

	awsConfig, err := ini.Load([]byte(content.String()))
	if err != nil {
		b.Fatalf("ini.Load() error = %v", err)
	}
	return awsConfig
}

func benchmarkSourceProfileChain(b *testing.B, depth int) (*ini.File, *ProfileConfig) {
	b.Helper()

	var content strings.Builder
	content.WriteString(`[profile level-0]
endpoint_url = https://storage.example.com
radosgw_oidc_provider = https://idp.example.com/realms/benchmark
radosgw_oidc_client_id = benchmark-client
radosgw_oidc_auth_type = device
radosgw_oidc_scope = openid
radosgw_oidc_pkce_method = S256
radosgw_ssl_verify = true
`)
	for level := 1; level <= depth; level++ {
		_, _ = fmt.Fprintf(&content, `
[profile level-%d]
source_profile = level-%d
role_arn = arn:aws:iam::123456789012:role/Benchmark%d
`, level, level-1, level)
	}

	awsConfig, err := ini.Load([]byte(content.String()))
	if err != nil {
		b.Fatalf("ini.Load() error = %v", err)
	}
	profileConfig, err := GetProfileConfig(fmt.Sprintf("level-%d", depth), awsConfig)
	if err != nil {
		b.Fatalf("GetProfileConfig() error = %v", err)
	}
	return awsConfig, profileConfig
}
