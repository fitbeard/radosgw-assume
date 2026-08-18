package credentialcache

import (
	"strings"
	"testing"
	"time"

	"github.com/fitbeard/radosgw-assume/internal/config"
)

func BenchmarkKey(b *testing.B) {
	tests := []struct {
		name      string
		authType  config.AuthType
		oidcToken string
	}{
		{name: "device", authType: config.AuthTypeDevice},
		{name: "token", authType: config.AuthTypeToken, oidcToken: strings.Repeat("token-payload", 200)},
	}

	for _, test := range tests {
		b.Run(test.name, func(b *testing.B) {
			profileConfig := testProfileConfig()
			profileConfig.RadosGWOIDCAuthType = test.authType

			b.ReportAllocs()
			for b.Loop() {
				key, err := Key("benchmark-profile", profileConfig, time.Hour, test.oidcToken)
				if err != nil {
					b.Fatal(err)
				}
				_ = key
			}
		})
	}
}

func BenchmarkStoreCacheHit(b *testing.B) {
	now := time.Date(2030, time.January, 1, 0, 0, 0, 0, time.UTC)
	store := newStore(b.TempDir(), func() time.Time { return now }, refreshWindow(time.Hour))
	key, err := Key("benchmark-profile", testProfileConfig(), time.Hour, "")
	if err != nil {
		b.Fatalf("Key() error = %v", err)
	}
	want := testResult(now.Add(time.Hour))
	if _, hit, err := store.GetOrRetrieve(key, func() (*config.AssumeRoleResult, error) { return want, nil }); err != nil || hit {
		b.Fatalf("populate cache = (hit %v, error %v), want fresh result", hit, err)
	}

	retrieve := func() (*config.AssumeRoleResult, error) {
		b.Fatal("cache hit unexpectedly retrieved credentials")
		return nil, nil
	}
	b.ReportAllocs()
	for b.Loop() {
		result, hit, err := store.GetOrRetrieve(key, retrieve)
		if err != nil {
			b.Fatal(err)
		}
		if !hit {
			b.Fatal("GetOrRetrieve() missed a populated cache entry")
		}
		_ = result
	}
}
