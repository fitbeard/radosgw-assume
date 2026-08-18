package credentialcache

import (
	"time"

	"github.com/fitbeard/radosgw-assume/internal/config"
)

func (store *Store) isReusable(result *config.AssumeRoleResult) bool {
	expiration, valid := credentialExpiration(result)
	if !valid {
		return false
	}
	return expiration.After(store.now().Add(store.minimumValidity))
}

func credentialExpiration(result *config.AssumeRoleResult) (time.Time, bool) {
	if result == nil || result.AccessKeyID == "" || result.SecretAccessKey == "" || result.SessionToken == "" {
		return time.Time{}, false
	}
	expiration, err := time.Parse(time.RFC3339, result.Expiration)
	return expiration, err == nil
}
