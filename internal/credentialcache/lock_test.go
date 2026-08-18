package credentialcache

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fitbeard/radosgw-assume/internal/config"
)

func TestStoreSerializesConcurrentRetrieval(t *testing.T) {
	now := time.Date(2030, time.January, 1, 0, 0, 0, 0, time.UTC)
	store := newStore(t.TempDir(), func() time.Time { return now }, refreshWindow(time.Hour))
	key := testKey(t)
	want := testResult(now.Add(time.Hour))
	started := make(chan struct{})
	release := make(chan struct{})
	var retrievals atomic.Int32
	retrieve := func() (*config.AssumeRoleResult, error) {
		if retrievals.Add(1) == 1 {
			close(started)
		}
		<-release
		return want, nil
	}

	const callers = 8
	var waitGroup sync.WaitGroup
	waitGroup.Add(callers)
	errorsChannel := make(chan error, callers)
	for range callers {
		go func() {
			defer waitGroup.Done()
			result, _, err := store.GetOrRetrieve(key, retrieve)
			if err == nil && result.AccessKeyID != want.AccessKeyID {
				err = errors.New("unexpected cached result")
			}
			errorsChannel <- err
		}()
	}
	<-started
	close(release)
	waitGroup.Wait()
	close(errorsChannel)

	for err := range errorsChannel {
		if err != nil {
			t.Errorf("GetOrRetrieve() error = %v", err)
		}
	}
	if retrievals.Load() != 1 {
		t.Errorf("retrievals = %d, want 1", retrievals.Load())
	}
}
