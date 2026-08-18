package credentialcache

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

const cacheLockName = ".cache.lock"

func (store *Store) lockCache(mode int) (*os.File, error) {
	lockPath := filepath.Join(store.directory, cacheLockName)
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open credential cache management lock: %w", err)
	}
	if err := os.Chmod(lockPath, 0o600); err != nil {
		_ = lockFile.Close()
		return nil, fmt.Errorf("secure credential cache management lock: %w", err)
	}
	if err := unix.Flock(int(lockFile.Fd()), mode); err != nil {
		_ = lockFile.Close()
		return nil, fmt.Errorf("lock credential cache: %w", err)
	}
	return lockFile, nil
}

func unlockFile(file *os.File) {
	_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
	_ = file.Close()
}

func (store *Store) lock(key string) (*os.File, error) {
	lockPath := filepath.Join(store.directory, key+".lock")
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open credential cache lock: %w", err)
	}
	if err := os.Chmod(lockPath, 0o600); err != nil {
		_ = lockFile.Close()
		return nil, fmt.Errorf("secure credential cache lock: %w", err)
	}
	if err := unix.Flock(int(lockFile.Fd()), unix.LOCK_EX); err != nil {
		_ = lockFile.Close()
		return nil, fmt.Errorf("lock credential cache: %w", err)
	}
	return lockFile, nil
}
