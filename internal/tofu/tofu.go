// Package tofu stores trust-on-first-use SHA256 fingerprints for binaries.
package tofu

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// Store maps absolute binary path → sha256 hex.
type Store struct {
	mu   sync.Mutex
	path string
	data map[string]string
}

// Open loads or creates a TOFU store at path (JSON).
func Open(path string) (*Store, error) {
	s := &Store{path: path, data: map[string]string{}}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	if err := s.withFileLock(func() error {
		if err := s.loadLocked(); os.IsNotExist(err) {
			return s.flushLocked()
		} else {
			return err
		}
	}); err != nil {
		return nil, err
	}
	return s, nil
}

// DefaultPath returns $XDG_STATE_HOME/quarshell/binary-tofu.json (or ~/.local/state/…).
func DefaultPath() string {
	if xdg := os.Getenv("XDG_STATE_HOME"); xdg != "" {
		return filepath.Join(xdg, "quarshell", "binary-tofu.json")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "quarshell-binary-tofu.json")
	}
	return filepath.Join(home, ".local", "state", "quarshell", "binary-tofu.json")
}

// VerifyOrCache hashes path and either records first-seen or denies on mismatch.
func (s *Store) VerifyOrCache(binPath string) (hash string, err error) {
	if s == nil {
		return "", fmt.Errorf("tofu: nil store")
	}
	abs, err := filepath.Abs(binPath)
	if err != nil {
		return "", err
	}
	abs, err = filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}
	sum, err := hashFile(abs)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	err = s.withFileLock(func() error {
		if err := s.loadLocked(); err != nil {
			return err
		}
		if prev, ok := s.data[abs]; ok {
			if prev != sum {
				return fmt.Errorf("tofu: binary fingerprint changed for %s", abs)
			}
			return nil
		}
		s.data[abs] = sum
		return s.flushLocked()
	})
	return sum, err
}

func (s *Store) loadLocked() error {
	b, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	var data map[string]string
	if err := json.Unmarshal(b, &data); err != nil {
		return fmt.Errorf("tofu: parse: %w", err)
	}
	if data == nil {
		data = map[string]string{}
	}
	s.data = data
	return nil
}

func (s *Store) withFileLock(fn func() error) error {
	lock, err := os.OpenFile(s.path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := lockFile(lock); err != nil {
		return err
	}
	defer unlockFile(lock)
	return fn()
}

func (s *Store) flushLocked() error {
	b, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(s.path), ".tofu-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(s.path))
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
