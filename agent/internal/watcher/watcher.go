package watcher

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"barbarika/agent/internal/normalizer"
)

// Config holds configuration for the file integrity monitoring (FIM) watcher.
type Config struct {
	WatchDirs     []string
	CanaryDir     string
	DebounceDelay time.Duration
}

// Watcher monitors directories using fsnotify and emits normalized file integrity events.
type Watcher struct {
	cfg        Config
	normalizer *normalizer.Normalizer
	fsWatcher  *fsnotify.Watcher
	mu         sync.Mutex
	watched    map[string]bool
}

// NewWatcher creates a new file integrity watcher.
func NewWatcher(cfg Config, norm *normalizer.Normalizer) (*Watcher, error) {
	fsWatcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create fsnotify watcher: %w", err)
	}

	if cfg.DebounceDelay <= 0 {
		cfg.DebounceDelay = 50 * time.Millisecond
	}

	return &Watcher{
		cfg:        cfg,
		normalizer: norm,
		fsWatcher:  fsWatcher,
		watched:    make(map[string]bool),
	}, nil
}

// Start begins monitoring watched directories and emits Events to the returned channel.
func (w *Watcher) Start(ctx context.Context) (<-chan normalizer.Event, <-chan error, error) {
	eventsChan := make(chan normalizer.Event, 100)
	errChan := make(chan error, 1)

	// Add watch directories
	for _, dir := range w.cfg.WatchDirs {
		if err := w.addRecursive(dir); err != nil {
			// Directory might not exist yet in test/demo; log and continue
			continue
		}
	}

	// Add canary dir if configured
	if w.cfg.CanaryDir != "" {
		_ = w.addRecursive(w.cfg.CanaryDir)
	}

	go func() {
		defer close(eventsChan)
		defer close(errChan)
		defer w.fsWatcher.Close()

		for {
			select {
			case <-ctx.Done():
				return

			case err, ok := <-w.fsWatcher.Errors:
				if !ok {
					return
				}
				errChan <- fmt.Errorf("fsnotify error: %w", err)

			case fsEvt, ok := <-w.fsWatcher.Events:
				if !ok {
					return
				}

				// Check if new directory was created, add it to watcher
				if fsEvt.Op&fsnotify.Create == fsnotify.Create {
					if fi, err := os.Stat(fsEvt.Name); err == nil && fi.IsDir() {
						_ = w.addRecursive(fsEvt.Name)
					}
				}

				// Determine operation name
				opName := opToString(fsEvt.Op)
				isCanary := w.isCanaryPath(fsEvt.Name)

				// Compute hash if file exists and is readable
				fileHash := ""
				if fsEvt.Op&(fsnotify.Create|fsnotify.Write) != 0 {
					if hash, err := hashFile(fsEvt.Name); err == nil {
						fileHash = hash
					}
				}

				// Normalize into Barbarika Event
				event := w.normalizer.NormalizeFileEvent(fsEvt.Name, opName, isCanary, fileHash)
				eventsChan <- event
			}
		}
	}()

	return eventsChan, errChan, nil
}

// addRecursive recursively adds directories to fsnotify.
func (w *Watcher) addRecursive(root string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if !w.watched[path] {
				if err := w.fsWatcher.Add(path); err == nil {
					w.watched[path] = true
				}
			}
		}
		return nil
	})
}

// isCanaryPath checks if a path falls within the canary directory or filename convention.
func (w *Watcher) isCanaryPath(path string) bool {
	if w.cfg.CanaryDir != "" {
		canaryClean := strings.ToLower(filepath.Clean(w.cfg.CanaryDir))
		pathClean := strings.ToLower(filepath.Clean(path))
		if rel, err := filepath.Rel(canaryClean, pathClean); err == nil && !strings.HasPrefix(rel, "..") {
			return true
		}
	}
	base := strings.ToLower(filepath.Base(path))
	return strings.Contains(base, ".canary") || strings.Contains(base, "canary_token")
}

func opToString(op fsnotify.Op) string {
	switch {
	case op&fsnotify.Create == fsnotify.Create:
		return "CREATE"
	case op&fsnotify.Write == fsnotify.Write:
		return "WRITE"
	case op&fsnotify.Remove == fsnotify.Remove:
		return "REMOVE"
	case op&fsnotify.Rename == fsnotify.Rename:
		return "RENAME"
	case op&fsnotify.Chmod == fsnotify.Chmod:
		return "CHMOD"
	default:
		return "UNKNOWN"
	}
}

func hashFile(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}
