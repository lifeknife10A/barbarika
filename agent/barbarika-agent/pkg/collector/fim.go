package collector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"

	"barbarika-agent/pkg/models"
)

// FIMWatcher is a file-integrity monitor. It watches the web root(s) and data
// dir(s) with fsnotify and emits one normalized event per change on the shared
// collector channel, as `source=fim` LogEvents whose RawContent is the wire
// string Anishka's rules match on (rules/TELEMETRY_CONTRACT.md §3–§4):
//
//	FIM <OP> <abs_path> sha256=<hex|->
//	FIM CANARY <OP> <abs_path> sha256=<hex|->   (a decoy file was touched)
//
// <OP> ∈ CREATE WRITE RENAME REMOVE CHMOD; sha256 is the new content hash, or
// "-" when the file was removed/unreadable. The category (iv web-root vs v
// data-dir vs v canary) is assigned downstream by egress.candidateCategory from
// this path, keeping a single telemetry→category bridge.
type FIMWatcher struct {
	dirs      []string
	canaryDir string
	fsw       *fsnotify.Watcher
	watched   map[string]bool
}

// NewFIMWatcher builds a watcher over the given directories (web roots + data
// dirs). Returns (nil, nil) when no directories are configured — FIM is off.
func NewFIMWatcher(dirs []string, canaryDir string) (*FIMWatcher, error) {
	if len(dirs) == 0 {
		return nil, nil
	}
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	return &FIMWatcher{
		dirs:      dirs,
		canaryDir: canaryDir,
		fsw:       fsw,
		watched:   make(map[string]bool),
	}, nil
}

// Start registers the watch roots and streams change events onto outChan using
// the shared restart-durable sequence source, until ctx is cancelled.
func (w *FIMWatcher) Start(ctx context.Context, outChan chan<- models.LogEvent, seq *SeqStore) {
	for _, dir := range w.dirs {
		w.addRecursive(dir)
	}
	if w.canaryDir != "" {
		w.addRecursive(w.canaryDir)
	}
	log.Printf("[FIM] Watching %v (canary dir: %q)", w.dirs, w.canaryDir)

	go func() {
		defer w.fsw.Close()
		for {
			select {
			case <-ctx.Done():
				log.Printf("[FIM] Stopping file-integrity watcher")
				return
			case err, ok := <-w.fsw.Errors:
				if !ok {
					return
				}
				log.Printf("[FIM Warning] fsnotify error: %v", err)
			case ev, ok := <-w.fsw.Events:
				if !ok {
					return
				}
				w.handle(ev, outChan, seq)
			}
		}
	}()
}

func (w *FIMWatcher) handle(ev fsnotify.Event, outChan chan<- models.LogEvent, seq *SeqStore) {
	// A newly created directory is added to the watch set but not itself an
	// integrity event worth shipping.
	if ev.Op&fsnotify.Create == fsnotify.Create {
		if fi, err := os.Stat(ev.Name); err == nil && fi.IsDir() {
			w.addRecursive(ev.Name)
			return
		}
	}

	op := opToString(ev.Op)
	if op == "" {
		return
	}

	// New content hash for create/write; "-" for remove/rename/unreadable.
	sha := "-"
	if ev.Op&(fsnotify.Create|fsnotify.Write) != 0 {
		if h, err := hashFile(ev.Name); err == nil {
			sha = h
		}
	}

	absPath := ev.Name
	if p, err := filepath.Abs(ev.Name); err == nil {
		absPath = p
	}

	prefix := "FIM"
	if w.isCanaryPath(absPath) {
		prefix = "FIM CANARY"
	}
	raw := prefix + " " + op + " " + absPath + " sha256=" + sha

	event := models.LogEvent{
		Sequence:   seq.Next(),
		Source:     "fim",
		Timestamp:  time.Now().UTC(),
		RawContent: raw,
	}
	event.ComputeHash()
	outChan <- event
}

// addRecursive walks root and adds every directory to the fsnotify watch set.
// Missing roots are tolerated (a dir may not exist yet in a demo).
func (w *FIMWatcher) addRecursive(root string) {
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() && !w.watched[path] {
			if err := w.fsw.Add(path); err == nil {
				w.watched[path] = true
			}
		}
		return nil
	})
}

// isCanaryPath reports whether a path is a planted decoy — inside the canary
// dir, or a file whose name carries the canary convention.
func (w *FIMWatcher) isCanaryPath(path string) bool {
	if w.canaryDir != "" {
		canary := strings.ToLower(filepath.Clean(w.canaryDir))
		p := strings.ToLower(filepath.Clean(path))
		if rel, err := filepath.Rel(canary, p); err == nil && !strings.HasPrefix(rel, "..") {
			return true
		}
	}
	base := strings.ToLower(filepath.Base(path))
	return strings.Contains(base, ".canary") || strings.Contains(base, "canary_token")
}

// opToString maps an fsnotify op to the FIM verb the rules expect. Returns ""
// for an op we do not report.
func opToString(op fsnotify.Op) string {
	switch {
	case op&fsnotify.Create == fsnotify.Create:
		return "CREATE"
	case op&fsnotify.Write == fsnotify.Write:
		return "WRITE"
	case op&fsnotify.Rename == fsnotify.Rename:
		return "RENAME"
	case op&fsnotify.Remove == fsnotify.Remove:
		return "REMOVE"
	case op&fsnotify.Chmod == fsnotify.Chmod:
		return "CHMOD"
	default:
		return ""
	}
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
