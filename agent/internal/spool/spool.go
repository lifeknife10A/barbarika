package spool

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"barbarika/agent/internal/normalizer"
)

const (
	DefaultMaxSpoolBytes = 50 * 1024 * 1024 // 50MB bounded limit
	SegmentPrefix        = "spool_"
	SegmentExt           = ".log"
)

// Spool provides a crash-resilient, disk-backed FIFO queue for telemetry events.
type Spool struct {
	dir         string
	maxBytes    int64
	mu          sync.Mutex
	activeFile  *os.File
	activeBytes int64
	segmentMax  int64
}

// NewSpool creates or opens a bounded local disk spool in spoolDir.
func NewSpool(dir string, maxBytes int64) (*Spool, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create spool dir: %w", err)
	}

	if maxBytes <= 0 {
		maxBytes = DefaultMaxSpoolBytes
	}

	s := &Spool{
		dir:        dir,
		maxBytes:   maxBytes,
		segmentMax: 5 * 1024 * 1024, // 5MB per segment
	}

	if err := s.rotateSegment(); err != nil {
		return nil, fmt.Errorf("failed to initialize spool segment: %w", err)
	}

	return s, nil
}

// Push writes an event to the local disk spool with immediate flush.
func (s *Spool) Push(evt normalizer.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.Marshal(evt)
	if err != nil {
		return fmt.Errorf("spool marshal error: %w", err)
	}
	data = append(data, '\n')

	// Check if active segment exceeds segment max
	if s.activeBytes+int64(len(data)) > s.segmentMax {
		if err := s.rotateSegment(); err != nil {
			return err
		}
	}

	n, err := s.activeFile.Write(data)
	if err != nil {
		return fmt.Errorf("spool write error: %w", err)
	}
	_ = s.activeFile.Sync()

	s.activeBytes += int64(n)
	s.enforceBounds()
	return nil
}

// ReplayUnacknowledged reads all existing spooled events in chronological order.
func (s *Spool) ReplayUnacknowledged() ([]normalizer.Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	segments, err := s.listSegments()
	if err != nil {
		return nil, err
	}

	var events []normalizer.Event
	for _, segPath := range segments {
		f, err := os.Open(segPath)
		if err != nil {
			continue
		}
		reader := bufio.NewReader(f)
		for {
			line, err := reader.ReadBytes('\n')
			if len(line) > 0 {
				var evt normalizer.Event
				if jsonErr := json.Unmarshal(line, &evt); jsonErr == nil {
					events = append(events, evt)
				}
			}
			if err != nil {
				if err == io.EOF {
					break
				}
				break
			}
		}
		_ = f.Close()
	}

	return events, nil
}

// rotateSegment closes the current active segment and opens a new timestamped segment.
func (s *Spool) rotateSegment() error {
	if s.activeFile != nil {
		_ = s.activeFile.Sync()
		_ = s.activeFile.Close()
	}

	segName := fmt.Sprintf("%s%d%s", SegmentPrefix, time.Now().UnixNano(), SegmentExt)
	segPath := filepath.Join(s.dir, segName)

	f, err := os.OpenFile(segPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}

	s.activeFile = f
	s.activeBytes = 0
	return nil
}

// listSegments returns all segment paths in alphabetical (chronological) order.
func (s *Spool) listSegments() ([]string, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}

	var segments []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == SegmentExt {
			segments = append(segments, filepath.Join(s.dir, e.Name()))
		}
	}
	sort.Strings(segments)
	return segments, nil
}

// enforceBounds removes oldest segments if total size exceeds maxBytes.
func (s *Spool) enforceBounds() {
	segments, err := s.listSegments()
	if err != nil || len(segments) <= 1 {
		return
	}

	var total int64
	for _, seg := range segments {
		if fi, err := os.Stat(seg); err == nil {
			total += fi.Size()
		}
	}

	// Evict oldest segments until within bounds (keeping active segment)
	for i := 0; i < len(segments)-1 && total > s.maxBytes; i++ {
		seg := segments[i]
		if fi, err := os.Stat(seg); err == nil {
			total -= fi.Size()
			_ = os.Remove(seg)
		}
	}
}

// Close flushes and closes the active spool segment.
func (s *Spool) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.activeFile != nil {
		_ = s.activeFile.Sync()
		return s.activeFile.Close()
	}
	return nil
}
