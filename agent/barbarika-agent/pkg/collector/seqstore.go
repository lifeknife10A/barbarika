package collector

import (
	"os"
	"strconv"
	"strings"
	"sync"
)

// SeqStore hands out monotonically increasing sequence numbers that survive
// agent restarts. Without this the counter resets to 1 on every boot, which
// makes Sentry's per-agent hash chain (whose predecessor lookup orders by
// sequence) fork or fail once sequences overlap across restarts.
//
// It persists a reservation — a high-water mark ahead of the last issued
// number — so a crash never reuses a sequence. Sequence gaps after a restart
// are acceptable; only monotonicity (never go backwards, never reuse) matters.
// Writes happen once per `block` numbers, not per event.
type SeqStore struct {
	path       string
	block      uint64
	mu         sync.Mutex
	next       uint64
	reservedTo uint64
}

// OpenSeqStore resumes from the persisted reservation (if any) and reserves a
// fresh block above it, so the first number issued is strictly greater than
// anything a previous run could have used. An empty path keeps it in-memory.
func OpenSeqStore(path string, block uint64) (*SeqStore, error) {
	if block == 0 {
		block = 100
	}
	s := &SeqStore{path: path, block: block}
	if path != "" {
		if data, err := os.ReadFile(path); err == nil {
			if v, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64); err == nil {
				s.next = v
				s.reservedTo = v
			}
		}
	}
	if err := s.reserve(s.next + s.block); err != nil {
		return nil, err
	}
	return s, nil
}

// Next returns the next sequence number, persisting a new reservation when the
// current block is exhausted.
func (s *SeqStore) Next() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next++
	if s.next > s.reservedTo {
		_ = s.reserve(s.next + s.block)
	}
	return s.next
}

func (s *SeqStore) reserve(upTo uint64) error {
	s.reservedTo = upTo
	if s.path == "" {
		return nil
	}
	return os.WriteFile(s.path, []byte(strconv.FormatUint(upTo, 10)), 0600)
}
