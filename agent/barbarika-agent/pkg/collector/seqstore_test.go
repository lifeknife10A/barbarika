package collector

import (
	"path/filepath"
	"testing"
)

func TestSeqStoreIsMonotonicAndSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "seq.state")

	s1, err := OpenSeqStore(path, 10)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	var last uint64
	for i := 0; i < 25; i++ {
		n := s1.Next()
		if n <= last {
			t.Fatalf("not monotonic: got %d after %d", n, last)
		}
		last = n
	}

	// Reopen (simulate an agent restart): the next number must exceed every
	// number the previous run could have issued — no reuse, no going backwards.
	s2, err := OpenSeqStore(path, 10)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if n := s2.Next(); n <= last {
		t.Fatalf("restart reused/regressed sequence: %d <= %d", n, last)
	}
}

func TestSeqStoreInMemoryWithoutPath(t *testing.T) {
	s, err := OpenSeqStore("", 10)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if s.Next() != 1 || s.Next() != 2 {
		t.Fatal("in-memory store should start at 1 and increment")
	}
}
