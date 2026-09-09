package collector

import (
	"bufio"
	"context"
	"io"
	"log"
	"os/exec"
	"strings"
	"time"

	"barbarika-agent/pkg/models"
)

// JournaldCollector streams the systemd journal (`journalctl -f`) into the event
// pipeline. On Ubuntu 24.04 and other minimal/systemd-only hosts the classic
// /var/log/auth.log often does not exist (rsyslog is not installed by default),
// so the file tailers find nothing and the feed looks empty. journald is the
// authoritative log source there, so following it keeps the feed alive even
// before any attack — the whole system's activity flows through it.
type JournaldCollector struct {
	Source string
	Args   []string
}

// NewJournaldCollector configures a follower that seeds a little recent context
// (so a quiet host is not blank on start) and then streams live entries.
func NewJournaldCollector() *JournaldCollector {
	return &JournaldCollector{
		Source: "journald",
		// -n 30 seeds the feed with recent lines; -f follows; short-iso emits
		// readable, timestamped lines the Sentry normalizer can treat like syslog.
		Args: []string{"-f", "-n", "30", "--no-pager", "-o", "short-iso"},
	}
}

// Start runs journalctl and streams its output into outChan. It blocks until the
// context is cancelled or journalctl exits, so launch it in a goroutine like the
// file tailers. If journalctl is unavailable (a non-systemd or dev host) it logs
// a clear, actionable reason and returns rather than failing silently.
func (j *JournaldCollector) Start(ctx context.Context, outChan chan<- models.LogEvent, seq *SeqStore) {
	if _, err := exec.LookPath("journalctl"); err != nil {
		log.Printf("[Journald] journalctl not found (%v); journald source disabled. "+
			"On Ubuntu 24.04 without rsyslog this is the primary log source — run the "+
			"agent on the systemd host, as root or a member of the 'adm'/'systemd-journal' group.", err)
		return
	}

	log.Printf("[Journald] Starting journald follower: journalctl %s", strings.Join(j.Args, " "))
	cmd := exec.CommandContext(ctx, "journalctl", j.Args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Printf("[Journald Error] cannot open journalctl stdout: %v", err)
		return
	}
	if err := cmd.Start(); err != nil {
		log.Printf("[Journald Error] cannot start journalctl (permission or systemd missing?): %v", err)
		return
	}

	j.stream(ctx, stdout, outChan, seq)

	// Reap the process; on ctx cancel CommandContext kills it, so ignore the err.
	_ = cmd.Wait()
	log.Printf("[Journald] follower stopped")
}

// stream reads newline-delimited journal entries from r and emits one LogEvent
// each, sharing the manager's restart-durable sequence. Split out from Start so
// it can be unit-tested with any io.Reader.
func (j *JournaldCollector) stream(ctx context.Context, r io.Reader, outChan chan<- models.LogEvent, seq *SeqStore) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024) // tolerate long journal lines
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return
		default:
		}
		line := strings.TrimRight(scanner.Text(), "\r")
		if line == "" {
			continue
		}
		event := models.LogEvent{
			Sequence:   seq.Next(),
			Source:     j.Source,
			Timestamp:  time.Now().UTC(),
			RawContent: line,
		}
		event.ComputeHash()
		select {
		case <-ctx.Done():
			return
		case outChan <- event:
		}
	}
}
