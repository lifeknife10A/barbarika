package tailer

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

// Config holds configuration options for the Tailer.
type Config struct {
	FilePath      string
	Follow        bool
	PollInterval  time.Duration
	FromBeginning bool
}

// Tailer reads and tails lines from a file.
type Tailer struct {
	cfg Config
}

// NewTailer creates a new file tailer.
func NewTailer(cfg Config) *Tailer {
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 100 * time.Millisecond
	}
	return &Tailer{cfg: cfg}
}

// Start begins tailing the configured file and streams lines to the returned channel.
func (t *Tailer) Start(ctx context.Context) (<-chan string, <-chan error) {
	lines := make(chan string, 100)
	errs := make(chan error, 1)

	go func() {
		defer close(lines)
		defer close(errs)

		file, err := os.Open(t.cfg.FilePath)
		if err != nil {
			errs <- fmt.Errorf("failed to open file %s: %w", t.cfg.FilePath, err)
			return
		}
		defer file.Close()

		if !t.cfg.FromBeginning {
			_, err = file.Seek(0, io.SeekEnd)
			if err != nil {
				errs <- fmt.Errorf("failed to seek to end of file: %w", err)
				return
			}
		}

		reader := bufio.NewReader(file)

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			line, err := reader.ReadString('\n')
			if err != nil {
				if errors.Is(err, io.EOF) {
					if len(line) > 0 {
						lines <- line
					}
					if !t.cfg.Follow {
						// Finished reading file
						return
					}
					// Follow mode: wait before polling for new lines
					select {
					case <-ctx.Done():
						return
					case <-time.After(t.cfg.PollInterval):
						continue
					}
				}
				errs <- fmt.Errorf("error reading file %s: %w", t.cfg.FilePath, err)
				return
			}

			lines <- line
		}
	}()

	return lines, errs
}
