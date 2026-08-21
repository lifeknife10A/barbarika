package tailer

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
)

// JournaldTailer streams journalctl JSON output via exec or file.
type JournaldTailer struct {
	unit   string
	follow bool
}

// NewJournaldTailer creates a new journald tailer.
func NewJournaldTailer(unit string, follow bool) *JournaldTailer {
	return &JournaldTailer{
		unit:   unit,
		follow: follow,
	}
}

// Start spawns journalctl -o json and returns a channel of raw JSON strings.
func (j *JournaldTailer) Start(ctx context.Context) (<-chan string, <-chan error) {
	lines := make(chan string, 100)
	errs := make(chan error, 1)

	args := []string{"-o", "json"}
	if j.follow {
		args = append(args, "-f")
	}
	if j.unit != "" {
		args = append(args, "-u", j.unit)
	}

	cmd := exec.CommandContext(ctx, "journalctl", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		errs <- fmt.Errorf("failed to create stdout pipe for journalctl: %w", err)
		close(lines)
		close(errs)
		return lines, errs
	}

	if err := cmd.Start(); err != nil {
		errs <- fmt.Errorf("failed to start journalctl: %w", err)
		close(lines)
		close(errs)
		return lines, errs
	}

	go func() {
		defer close(lines)
		defer close(errs)

		reader := bufio.NewReader(stdout)
		for {
			select {
			case <-ctx.Done():
				_ = cmd.Process.Kill()
				return
			default:
			}

			line, err := reader.ReadString('\n')
			if err != nil {
				if err != io.EOF {
					errs <- fmt.Errorf("journalctl read error: %w", err)
				}
				return
			}
			lines <- line
		}
	}()

	return lines, errs
}
