package collector

import (
	"bufio"
	"context"
	"io"
	"log"
	"os"
	"sync/atomic"
	"time"

	"barbarika-agent/pkg/models"
)

// FileTailer continuously tails a log file line-by-line in real-time.
type FileTailer struct {
	Source   string
	FilePath string
}

// NewFileTailer creates a tailer instance for a specific log source (e.g. "auth", "nginx").
func NewFileTailer(source, filePath string) *FileTailer {
	return &FileTailer{
		Source:   source,
		FilePath: filePath,
	}
}

// StartTailing opens the log file and streams new lines to the output channel.
func (t *FileTailer) StartTailing(ctx context.Context, outChan chan<- models.LogEvent, seqCounter *uint64) {
	log.Printf("[Tailer] Starting tailer for source '%s' at path: %s", t.Source, t.FilePath)

	file, err := os.OpenFile(t.FilePath, os.O_RDONLY, 0644)
	if err != nil {
		log.Printf("[Tailer Error] Failed to open log file %s: %v. Retrying in background...", t.FilePath, err)
		// Wait and retry opening if file is created late
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				file, err = os.Open(t.FilePath)
				if err == nil {
					break
				}
			}
			if file != nil {
				break
			}
		}
	}
	defer file.Close()

	// Read existing lines or seek to start
	reader := bufio.NewReader(file)

	for {
		select {
		case <-ctx.Done():
			log.Printf("[Tailer] Stopping tailer for source '%s'", t.Source)
			return
		default:
			line, err := reader.ReadString('\n')
			if err != nil {
				if err == io.EOF {
					// Reached end of file; sleep briefly and wait for new log lines to be appended
					time.Sleep(200 * time.Millisecond)
					continue
				}
				log.Printf("[Tailer Warning] Read error on %s: %v", t.FilePath, err)
				time.Sleep(500 * time.Millisecond)
				continue
			}

			// Trim newline characters
			if len(line) > 0 && line[len(line)-1] == '\n' {
				line = line[:len(line)-1]
			}
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}

			if line == "" {
				continue
			}

			// Increment global event sequence counter atomically
			seq := atomic.AddUint64(seqCounter, 1)

			// Create & normalize event
			event := models.LogEvent{
				Sequence:   seq,
				Source:     t.Source,
				Timestamp:  time.Now().UTC(),
				RawContent: line,
			}
			event.ComputeHash()

			// Send to centralized event channel
			outChan <- event
		}
	}
}
