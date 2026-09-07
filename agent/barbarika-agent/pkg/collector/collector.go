package collector

import (
	"context"

	"barbarika-agent/config"
	"barbarika-agent/pkg/models"
)

// Manager coordinates all log file tailers and aggregates events into a single channel.
type Manager struct {
	cfg       *config.Config
	seq       *SeqStore
	EventChan chan models.LogEvent
}

// NewManager initializes the collector manager with a restart-durable sequence
// source persisted at cfg.SeqStatePath.
func NewManager(cfg *config.Config) (*Manager, error) {
	seq, err := OpenSeqStore(cfg.SeqStatePath, 100)
	if err != nil {
		return nil, err
	}
	return &Manager{
		cfg:       cfg,
		seq:       seq,
		EventChan: make(chan models.LogEvent, 1000), // Buffered channel for high-throughput logging
	}, nil
}

// Start launches tailers for all configured log sources in parallel goroutines.
func (m *Manager) Start(ctx context.Context) {
	for source, path := range m.cfg.LogSources {
		tailer := NewFileTailer(source, path)
		go tailer.StartTailing(ctx, m.EventChan, m.seq)
	}
}
