package collector

import (
	"context"

	"barbarika-agent/config"
	"barbarika-agent/pkg/models"
)

// Manager coordinates all log file tailers and aggregates events into a single channel.
type Manager struct {
	cfg        *config.Config
	seqCounter uint64
	EventChan  chan models.LogEvent
}

// NewManager initializes the collector manager.
func NewManager(cfg *config.Config) *Manager {
	return &Manager{
		cfg:       cfg,
		EventChan: make(chan models.LogEvent, 1000), // Buffered channel for high-throughput logging
	}
}

// Start launches tailers for all configured log sources in parallel goroutines.
func (m *Manager) Start(ctx context.Context) {
	for source, path := range m.cfg.LogSources {
		tailer := NewFileTailer(source, path)
		go tailer.StartTailing(ctx, m.EventChan, &m.seqCounter)
	}
}

// SequenceCounter returns the current total number of harvested events.
func (m *Manager) SequenceCounter() uint64 {
	return m.seqCounter
}
