package collector

import (
	"context"

	"barbarika-agent/config"
	"barbarika-agent/pkg/models"
)

// Manager coordinates all log file tailers and the FIM watcher, aggregating
// their events into a single channel with one shared sequence source.
type Manager struct {
	cfg       *config.Config
	seq       *SeqStore
	fim       *FIMWatcher
	EventChan chan models.LogEvent
}

// NewManager initializes the collector manager with a restart-durable sequence
// source persisted at cfg.SeqStatePath and, when FIM roots are configured, a
// file-integrity watcher.
func NewManager(cfg *config.Config) (*Manager, error) {
	seq, err := OpenSeqStore(cfg.SeqStatePath, 100)
	if err != nil {
		return nil, err
	}
	fimDirs := append(append([]string{}, cfg.FIMWebRoots...), cfg.FIMDataDirs...)
	fim, err := NewFIMWatcher(fimDirs, cfg.FIMCanaryDir)
	if err != nil {
		return nil, err
	}
	return &Manager{
		cfg:       cfg,
		seq:       seq,
		fim:       fim,
		EventChan: make(chan models.LogEvent, 1000), // Buffered channel for high-throughput logging
	}, nil
}

// Start launches tailers for all configured log sources plus the FIM watcher
// (if configured) in parallel goroutines, all feeding the shared EventChan.
func (m *Manager) Start(ctx context.Context) {
	for source, path := range m.cfg.LogSources {
		tailer := NewFileTailer(source, path)
		go tailer.StartTailing(ctx, m.EventChan, m.seq)
	}
	if m.fim != nil {
		m.fim.Start(ctx, m.EventChan, m.seq)
	}
}
