package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"barbarika/agent/internal/batcher"
	"barbarika/agent/internal/normalizer"
	"barbarika/agent/internal/signer"
	"barbarika/agent/internal/spool"
	"barbarika/agent/internal/tailer"
	"barbarika/agent/internal/watcher"
)

// Config holds runtime configuration for the ingestion daemon.
type Config struct {
	SourceID     string
	AuthLogPath  string
	NginxLogPath string
	JournaldUnit string
	WatchDirs    []string
	CanaryDir    string
	SpoolDir     string
	MaxSpoolSize int64
	BatchSize    int
	FlushPeriod  time.Duration
	Follow       bool
	EmitBatches  bool
}

// Daemon coordinates log ingestion, file integrity monitoring, spooling, signing, and emission.
type Daemon struct {
	cfg        Config
	signer     *signer.Signer
	normalizer *normalizer.Normalizer
	spool      *spool.Spool
	batcher    *batcher.Batcher
	output     io.Writer
	tailersWg  sync.WaitGroup
	serviceWg  sync.WaitGroup
}

// NewDaemon creates a fully-configured ingestion daemon.
func NewDaemon(cfg Config, sig *signer.Signer, norm *normalizer.Normalizer, sp *spool.Spool, out io.Writer) *Daemon {
	if cfg.SourceID == "" {
		cfg.SourceID = "primary-srv-01"
	}
	if norm == nil {
		norm = normalizer.NewNormalizer(cfg.SourceID)
	}

	b := batcher.NewBatcher(batcher.Config{
		AgentID:       cfg.SourceID,
		MaxBatchSize:  cfg.BatchSize,
		FlushInterval: cfg.FlushPeriod,
	}, sig)

	return &Daemon{
		cfg:        cfg,
		signer:     sig,
		normalizer: norm,
		spool:      sp,
		batcher:    b,
		output:     out,
	}
}

// Run starts all ingestion collectors and orchestrates the pipeline.
func (d *Daemon) Run(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// 1. Replay unacknowledged events from crash spool
	if d.spool != nil {
		replayed, err := d.spool.ReplayUnacknowledged()
		if err == nil && len(replayed) > 0 {
			for _, evt := range replayed {
				d.processEvent(evt)
			}
		}
	}

	// 2. Start batcher flush ticker
	go d.batcher.Start(runCtx)

	// 3. Start batch consumer with guaranteed shutdown drain
	d.serviceWg.Add(1)
	go func() {
		defer d.serviceWg.Done()
		for {
			select {
			case <-runCtx.Done():
				// Drain any remaining batches in outChan
				for {
					select {
					case batch, ok := <-d.batcher.OutChannel():
						if !ok {
							return
						}
						if d.cfg.EmitBatches {
							data, _ := json.Marshal(batch)
							_, _ = fmt.Fprintf(d.output, "%s\n", data)
						}
					default:
						return
					}
				}
			case batch, ok := <-d.batcher.OutChannel():
				if !ok {
					return
				}
				if d.cfg.EmitBatches {
					data, _ := json.Marshal(batch)
					_, _ = fmt.Fprintf(d.output, "%s\n", data)
				}
			}
		}
	}()

	hasTailers := false

	// 4. Start auth.log tailer if configured
	if d.cfg.AuthLogPath != "" {
		if _, err := os.Stat(d.cfg.AuthLogPath); err == nil {
			hasTailers = true
			d.startFileTailer(runCtx, d.cfg.AuthLogPath)
		}
	}

	// 5. Start nginx log tailer if configured
	if d.cfg.NginxLogPath != "" {
		if _, err := os.Stat(d.cfg.NginxLogPath); err == nil {
			hasTailers = true
			d.startFileTailer(runCtx, d.cfg.NginxLogPath)
		}
	}

	// 6. Start fsnotify watcher if directories configured
	if len(d.cfg.WatchDirs) > 0 || d.cfg.CanaryDir != "" {
		w, err := watcher.NewWatcher(watcher.Config{
			WatchDirs: d.cfg.WatchDirs,
			CanaryDir: d.cfg.CanaryDir,
		}, d.normalizer)
		if err == nil {
			fimEvents, fimErrs, err := w.Start(runCtx)
			if err == nil {
				d.serviceWg.Add(1)
				go func() {
					defer d.serviceWg.Done()
					for {
						select {
						case <-runCtx.Done():
							return
						case _, ok := <-fimErrs:
							if !ok {
								return
							}
						case evt, ok := <-fimEvents:
							if !ok {
								return
							}
							d.processEvent(evt)
						}
					}
				}()
			}
		}
	}

	// In non-follow mode with file tailers, wait for tailers to finish
	if !d.cfg.Follow && hasTailers {
		d.tailersWg.Wait()
		d.batcher.Flush()
		time.Sleep(30 * time.Millisecond)
		cancel()
	} else {
		<-ctx.Done()
		d.batcher.Flush()
	}

	d.serviceWg.Wait()
	if d.spool != nil {
		_ = d.spool.Close()
	}
	return nil
}

// IngestRawLine feeds a single log line directly into the pipeline.
func (d *Daemon) IngestRawLine(line string) {
	evt := d.normalizer.Normalize(line)
	d.processEvent(evt)
}

func (d *Daemon) startFileTailer(ctx context.Context, path string) {
	t := tailer.NewTailer(tailer.Config{
		FilePath:      path,
		Follow:        d.cfg.Follow,
		FromBeginning: true,
	})

	linesChan, errChan := t.Start(ctx)
	d.tailersWg.Add(1)
	go func() {
		defer d.tailersWg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case _, ok := <-errChan:
				if !ok {
					return
				}
			case line, ok := <-linesChan:
				if !ok {
					return
				}
				evt := d.normalizer.Normalize(line)
				d.processEvent(evt)
			}
		}
	}()
}

func (d *Daemon) processEvent(evt normalizer.Event) {
	// Spool to disk
	if d.spool != nil {
		_ = d.spool.Push(evt)
	}

	// Add to in-memory batcher
	d.batcher.Add(evt)

	// If streaming single events (not just batches)
	if !d.cfg.EmitBatches {
		evtBytes, _ := json.Marshal(evt)
		sigB64 := d.signer.SignBase64(evtBytes)

		signedEvt := normalizer.SignedEvent{
			Event:     evt,
			PublicKey: d.signer.PublicKeyBase64(),
			Signature: sigB64,
		}
		data, _ := json.Marshal(signedEvt)
		_, _ = fmt.Fprintf(d.output, "%s\n", data)
	}
}
