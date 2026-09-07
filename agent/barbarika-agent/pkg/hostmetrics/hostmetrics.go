// Package hostmetrics samples the monitored host's own vitals (CPU, memory,
// load, the daemon's RSS/uptime, OS/kernel) straight from /proc and /etc — the
// agent already runs on the host with local access, so it reports host health
// alongside the log stream. Linux-native, no external dependencies; on a
// non-Linux dev box the unavailable fields are simply omitted.
package hostmetrics

import (
	"bufio"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Snapshot is the wire shape Sentry's POST /host expects (see
// sentry/app/models.py :: HostSnapshot). Pointer fields are omitted when the
// metric could not be read, so the payload never carries a fake zero.
type Snapshot struct {
	AgentID      string   `json:"agent_id"`
	OS           string   `json:"os,omitempty"`
	Kernel       string   `json:"kernel,omitempty"`
	CPUPercent   *float64 `json:"cpu_percent,omitempty"`
	MemUsedMB    *float64 `json:"mem_used_mb,omitempty"`
	MemTotalMB   *float64 `json:"mem_total_mb,omitempty"`
	Load1        *float64 `json:"load1,omitempty"`
	RSSMB        *float64 `json:"rss_mb,omitempty"`
	UptimeS      *float64 `json:"uptime_s,omitempty"`
	AgentVersion string   `json:"agent_version,omitempty"`
	EgressMode   string   `json:"egress_mode,omitempty"`
	Sequence     uint64   `json:"sequence,omitempty"`
}

// Collector holds the previous CPU tick sample so successive calls can compute a
// utilisation delta. Not safe for concurrent Sample() calls (the poster is one
// goroutine).
type Collector struct {
	prevBusy, prevTotal float64
	haver               bool
	os, kernel          string
}

// New reads the static host facts (OS pretty-name, kernel release) once.
func New() *Collector {
	return &Collector{os: readOS(), kernel: firstLine("/proc/sys/kernel/osrelease")}
}

// Sample returns the host's current vitals. The first call cannot compute CPU%
// (no prior tick baseline) and omits it; every later call includes it.
func (c *Collector) Sample(agentID, version, egressMode string, seq uint64) Snapshot {
	s := Snapshot{
		AgentID: agentID, OS: c.os, Kernel: c.kernel,
		AgentVersion: version, EgressMode: egressMode, Sequence: seq,
	}
	if c.os == "" {
		s.OS = runtime.GOOS // dev fallback when /etc/os-release is absent
	}
	if v := c.cpuPercent(); v != nil {
		s.CPUPercent = v
	}
	if used, total := memMB(); total > 0 {
		s.MemUsedMB, s.MemTotalMB = &used, &total
	}
	if v := load1(); v != nil {
		s.Load1 = v
	}
	if v := rssMB(); v != nil {
		s.RSSMB = v
	}
	if v := uptimeS(); v != nil {
		s.UptimeS = v
	}
	return s
}

// cpuPercent parses the aggregate line of /proc/stat and returns busy/total
// utilisation since the previous call (nil on the first call or on error).
func (c *Collector) cpuPercent() *float64 {
	line := firstLine("/proc/stat")
	if !strings.HasPrefix(line, "cpu ") && !strings.HasPrefix(line, "cpu\t") {
		return nil
	}
	fields := strings.Fields(line)[1:]
	var total, idle float64
	for i, f := range fields {
		v, err := strconv.ParseFloat(f, 64)
		if err != nil {
			continue
		}
		total += v
		if i == 3 || i == 4 { // idle + iowait
			idle += v
		}
	}
	busy := total - idle
	defer func() { c.prevBusy, c.prevTotal, c.haver = busy, total, true }()
	if !c.haver {
		return nil
	}
	dt := total - c.prevTotal
	if dt <= 0 {
		return nil
	}
	pct := (busy - c.prevBusy) / dt * 100
	pct = clamp(pct, 0, 100)
	return &pct
}

func memMB() (used, total float64) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	defer f.Close()
	var totalKB, availKB float64
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		v, _ := strconv.ParseFloat(fields[1], 64)
		switch fields[0] {
		case "MemTotal:":
			totalKB = v
		case "MemAvailable:":
			availKB = v
		}
	}
	if totalKB == 0 {
		return 0, 0
	}
	return (totalKB - availKB) / 1024, totalKB / 1024
}

func load1() *float64 {
	fields := strings.Fields(firstLine("/proc/loadavg"))
	if len(fields) == 0 {
		return nil
	}
	v, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return nil
	}
	return &v
}

func rssMB() *float64 {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return nil
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), "VmRSS:") {
			fields := strings.Fields(sc.Text())
			if len(fields) >= 2 {
				kb, err := strconv.ParseFloat(fields[1], 64)
				if err == nil {
					mb := kb / 1024
					return &mb
				}
			}
		}
	}
	return nil
}

func uptimeS() *float64 {
	fields := strings.Fields(firstLine("/proc/uptime"))
	if len(fields) == 0 {
		return nil
	}
	v, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return nil
	}
	return &v
}

// readOS extracts PRETTY_NAME from /etc/os-release, e.g. "Ubuntu 24.04 LTS".
func readOS() string {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), "PRETTY_NAME=") {
			return strings.Trim(strings.TrimPrefix(sc.Text(), "PRETTY_NAME="), `"`)
		}
	}
	return ""
}

func firstLine(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	if sc.Scan() {
		return sc.Text()
	}
	return ""
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// SampleInterval is the recommended cadence for the host poster.
const SampleInterval = 5 * time.Second
