package api

import (
	"bufio"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// SystemStatus is a snapshot of the host and the Xray core, shown on the
// dashboard (the 3x-ui-style server status widget).
type SystemStatus struct {
	OS         string  `json:"os"`
	Arch       string  `json:"arch"`
	CPUCount   int     `json:"cpu_count"`
	CPUPercent float64 `json:"cpu_percent"`
	Load1      float64 `json:"load1"`
	MemTotal   uint64  `json:"mem_total"`
	MemUsed    uint64  `json:"mem_used"`
	SwapTotal  uint64  `json:"swap_total"`
	SwapUsed   uint64  `json:"swap_used"`
	DiskTotal  uint64  `json:"disk_total"`
	DiskUsed   uint64  `json:"disk_used"`
	UptimeSec  int64   `json:"uptime_sec"`
	// Xray.
	XrayInstalled bool   `json:"xray_installed"`
	XrayRunning   bool   `json:"xray_running"`
	XrayVersion   string `json:"xray_version"`
}

func (s *Server) handleSystem(w http.ResponseWriter, r *http.Request) {
	st := collectSystem()
	if s.Xray != nil {
		st.XrayInstalled = s.Xray.Installed()
		st.XrayRunning = s.Xray.Running()
		if v, err := s.Xray.Version(); err == nil {
			st.XrayVersion = v
		}
	}
	writeJSON(w, http.StatusOK, st)
}

// collectSystem reads host metrics. It is best-effort: on non-Linux hosts, or
// when /proc is unavailable, fields it cannot read stay zero.
func collectSystem() SystemStatus {
	st := SystemStatus{OS: runtime.GOOS, Arch: runtime.GOARCH, CPUCount: runtime.NumCPU()}

	if v, err := os.ReadFile("/proc/loadavg"); err == nil {
		if f := strings.Fields(string(v)); len(f) > 0 {
			st.Load1, _ = strconv.ParseFloat(f[0], 64)
		}
	}
	if up, err := os.ReadFile("/proc/uptime"); err == nil {
		if f := strings.Fields(string(up)); len(f) > 0 {
			sec, _ := strconv.ParseFloat(f[0], 64)
			st.UptimeSec = int64(sec)
		}
	}
	readMeminfo(&st)
	st.CPUPercent = cpuPercent()
	st.DiskTotal, st.DiskUsed = diskUsage("/")
	return st
}

func readMeminfo(st *SystemStatus) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return
	}
	defer f.Close()
	var memTotal, memAvail, memFree, buffers, cached, swapTotal, swapFree uint64
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		v, _ := strconv.ParseUint(fields[1], 10, 64)
		v *= 1024 // kB -> bytes
		switch strings.TrimSuffix(fields[0], ":") {
		case "MemTotal":
			memTotal = v
		case "MemAvailable":
			memAvail = v
		case "MemFree":
			memFree = v
		case "Buffers":
			buffers = v
		case "Cached":
			cached = v
		case "SwapTotal":
			swapTotal = v
		case "SwapFree":
			swapFree = v
		}
	}
	st.MemTotal = memTotal
	if memAvail > 0 {
		st.MemUsed = memTotal - memAvail
	} else {
		st.MemUsed = memTotal - memFree - buffers - cached
	}
	st.SwapTotal = swapTotal
	st.SwapUsed = swapTotal - swapFree
}

// cpuPercent samples /proc/stat twice over a short window.
func cpuPercent() float64 {
	idle0, total0, ok0 := cpuSample()
	if !ok0 {
		return 0
	}
	time.Sleep(120 * time.Millisecond)
	idle1, total1, ok1 := cpuSample()
	if !ok1 || total1 <= total0 {
		return 0
	}
	dt := float64(total1 - total0)
	di := float64(idle1 - idle0)
	p := (dt - di) / dt * 100
	if p < 0 {
		p = 0
	}
	return float64(int(p*10)) / 10
}

func cpuSample() (idle, total uint64, ok bool) {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0, false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		for i, f := range strings.Fields(line)[1:] {
			v, _ := strconv.ParseUint(f, 10, 64)
			total += v
			if i == 3 || i == 4 { // idle + iowait
				idle += v
			}
		}
		return idle, total, true
	}
	return 0, 0, false
}
