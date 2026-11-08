package collect

// NVIDIA GPUs through nvidia-smi, NVIDIA's own command-line tool (it ships with the driver). fairy-agent starts it
// once in its looping mode (-lms) and reads one CSV line per GPU per interval, so there is no process start per
// poll and nothing NVIDIA-specific is loaded into the agent itself.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"io"
	"log/slog"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// GPUQuery is the --query-gpu field list; ParseNvidiaGPULine expects this order.
const GPUQuery = "index,uuid,name,utilization.gpu,memory.used,memory.total,temperature.gpu,power.draw"

const mib = 1 << 20

// nvNum parses one nvidia-smi value; "[N/A]", "N/A", "[Not Supported]" and friends are nil.
func nvNum(s string) *float64 {
	s = strings.TrimSpace(s)
	if s == "" || strings.Contains(s, "N/A") || strings.HasPrefix(s, "[") {
		return nil
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return nil
	}
	return &v
}

func nvBytes(s string) *int64 {
	v := nvNum(s)
	if v == nil {
		return nil
	}
	b := int64(*v * mib)
	return &b
}

// ParseNvidiaGPULine parses one line of `nvidia-smi --query-gpu=GPUQuery --format=csv,noheader,nounits`.
func ParseNvidiaGPULine(line string) (GPU, bool) {
	r := csv.NewReader(strings.NewReader(line))
	r.TrimLeadingSpace = true
	f, err := r.Read()
	if err != nil || len(f) < 8 {
		return GPU{}, false
	}
	idx, err := strconv.Atoi(strings.TrimSpace(f[0]))
	if err != nil {
		return GPU{}, false
	}
	g := GPU{Index: idx, UUID: strings.TrimSpace(f[1]), Name: strings.TrimSpace(f[2]), Vendor: "nvidia",
		UtilPercent: nvNum(f[3]), VRAMUsed: nvBytes(f[4]), VRAMTotal: nvBytes(f[5]), TempC: nvNum(f[6])}
	if p := nvNum(f[7]); p != nil {
		g.PowerW = P(Round(*p, 1))
	}
	if g.Name == "" {
		g.Name = "NVIDIA GPU"
	}
	return g, true
}

// ParseComputeApps parses `--query-compute-apps=pid,gpu_uuid,used_memory --format=csv,noheader,nounits` into
// pid -> VRAM bytes per GPU index (Windows in WDDM mode reports [N/A]: those rows are skipped).
func ParseComputeApps(out []byte, uuidIndex map[string]int, nGPU int) map[int][]int64 {
	res := map[int][]int64{}
	r := csv.NewReader(bytes.NewReader(out))
	r.TrimLeadingSpace = true
	r.FieldsPerRecord = -1
	for {
		f, err := r.Read()
		if err != nil {
			break
		}
		if len(f) < 3 {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(f[0]))
		mem := nvBytes(f[2])
		idx, ok := uuidIndex[strings.TrimSpace(f[1])]
		if err != nil || mem == nil || !ok || idx < 0 || idx >= nGPU {
			continue
		}
		if res[pid] == nil {
			res[pid] = make([]int64, nGPU)
		}
		res[pid][idx] += *mem
	}
	return res
}

// NvidiaSMI keeps one looping nvidia-smi running and remembers the latest line per GPU.
type NvidiaSMI struct {
	Path     string
	Interval time.Duration

	mu     sync.Mutex
	latest map[int]GPU
	seen   map[int]time.Time
	apps   map[int][]int64
	appsAt time.Time
}

// NewNvidiaSMI returns a reader for the nvidia-smi at path ("" = none: GPUs() is always empty).
func NewNvidiaSMI(path string, interval time.Duration) *NvidiaSMI {
	if interval < time.Second {
		interval = 2 * time.Second
	}
	return &NvidiaSMI{Path: path, Interval: interval, latest: map[int]GPU{}, seen: map[int]time.Time{}}
}

// Run keeps nvidia-smi running until ctx ends, restarting it with a growing pause when it exits.
func (n *NvidiaSMI) Run(ctx context.Context) {
	if n == nil || n.Path == "" {
		return
	}
	backoff := 10 * time.Second
	for ctx.Err() == nil {
		start := time.Now()
		err := n.runOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		if time.Since(start) > 5*time.Minute {
			backoff = 10 * time.Second
		}
		slog.Warn("nvidia-smi stopped; retrying", "error", errString(err), "in", backoff.String())
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 10*time.Minute)
	}
}

func errString(err error) string {
	if err == nil {
		return "exited"
	}
	return err.Error()
}

func (n *NvidiaSMI) runOnce(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, n.Path, "--query-gpu="+GPUQuery, "--format=csv,noheader,nounits",
		"-lms", strconv.Itoa(int(n.Interval/time.Millisecond)))
	cmd.SysProcAttr = lowPriority()
	cmd.Env = minimalEnv()
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return err
	}
	sc := bufio.NewScanner(out)
	for sc.Scan() {
		if g, ok := ParseNvidiaGPULine(sc.Text()); ok {
			n.mu.Lock()
			n.latest[g.Index] = g
			n.seen[g.Index] = time.Now()
			n.mu.Unlock()
		}
	}
	err = cmd.Wait()
	if err == nil {
		err = errors.New("exited")
	}
	return err
}

// GPUs returns the GPUs seen within the last three intervals, by index.
func (n *NvidiaSMI) GPUs() []GPU {
	if n == nil {
		return nil
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	var out []GPU
	for i := 0; i < 64; i++ {
		g, ok := n.latest[i]
		if !ok {
			continue
		}
		if time.Since(n.seen[i]) > 3*n.Interval+2*time.Second {
			continue
		}
		out = append(out, g)
	}
	return out
}

// ComputeApps returns pid -> VRAM bytes per GPU index (cached for two seconds; nil without GPUs).
func (n *NvidiaSMI) ComputeApps(ctx context.Context) map[int][]int64 {
	gpus := n.GPUs()
	if len(gpus) == 0 {
		return nil
	}
	n.mu.Lock()
	if time.Since(n.appsAt) < 2*time.Second {
		a := n.apps
		n.mu.Unlock()
		return a
	}
	n.mu.Unlock()
	uuidIndex := map[string]int{}
	maxIdx := 0
	for _, g := range gpus {
		uuidIndex[g.UUID] = g.Index
		maxIdx = max(maxIdx, g.Index)
	}
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, n.Path, "--query-compute-apps=pid,gpu_uuid,used_memory", "--format=csv,noheader,nounits")
	cmd.SysProcAttr = lowPriority()
	cmd.Env = minimalEnv()
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	apps := ParseComputeApps(out, uuidIndex, maxIdx+1)
	n.mu.Lock()
	n.apps, n.appsAt = apps, time.Now()
	n.mu.Unlock()
	return apps
}
