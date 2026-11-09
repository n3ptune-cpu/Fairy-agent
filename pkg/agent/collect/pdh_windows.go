//go:build windows

package collect

// A minimal PDH (Performance Data Helper) reader: one wildcard counter, formatted as doubles. PDH is the
// documented user-mode API behind Performance Monitor.

import (
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	pdh                             = windows.NewLazySystemDLL("pdh.dll")
	procPdhOpenQueryW               = pdh.NewProc("PdhOpenQueryW")
	procPdhAddEnglishCounterW       = pdh.NewProc("PdhAddEnglishCounterW")
	procPdhCollectQueryData         = pdh.NewProc("PdhCollectQueryData")
	procPdhGetFormattedCounterArray = pdh.NewProc("PdhGetFormattedCounterArrayW")
	procPdhCloseQuery               = pdh.NewProc("PdhCloseQuery")
)

const (
	pdhFmtDouble = 0x00000200
	pdhMoreData  = 0x800007D2
	// PDH_CANNOT_READ_NAME_STRINGS: this account may not read the counters' names (the Perflib registry key
	// grants Administrators, SYSTEM, INTERACTIVE, Performance Monitor Users and Performance Log Users; a
	// service's virtual account is none of these unless added to a group).
	pdhCannotReadNameStrings = 0xC0000BC8
)

// pdhError is a PDH status from adding a counter.
type pdhError struct{ status uint32 }

func (e pdhError) Error() string {
	return fmt.Sprintf("counter not available (PDH status 0x%08X)", e.status)
}

// CounterAccessFix is what to do when the agent's account may not read performance counters.
const CounterAccessFix = `NT SERVICE\fairy-agent must be a member of the local group "Performance Monitor Users" (SID S-1-5-32-558; ` +
	`read access to performance counters only): fairy-agent setup-self-update (Administrator) or the next update ` +
	`through the panel adds it and restarts the agent; by hand: net localgroup "Performance Monitor Users" ` +
	`"NT SERVICE\fairy-agent" /add, then Restart-Service fairy-agent`

var counterAccessOnce sync.Once

// NoteCounterAccess reports whether err means this account may not read performance counters at all, and
// then logs one warning (once per process) that names the fix: GPU load, VRAM in use, per-process GPU memory
// and the ACPI temperatures stay unknown until then. Group membership counts from the next start of the
// service (a new token), so trying again in this process does not help.
func NoteCounterAccess(err error) bool {
	var pe pdhError
	if !errors.As(err, &pe) || pe.status != pdhCannotReadNameStrings {
		return false
	}
	counterAccessOnce.Do(func() {
		slog.Warn("performance counters not readable by this account (PDH status 0xC0000BC8, the counter names): "+
			"GPU load, VRAM in use, per-process GPU memory and ACPI temperatures unknown", "fix", CounterAccessFix)
	})
	return true
}

// pdhItem is PDH_FMT_COUNTERVALUE_ITEM_W with a double value (64-bit layout).
type pdhItem struct {
	Name    *uint16
	CStatus uint32
	_       uint32
	Value   float64
}

type pdhQuery struct {
	query, counter uintptr
}

type pdhValue struct {
	name  string
	value float64
}

func newPDHQuery(path string) (*pdhQuery, error) {
	q := &pdhQuery{}
	if r, _, _ := procPdhOpenQueryW.Call(0, 0, uintptr(unsafe.Pointer(&q.query))); r != 0 {
		return nil, errors.New("PdhOpenQuery failed")
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	if r, _, _ := procPdhAddEnglishCounterW.Call(q.query, uintptr(unsafe.Pointer(p)), 0, uintptr(unsafe.Pointer(&q.counter))); r != 0 {
		procPdhCloseQuery.Call(q.query)
		return nil, pdhError{status: uint32(r)}
	}
	return q, nil
}

func (q *pdhQuery) values() ([]pdhValue, error) {
	if r, _, _ := procPdhCollectQueryData.Call(q.query); r != 0 {
		return nil, errors.New("PdhCollectQueryData failed")
	}
	var size, count uint32
	r, _, _ := procPdhGetFormattedCounterArray.Call(q.counter, pdhFmtDouble, uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&count)), 0)
	if uint32(r) != pdhMoreData || size == 0 {
		return nil, fmt.Errorf("no instances (PDH status 0x%08X)", uint32(r))
	}
	var buf []byte
	// the size can grow between the two calls (GPU Engine has an instance per process and engine, often
	// a thousand, coming and going): ask again with what PDH says it needs now
	for try := 0; ; try++ {
		buf = make([]byte, size)
		count = 0
		r, _, _ = procPdhGetFormattedCounterArray.Call(q.counter, pdhFmtDouble, uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&count)), uintptr(unsafe.Pointer(&buf[0])))
		if r == 0 {
			break
		}
		if uint32(r) != pdhMoreData || try >= 3 || size == 0 || size > 64<<20 {
			return nil, fmt.Errorf("PdhGetFormattedCounterArray: PDH status 0x%08X", uint32(r))
		}
	}
	if uintptr(count)*unsafe.Sizeof(pdhItem{}) > uintptr(len(buf)) {
		return nil, errors.New("PdhGetFormattedCounterArray: more items than fit")
	}
	items := unsafe.Slice((*pdhItem)(unsafe.Pointer(&buf[0])), count)
	out := make([]pdhValue, 0, count)
	for _, it := range items {
		if it.CStatus != 0 && it.CStatus != 1 { // PDH_CSTATUS_VALID_DATA / NEW_DATA
			continue
		}
		out = append(out, pdhValue{name: windows.UTF16PtrToString(it.Name), value: it.Value})
	}
	return out, nil
}
