//go:build windows

package collect

// A minimal PDH (Performance Data Helper) reader: one wildcard counter, formatted as doubles. PDH is the
// documented user-mode API behind Performance Monitor.

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	pdh                             = windows.NewLazySystemDLL("pdh.dll")
	procPdhOpenQueryW               = pdh.NewProc("PdhOpenQueryW")
	procPdhAddEnglishCounterW       = pdh.NewProc("PdhAddEnglishCounterW")
	procPdhCollectQueryData         = pdh.NewProc("PdhCollectQueryData")
	procPdhGetFormattedCounterArray = pdh.NewProc("PdhGetFormattedCounterArrayW")
)

const (
	pdhFmtDouble = 0x00000200
	pdhMoreData  = 0x800007D2
)

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
		return nil, errors.New("counter not available")
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
		return nil, errors.New("no instances")
	}
	buf := make([]byte, size)
	r, _, _ = procPdhGetFormattedCounterArray.Call(q.counter, pdhFmtDouble, uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&count)), uintptr(unsafe.Pointer(&buf[0])))
	if r != 0 {
		return nil, errors.New("PdhGetFormattedCounterArray failed")
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
