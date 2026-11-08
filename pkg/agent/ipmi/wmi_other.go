//go:build !windows

package ipmi

import (
	"errors"
	"time"
)

// NewWMI is only available on Windows.
func NewWMI(time.Duration) (Transport, error) {
	return nil, errors.New("the wmi IPMI transport is only available on Windows")
}
