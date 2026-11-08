package devices

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Describe returns a short, secret-free reason string (never includes headers or URLs).
func Describe(err error) string {
	if err == nil {
		return ""
	}
	var de *Error
	if errors.As(err, &de) {
		return de.Msg
	}
	var he *HTTPStatusError
	if errors.As(err, &he) {
		return fmt.Sprintf("http %d", he.Code)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout"
	}
	msg := err.Error()
	if strings.Contains(msg, "certificate") || strings.Contains(msg, "x509") {
		return "tls verification failed"
	}
	var se *json.SyntaxError
	var ue *json.UnmarshalTypeError
	if errors.As(err, &se) || errors.As(err, &ue) || errors.Is(err, strconv.ErrSyntax) {
		return "invalid response"
	}
	var oe *net.OpError
	if errors.As(err, &oe) {
		return "connection failed"
	}
	if strings.Contains(msg, "connection refused") || strings.Contains(msg, "no route") || strings.Contains(msg, "EOF") {
		return "connection failed"
	}
	return "error"
}
