// Package configutil holds the small config helpers the panel and fairy-agent share: the id rule for systems,
// agents, power sources and UPSes, and secrets referenced by environment variable name.
package configutil

import (
	"fmt"
	"os"
	"regexp"
)

var systemIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// ValidID reports whether s is a valid id for a system, agent, power source or UPS: lowercase letters, digits
// and dashes, starting with a letter or digit, at most 63 characters.
func ValidID(s string) bool { return systemIDRe.MatchString(s) }

// EnvSecret resolves a secret referenced by env-var name.
func EnvSecret(name, what string, minLen int) (string, error) {
	if name == "" {
		return "", nil
	}
	v := os.Getenv(name)
	if len(v) < max(minLen, 1) {
		return "", fmt.Errorf("%s: env var %s is missing or shorter than %d chars", what, name, max(minLen, 1))
	}
	return v, nil
}
