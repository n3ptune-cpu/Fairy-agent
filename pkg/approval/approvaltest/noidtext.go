package approvaltest

import (
	"fmt"
	"strings"
)

// NoIDHint ends the error text of a trust file without machine id whose id could not be added.
const NoIDHint = " (the file is as it was; repair on the machine: fairy-agent helper-trust set)"

// NoIDTextProblem holds such an error text (got) against the rule for it, for the trust file at path and the
// reason why, and says what is wrong ("": nothing). The rule (approval.Gate's look at the file): the path and
// what failed come first; the whole text has at most 300 characters; while the path leaves room (it has at
// most 160 characters) the text ends with the hint, and the reason before it is whole when everything fits
// and otherwise as much of it as fits, ending in "...".
//
// The file's path is part of the text, and the path of a test's folder is as long as TMPDIR makes it. A test
// that compares with the whole text passes under /tmp and fails under a longer TMPDIR (second review of
// ae9384f..5a6658c: two tests, from 16 characters on). This check does not depend on the path's length.
func NoIDTextProblem(got, path, why string) string {
	const pre, limit = ": the trust file has no machine_id, and adding one failed: ", 300
	whole := path + pre + why + NoIDHint
	switch {
	case len(got) > limit:
		return fmt.Sprintf("the text has %d characters, an answer holds %d", len(got), limit)
	case len(whole) <= limit:
		if got != whole {
			return "everything fits, so the text should be: " + whole
		}
	case len(path) > 160: // no room for a reason: the text is cut where the answer ends
		if got != whole[:limit] {
			return "want the first 300 characters of: " + whole
		}
	default:
		if !strings.HasPrefix(got, path+pre) || !strings.HasSuffix(got, "..."+NoIDHint) || len(got) != limit {
			return "want the path, what failed, the reason cut with \"...\" and the hint, 300 characters in all"
		}
		if reason := got[len(path)+len(pre) : len(got)-len("..."+NoIDHint)]; reason == "" || !strings.HasPrefix(why, reason) {
			return fmt.Sprintf("the cut reason %q is not the beginning of %q", reason, why)
		}
	}
	return ""
}
