package winpipe

import (
	"errors"
	"strings"
	"testing"
)

// The agent knows the helper by its process id only; the pipe's owner is looked at too. In this release the
// look only reports (the rule "the helper's pipe belongs to SYSTEM or Administrators" has not been seen on a
// real PC, and a wrong guess would cut every agent off from its helper); with Enforce it refuses.
func TestOwnerCheck(t *testing.T) {
	const (
		pipe = `\\.\pipe\fairy-agent-helper`
		user = "S-1-5-21-1111111111-2222222222-3333333333-1001"
	)
	denied := errors.New("Access is denied.")
	type look struct {
		owner string
		err   error
	}
	expected := []look{{sidSystem, nil}, {sidAdministrators, nil}}
	strange := []look{
		{user, nil},                 // a program of an ordinary user took the name and its process id was used again
		{"S-1-5-19", nil},           // LocalService
		{"S-1-5-80-1-2-3-4-5", nil}, // another service's account (also Fairy's own agent, were it to make such a pipe)
		{"", nil},                   // no owner
		{"", denied},                // the pipe does not let its owner be read
		{sidSystem, errors.New("The handle is invalid.")}, // what could not be read is not known
	}

	for _, enforce := range []bool{false, true} {
		var warned []string
		c := &OwnerCheck{Enforce: enforce, Warn: func(m string) { warned = append(warned, m) }}
		if c.Owner() != "" {
			t.Fatal("an owner before the first look")
		}
		// the helper's own pipe: used, nothing said, in both modes
		for _, l := range expected {
			for i := 0; i < 3; i++ {
				if err := c.Decide(pipe, l.owner, l.err); err != nil {
					t.Fatalf("enforce %v: the helper's own pipe (owner %s) refused: %v", enforce, l.owner, err)
				}
			}
			if c.Owner() != l.owner {
				t.Fatalf("Owner() = %q", c.Owner())
			}
		}
		if len(warned) != 0 {
			t.Fatalf("enforce %v: a warning about the helper's own pipe: %v", enforce, warned)
		}
		for _, l := range strange {
			warned = nil
			var err error
			for i := 0; i < 5; i++ { // the agent asks the helper every few seconds: one warning, not one a call
				err = c.Decide(pipe, l.owner, l.err)
			}
			if len(warned) != 1 {
				t.Fatalf("enforce %v, owner %q (%v): %d warnings, want one: %v", enforce, l.owner, l.err, len(warned), warned)
			}
			w := warned[0]
			if !strings.Contains(w, pipe) || !strings.Contains(w, "SYSTEM or Administrators") || !strings.Contains(w, "require_helper_pipe_owner") {
				t.Errorf("enforce %v: the warning does not say what it is about: %s", enforce, w)
			}
			if l.err == nil && l.owner != "" && !strings.Contains(w, l.owner) {
				t.Errorf("the warning does not name the owner %s: %s", l.owner, w)
			}
			if (l.err != nil || l.owner == "") && !strings.Contains(w, "cannot be read") {
				t.Errorf("the warning does not say the owner could not be read: %s", w)
			}
			if enforce {
				// refused, as a pipe that is not the helper's
				if !errors.Is(err, ErrNotHelper) || !strings.Contains(w, "is not used") {
					t.Errorf("enforcing, owner %q (%v): %v / %s", l.owner, l.err, err, w)
				}
				continue
			}
			// observe only: never refused, and the warning says so and how to make it strict
			if err != nil || !strings.Contains(w, "used all the same") || !strings.Contains(w, "require_helper_pipe_owner: true") {
				t.Errorf("observing, owner %q (%v): %v / %s", l.owner, l.err, err, w)
			}
		}
		if got := c.Owner(); !strings.HasPrefix(got, "unknown (") {
			t.Errorf("Owner() after an owner that could not be read: %q", got)
		}
	}

	// no check at all (nil), and one without a Warn function: nothing is refused, nothing panics
	var none *OwnerCheck
	if err := none.Decide(pipe, user, nil); err != nil || none.Owner() != "" {
		t.Fatal(err)
	}
	quiet := &OwnerCheck{}
	if err := quiet.Decide(pipe, user, nil); err != nil || quiet.Owner() != user {
		t.Fatal(err, quiet.Owner())
	}
	if err := (&OwnerCheck{Enforce: true}).Decide(pipe, user, nil); !errors.Is(err, ErrNotHelper) {
		t.Fatal(err)
	}
}
