package hook

import (
	"time"

	"github.com/karlkfi/claude-spill-guard/internal/scan"
)

// hookTimeout is what hooks/hooks.json gives this process, mirrored here
// because nothing else links the two: this binary never reads that file, and
// the number the budget below has to stay under is written in it.
// TestTheBudgetFitsInsideTheTimeoutTheManifestGives holds the two together.
const hookTimeout = 60 * time.Second

// margin is what the budget leaves of that timeout, and it is the whole of
// what this process needs in order to say anything at all.
//
// Two things are charged to it. Everything before the clock starts -- the
// shell, the launcher, this binary's own startup -- and everything after it
// stops, which is one JSON object of a few hundred bytes onto a pipe with a
// 64 KiB buffer.
//
// Measured 2026-09-04 on an M5 Max, warm, on a machine already carrying other
// work. A hook invocation over a payload naming no file, driven through the
// shell and the launcher the way Claude Code drives it: 7.02ms at best over 30
// runs, 7.49ms median, and one 350ms outlier. The verdict after the deadline
// fires, timed from inside over a 64 MiB buffer at four budgets: under 10ms
// idle, and under 37ms with twice as many CPU-bound goroutines running as the
// machine has cores. The two worst readings together are 0.39s, and the margin
// is forty times that.
//
// It is not sized to those numbers. It is sized so that being wrong about them
// costs nothing, because the thing they cannot bound is scheduling on somebody
// else's machine: Go preempts a goroutine in a tight match loop asynchronously,
// so the timer does not wait for the scan to yield -- driven,
// TestTheDeadlineFiresWhileTheMatchLoopIsRunning -- and a saturated machine
// still wakes it late by an amount no measurement here generalises to.
const margin = 15 * time.Second

// budget is how long the scan gets before it stops and blocks.
//
// It is the timeout minus the margin rather than a number of its own, because
// the quantity that matters is the distance between them: every second the
// budget takes is a second in which a scan that has not finished can still say
// so, and every second the margin takes is a second of scanning given up for
// nothing.
//
// A scan that overruns it blocks, which is the only verdict that keeps this
// tool's promise. Past the timeout the process is killed, whatever it was going
// to say is discarded, and the call proceeds -- measured on both events, and no
// exit code reaches it, because a killed process writes none. So the choice is
// not between blocking and allowing. It is between blocking and allowing
// silently fifteen seconds later.
//
// What it costs is the calls that would have finished between 45 and 60
// seconds. At the worst rate measured before rules ran at their keyword
// positions -- 6.5 MiB/s, text carrying every keyword the ruleset gates on --
// that was a call adding up to between 293 and 390 MiB on the machine those
// figures were taken on. The same fixture now runs 5.8x faster, which moves the
// band up rather than changing what it is, and nothing in the two populations
// this repo has counted came near either end of the old one: nothing outside
// `.git` in this worktree exceeds 5 MiB, and the largest session transcript on
// the author's machine is 35.4 MiB. docs/design/README.md, "The scanner's own
// budget", has the table and what a slower machine does to it.
const budget = hookTimeout - margin

// A scanned is what scanCall made of a call, boxed so that the goroutine below
// can hand back all three at once.
type scanned struct {
	findings []scan.Finding
	skips    []skipped
	err      error
}

// within runs scanCall under a deadline and reports whether it reached one.
//
// Nothing here interrupts the work. os.ReadFile takes no context and neither
// does the match loop, which is why the goroutine is left running rather than
// cancelled -- fifo_unix_test.go says the same sentence about the same call for
// the file-mode question, and it is why a fifo had to be refused up front
// instead of read with a limit. A deadline cannot cut the read short. It can
// only outrun it, write the verdict, and let the process exit take the
// goroutine with it.
//
// So this is a hard deadline over soft work, and the leak is bounded by the
// process rather than by the scan: `hook` writes one verdict and returns, and
// the runtime collects everything on the way out. In a test, which is the one
// caller that outlives a verdict, the goroutine finishes the buffer it was
// given and exits on its own.
func within(call payload, event Event, left time.Duration) (scanned, bool) {
	done := make(chan scanned, 1)
	go func() {
		findings, skips, err := scanCall(call, event)
		done <- scanned{findings, skips, err}
	}()
	timer := time.NewTimer(left)
	defer timer.Stop()
	select {
	case got := <-done:
		return got, true
	case <-timer.C:
		return scanned{}, false
	}
}
