package hook

import (
	"context"
	"sync/atomic"
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
// 64 KiB buffer. walkFloor is a third, and only where the budget was spent
// before the walk was through.
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

// budget is how long the scan gets before the hook stops waiting for it.
//
// It is the timeout minus the margin rather than a number of its own, because
// the quantity that matters is the distance between them: every second the
// budget takes is a second in which a scan that has not finished can still say
// so, and every second the margin takes is a second of scanning given up for
// nothing.
//
// A scan that overruns it blocks on a finding in what it got through, and
// otherwise defers with a coverage record; overran in verdict.go says why the
// budget outlived the block, and hook.go argues the deferral at its branch.
// Past the timeout the process is killed, whatever it was going to say is
// discarded, and the call proceeds -- measured on both events, and no exit code
// reaches it, because a killed process writes none. So what the budget buys is
// not a block. It is a record, or a block on what was read, where the
// alternative is an allow whose only trace is a hook_cancelled attachment
// fifteen seconds later.
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

// walkFloor is how long the walk gets when the budget leaves it less, which it
// takes out of the margin. A refusal comes out of the walk and needs no buffer
// read, so a budget spent before the walk began, or ending just after, would
// otherwise defer an `env` dump that a walk of microseconds decides (Q270).
//
// The slowest of 211,428 Bash walks replayed from this machine's transcripts
// on 2026-11-27 took 408ms, so the floor is two and a half times that. It
// leaves fourteen seconds of the margin for the verdict, against the 0.39s
// the margin's own measurement puts on the worst case.
const walkFloor = time.Second

// What pace hears as the walk starts and when it reaches a refusal, which are
// the two points inside the walk a test can stop it at.
const (
	walkLabel    = "<walk>"
	refusedLabel = "<refused>"
)

// reached tells reach of a refusal, if anyone is listening.
func reached(reach func(error), err error) {
	if reach != nil {
		reach(err)
	}
}

// walk runs targets under the deadline within runs the scan under, or under
// walkFloor where that is later, and reports whether the walk finished.
//
// A walk that did not finish hands back the first refusal it reached, as the
// error, and no buffers: the refusal is settled when reached, and the rest of
// the walk -- a glob over a home directory was driven at 206s -- has no bearing
// on it. With settle set, which is a call nobody overrode, it hands the refusal
// back the moment it is reached rather than at the deadline, because the
// buffers past it would be read only for a confirmation. A walk that reached none hands back nothing, and the call defers with
// a record, as a scan the deadline ran out on does. A walk with no bound is
// killed at the hook's timeout instead, and writes nothing.
//
// The goroutine is left running for within's reason.
func walk(ctx context.Context, pace func(label string), call payload, event Event, left time.Duration, settle bool) ([]target, error, bool) {
	type walked struct {
		buffers []target
		gap     error
	}
	var first atomic.Pointer[error]
	refused := make(chan struct{})
	done := make(chan walked, 1)
	go func() {
		pace(walkLabel)
		buffers, gap := targets(call, event, func(err error) {
			if first.CompareAndSwap(nil, &err) {
				close(refused)
				pace(refusedLabel)
			}
		})
		done <- walked{buffers, gap}
	}()
	deadline, cancel := context.WithTimeout(ctx, left)
	defer cancel()
	floor := time.NewTimer(walkFloor)
	defer floor.Stop()
	ended, floored := deadline.Done(), floor.C
	reached := (<-chan struct{})(nil)
	if settle {
		reached = refused
	}
	for ended != nil || floored != nil {
		select {
		case w := <-done:
			return w.buffers, w.gap, true
		case <-reached:
			return nil, *first.Load(), false
		case <-ended:
			ended = nil
		case <-floored:
			floored = nil
		}
	}
	if err := first.Load(); err != nil {
		return nil, *err, false
	}
	return nil, nil, false
}

// A scanned is what scanCall made of a call, boxed so that the goroutine below
// can hand back all three at once. err is unset on what is gathered partway.
type scanned struct {
	findings []scan.Finding
	skips    []skipped
	err      error
}

// within runs scanCall under a deadline and reports whether the scan finished
// ahead of it. A budget already spent does not reach scanCall at all, for the
// reason below.
//
// A deadline that fires hands back what the scan had settled by then. That is
// every buffer it got through, and in the buffer still running, every finding
// whose rule had finished with it: a finding in that buffer is stored when its
// rule is through, not when the last rule is. What a rule still running would
// have found is not in it. The scan's goroutine goes on writing while this one
// reads, so each result sits in its own atomic slot, and a stored result is
// replaced rather than changed.
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
func within(ctx context.Context, pace func(label string), buffers []target, gap error, event Event, left time.Duration) (scanned, bool) {
	// A budget already spent is answered here rather than below, because the
	// select cannot answer it twice the same way. Both of its cases are ready
	// at once in that case -- the timer from the first instant, the scan as
	// soon as a six-byte file is through the match loop -- and Go chooses
	// among ready cases uniformly at random, so the same call could defer on
	// one invocation and decide on the next. Measured at 50.2% once the scan
	// reaches the channel first, and 0% otherwise.
	//
	// It is also the answer on the merits, which is what makes it a rule
	// rather than a coin weighted towards the reading a test wanted. The
	// margin past the budget is sized to write one verdict and nothing else,
	// so time past the budget is not scanning time: the only clock such a
	// scan could race is one that expired before it began, and the process is
	// killed at most fifteen seconds later whatever it found -- fifteen is the
	// margin, so a budget spent by more than nothing leaves less. Nothing was
	// read, and that is what gets reported.
	if left <= 0 {
		return scanned{}, false
	}
	ctx, cancel := context.WithTimeout(ctx, left)
	defer cancel()
	var settle atomic.Pointer[func() scanned]
	done := make(chan scanned, 1)
	go func() {
		findings, skips, err := scanCall(buffers, gap, event, pace, func(s func() scanned) { settle.Store(&s) })
		done <- scanned{findings, skips, err}
	}()
	select {
	case got := <-done:
		return got, true
	case <-ctx.Done():
		if s := settle.Load(); s != nil {
			return (*s)(), false
		}
		return scanned{}, false
	}
}
