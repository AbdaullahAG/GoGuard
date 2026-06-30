// Package safety provides concurrency primitives whose entire purpose is
// resource-exhaustion defense, not raw performance.
package safety

import (
	"context"
	"sync"
	"sync/atomic"
)

// Job is a unit of packet-processing work.
type Job func()

// Pool runs Jobs across a fixed number of workers backed by a bounded
// channel.
//
// Security rationale: without a bound, a fast enough attacker — or just an
// ordinary traffic spike — can grow an unbounded queue without limit and
// exhaust memory. When the queue is full, Submit drops the job instead of
// blocking the capture loop or growing without bound. Dropping packets
// under overload is the correct fail-safe behaviour for an IDS; silently
// queuing forever, or blocking capture, is not.
type Pool struct {
	jobs    chan Job
	wg      sync.WaitGroup
	dropped atomic.Uint64
}

// New starts a pool with the given number of workers and a queue of
// capacity queueCap. Both are clamped to at least 1 so a misconfiguration
// can't accidentally create a pool that can never make progress.
func New(workers, queueCap int) *Pool {
	if workers < 1 {
		workers = 1
	}
	if queueCap < 1 {
		queueCap = 1
	}
	p := &Pool{jobs: make(chan Job, queueCap)}
	for i := 0; i < workers; i++ {
		p.wg.Add(1)
		go p.worker()
	}
	return p
}

func (p *Pool) worker() {
	defer p.wg.Done()
	for job := range p.jobs {
		runSafely(job)
	}
}

// runSafely is a defense-in-depth backstop, not a substitute for correct
// code. A panic recovered here indicates a real bug — most likely in a
// detection engine — that should be fixed. But one misbehaving engine must
// never be allowed to kill the worker goroutine, and with it, the whole
// packet-processing pipeline for every other engine.
func runSafely(job Job) {
	defer func() {
		_ = recover() // intentionally swallowed here; wire to telemetry in production
	}()
	job()
}

// Submit enqueues job if there is room, or drops it immediately and counts
// the drop if the queue is full. The returned bool reports whether the job
// was accepted.
func (p *Pool) Submit(job Job) bool {
	select {
	case p.jobs <- job:
		return true
	default:
		p.dropped.Add(1)
		return false
	}
}

// Dropped returns the total number of jobs dropped due to a full queue.
// Export this as a metric — a rising drop count under normal traffic is a
// capacity signal, not a bug, and should page someone before it becomes one.
func (p *Pool) Dropped() uint64 {
	return p.dropped.Load()
}

// Shutdown stops accepting new jobs and waits for in-flight jobs to finish,
// or for ctx to be cancelled, whichever happens first.
func (p *Pool) Shutdown(ctx context.Context) {
	close(p.jobs)
	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
}
