package safety

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPool_ExecutesSubmittedJobs(t *testing.T) {
	p := New(4, 16)
	var count atomic.Int32
	var wg sync.WaitGroup
	wg.Add(10)
	for i := 0; i < 10; i++ {
		ok := p.Submit(func() {
			count.Add(1)
			wg.Done()
		})
		if !ok {
			t.Fatalf("expected job to be accepted, queue should have room")
		}
	}
	wg.Wait()
	if got := count.Load(); got != 10 {
		t.Fatalf("expected 10 jobs executed, got %d", got)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	p.Shutdown(ctx)
}

func TestPool_PanicInJobDoesNotKillWorker(t *testing.T) {
	// This is the property internal/safety.runSafely exists for: one
	// misbehaving job (simulating a buggy detection engine) must never
	// take down the worker goroutine, and with it, every other job's
	// ability to run.
	p := New(1, 4)
	var after atomic.Bool
	done := make(chan struct{})

	if ok := p.Submit(func() { panic("simulated engine bug") }); !ok {
		t.Fatalf("expected panicking job to be accepted")
	}
	if ok := p.Submit(func() {
		after.Store(true)
		close(done)
	}); !ok {
		t.Fatalf("expected follow-up job to be accepted")
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("worker appears to have died after a panic; follow-up job never ran")
	}
	if !after.Load() {
		t.Fatalf("expected follow-up job to have executed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	p.Shutdown(ctx)
}

func TestPool_DropsWhenQueueFull(t *testing.T) {
	// Zero workers isn't allowed (clamped to 1), so block the single
	// worker on a job that won't finish until the test releases it, then
	// fill the (small) queue and confirm additional submissions are
	// dropped rather than blocking the caller or growing without bound.
	release := make(chan struct{})
	p := New(1, 1)

	if ok := p.Submit(func() { <-release }); !ok {
		t.Fatalf("expected first (blocking) job to be accepted")
	}
	// Give the worker a moment to actually start executing the blocking
	// job so the queue itself is empty and available to fill next.
	time.Sleep(50 * time.Millisecond)

	if ok := p.Submit(func() {}); !ok {
		t.Fatalf("expected second job to fill the 1-capacity queue")
	}
	// Queue is now full (capacity 1, one job already enqueued) and the
	// worker is busy — a third submission must be dropped, not block.
	if ok := p.Submit(func() {}); ok {
		t.Fatalf("expected third job to be dropped (queue full)")
	}
	if got := p.Dropped(); got != 1 {
		t.Fatalf("expected Dropped()==1, got %d", got)
	}

	close(release)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	p.Shutdown(ctx)
}

func TestNew_ClampsInvalidConfig(t *testing.T) {
	// A misconfigured pool (zero or negative workers/queue capacity) must
	// still be able to make progress rather than silently becoming
	// unusable — New clamps both to at least 1.
	p := New(0, 0)
	done := make(chan struct{})
	if ok := p.Submit(func() { close(done) }); !ok {
		t.Fatalf("expected pool with clamped config to still accept a job")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatalf("clamped pool never executed the job")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	p.Shutdown(ctx)
}
