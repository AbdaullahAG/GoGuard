package signature

import (
	"sync"
	"testing"

	"ids-ips/pkg/types"
)

func TestEngine_MatchesConfiguredPattern(t *testing.T) {
	e := New([]Rule{
		{ID: "r1", Pattern: []byte("evil"), Severity: types.SeverityHigh, Reason: "test rule"},
	})
	pkt := types.Packet{Payload: []byte("this payload contains evil content")}

	f, ok := e.Inspect(pkt)
	if !ok {
		t.Fatalf("expected a match")
	}
	if f.Severity != types.SeverityHigh {
		t.Fatalf("expected severity to come from the matched rule, got %v", f.Severity)
	}
	if f.Reason == "" {
		t.Fatalf("expected a human-readable reason for explainability")
	}
}

func TestEngine_NoMatchOnCleanPayload(t *testing.T) {
	e := New([]Rule{{ID: "r1", Pattern: []byte("evil"), Severity: types.SeverityHigh}})
	pkt := types.Packet{Payload: []byte("perfectly ordinary traffic")}

	if _, ok := e.Inspect(pkt); ok {
		t.Fatalf("did not expect a match on clean payload")
	}
}

func TestEngine_EmptyPatternNeverMatches(t *testing.T) {
	// An empty pattern would otherwise match bytes.Contains(anything, "")
	// == true for every single packet — a rule-authoring mistake that
	// must not silently become "block all traffic".
	e := New([]Rule{{ID: "bad-rule", Pattern: nil, Severity: types.SeverityCritical}})
	pkt := types.Packet{Payload: []byte("totally normal traffic")}

	if _, ok := e.Inspect(pkt); ok {
		t.Fatalf("empty pattern must never match")
	}
}

func TestEngine_SetRulesHotSwapsAtomically(t *testing.T) {
	e := New([]Rule{{ID: "r1", Pattern: []byte("old"), Severity: types.SeverityLow}})
	if _, ok := e.Inspect(types.Packet{Payload: []byte("old stuff")}); !ok {
		t.Fatalf("expected initial rule to match before swap")
	}

	e.SetRules([]Rule{{ID: "r2", Pattern: []byte("new"), Severity: types.SeverityLow}})

	if _, ok := e.Inspect(types.Packet{Payload: []byte("old stuff")}); ok {
		t.Fatalf("old rule must no longer match after SetRules")
	}
	if _, ok := e.Inspect(types.Packet{Payload: []byte("new stuff")}); !ok {
		t.Fatalf("new rule must match after SetRules")
	}
	if got := e.RuleCount(); got != 1 {
		t.Fatalf("expected RuleCount()==1 after swap, got %d", got)
	}
}

func TestEngine_SetRulesDefensiveCopy(t *testing.T) {
	rules := []Rule{{ID: "r1", Pattern: []byte("x"), Severity: types.SeverityLow}}
	e := New(rules)

	// Mutating the caller's original slice after construction must not
	// change engine behaviour — New and SetRules both take defensive
	// copies specifically to prevent this class of bug.
	rules[0].Pattern = []byte("mutated")

	if _, ok := e.Inspect(types.Packet{Payload: []byte("x")}); !ok {
		t.Fatalf("expected engine to still match on the original pattern, unaffected by caller mutation")
	}
}

func TestEngine_ConcurrentInspectAndSetRulesIsRaceFree(t *testing.T) {
	// The whole point of atomic.Pointer over a plain slice+mutex is that
	// Inspect (hot path) and SetRules (rare, from the hot-reload watcher)
	// can run concurrently without a data race. `go test -race` is what
	// actually proves this; the test just needs to genuinely exercise
	// both paths at once.
	e := New([]Rule{{ID: "r1", Pattern: []byte("a"), Severity: types.SeverityLow}})
	stop := make(chan struct{})
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				e.Inspect(types.Packet{Payload: []byte("a payload")})
			}
		}
	}()

	for i := 0; i < 100; i++ {
		e.SetRules([]Rule{{ID: "r1", Pattern: []byte("a"), Severity: types.SeverityLow}})
	}
	close(stop)
	wg.Wait()
}
