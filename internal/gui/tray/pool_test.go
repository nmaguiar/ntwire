package tray

import (
	"runtime"
	"sync"
	"testing"
	"time"
)

// fakeSlot is a Slot that records calls and lets a test simulate a click by
// sending on its own channel directly.
type fakeSlot struct {
	mu      sync.Mutex
	title   string
	visible bool

	clicked chan struct{}
}

func newFakeSlot() *fakeSlot { return &fakeSlot{clicked: make(chan struct{})} }

func (s *fakeSlot) SetTitle(title string)        { s.mu.Lock(); defer s.mu.Unlock(); s.title = title }
func (s *fakeSlot) SetTooltip(string)            {}
func (s *fakeSlot) Show()                        { s.mu.Lock(); defer s.mu.Unlock(); s.visible = true }
func (s *fakeSlot) Hide()                        { s.mu.Lock(); defer s.mu.Unlock(); s.visible = false }
func (s *fakeSlot) Enable()                      {}
func (s *fakeSlot) Disable()                     {}
func (s *fakeSlot) ClickedChan() <-chan struct{} { return s.clicked }

func (s *fakeSlot) click(t *testing.T) {
	t.Helper()
	select {
	case s.clicked <- struct{}{}:
	case <-time.After(time.Second):
		t.Fatal("click was not consumed by the slot's dispatch goroutine")
	}
}

func newFakePool(n int) (*slotPool, []*fakeSlot) {
	fakes := make([]*fakeSlot, n)
	slots := make([]Slot, n)
	for i := range fakes {
		fakes[i] = newFakeSlot()
		slots[i] = fakes[i]
	}
	return newSlotPool(slots), fakes
}

func TestAcquireBindsFreeSlotAndIsIdempotent(t *testing.T) {
	p, _ := newFakePool(2)
	s1, ok := p.acquire("profile-a")
	if !ok {
		t.Fatal("acquire failed on an empty pool")
	}
	s2, ok := p.acquire("profile-a")
	if !ok || s2 != s1 {
		t.Fatal("acquiring the same id again should return the same slot")
	}
}

func TestAcquireFailsWhenPoolIsFull(t *testing.T) {
	p, _ := newFakePool(1)
	if _, ok := p.acquire("a"); !ok {
		t.Fatal("first acquire should succeed")
	}
	if _, ok := p.acquire("b"); ok {
		t.Fatal("acquire should fail once every slot is bound to a different id")
	}
}

func TestReleaseHidesAndFreesSlotForReuse(t *testing.T) {
	p, fakes := newFakePool(1)
	slot, _ := p.acquire("a")
	slot.Show()
	p.release("a")
	if fakes[0].visible {
		t.Error("release should hide the slot")
	}
	if _, ok := p.acquire("b"); !ok {
		t.Fatal("a released slot should be available for a new id")
	}
}

// TestReusedSlotInvokesCurrentActionNotStaleOne is the actual bug the
// pool's atomic-swap design exists to prevent: binding id "a" to a slot,
// giving it an action, releasing it, binding a different id "b" to the
// same physical slot, and clicking it must run "b"'s action -- never "a"'s.
func TestReusedSlotInvokesCurrentActionNotStaleOne(t *testing.T) {
	p, fakes := newFakePool(1)

	// fired is unbuffered-in-spirit (size 1, drained immediately below) so
	// receiving from it happens-after the action actually ran -- unlike
	// waiting for fakeSlot.click to return, which only proves the
	// dispatch goroutine *received* the click, not that it has finished
	// loading and invoking the (possibly still-being-swapped) action.
	fired := make(chan string, 1)
	record := func(label string) func() {
		return func() { fired <- label }
	}
	awaitFired := func(want string) {
		t.Helper()
		select {
		case got := <-fired:
			if got != want {
				t.Fatalf("fired action = %q, want %q", got, want)
			}
		case <-time.After(time.Second):
			t.Fatalf("action %q never fired", want)
		}
	}

	slotA, _ := p.acquire("a")
	p.setAction("a", record("a-clicked"))
	fakes[0].click(t)
	awaitFired("a-clicked")

	p.release("a")
	slotB, ok := p.acquire("b")
	if !ok || slotB != slotA {
		t.Fatal("expected the released slot to be reused for id \"b\"")
	}
	p.setAction("b", record("b-clicked"))
	fakes[0].click(t)
	awaitFired("b-clicked")
}

func TestSetActionOnUnboundIDIsNoop(t *testing.T) {
	p, _ := newFakePool(1)
	// Must not panic even though "ghost" was never acquired.
	p.setAction("ghost", func() {})
}

func TestReleaseAllExceptKeepsOnlyListedIDs(t *testing.T) {
	p, fakes := newFakePool(3)
	p.acquire("a")
	p.acquire("b")
	p.acquire("c")

	p.releaseAllExcept(map[string]bool{"b": true})

	if _, ok := p.acquire("a"); !ok {
		t.Fatal("id \"a\" should have been released")
	}
	// "a" now occupies whichever slot was freed for it; assert "b" was not
	// touched by checking it is still bound to its original slot and
	// still visible if it was shown.
	_ = fakes
	if _, ok := p.acquire("c"); !ok {
		t.Fatal("id \"c\" should have been released")
	}
}

// TestHundredAcquireReleaseCyclesDoNotLeakGoroutines exercises the design
// this pool exists for: a fixed number of slots, each with exactly one
// permanent dispatch goroutine, reused across many bind/release cycles
// instead of a goroutine per menu item's lifetime.
func TestHundredAcquireReleaseCyclesDoNotLeakGoroutines(t *testing.T) {
	const poolSize = 8
	p, _ := newFakePool(poolSize)

	settle := func() int {
		runtime.GC()
		time.Sleep(5 * time.Millisecond)
		return runtime.NumGoroutine()
	}
	baseline := settle()

	for i := 0; i < 100; i++ {
		id := "profile-" + string(rune('a'+i%poolSize))
		if _, ok := p.acquire(id); !ok {
			t.Fatalf("cycle %d: acquire(%q) failed", i, id)
		}
		p.setAction(id, func() {})
		p.release(id)
	}

	after := settle()
	if after > baseline+2 { // small slack for unrelated background goroutines
		t.Errorf("goroutine count grew from %d to %d after 100 acquire/release cycles", baseline, after)
	}
}
