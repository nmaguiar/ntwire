package tray

import (
	"sync"
	"sync/atomic"
)

// slotPool is a fixed-size set of pre-created menu-item slots, each keyed
// at any moment by an arbitrary string ID -- a profile ID, or
// "<profileID>\x00<tunnelName>" for a tunnel row (see keyFor). systray
// cannot remove a menu item once created, so a pool never grows or shrinks
// after construction: rebuilding the menu means re-binding existing slots
// to different IDs, hiding whichever ones are currently unused.
//
// Each slot has exactly one goroutine, started at construction and running
// for the pool's entire lifetime, forwarding that slot's clicks to
// whichever action is currently bound. The action is stored in an
// atomic.Pointer and swapped on every bind/release rather than the
// goroutine being torn down and recreated -- that's what guarantees a
// click on a reused slot invokes the *current* binding's action, never a
// stale one left over from whatever the slot used to represent.
type slotPool struct {
	slots []Slot

	mu      sync.Mutex
	ids     []string // ids[i] == "" means slots[i] is free
	actions []atomic.Pointer[func()]
}

// newSlotPool takes ownership of slots (assumed freshly created and
// unbound) and starts their dispatch goroutines.
func newSlotPool(slots []Slot) *slotPool {
	p := &slotPool{
		slots:   slots,
		ids:     make([]string, len(slots)),
		actions: make([]atomic.Pointer[func()], len(slots)),
	}
	for i, s := range slots {
		go p.dispatch(i, s)
	}
	return p
}

func (p *slotPool) dispatch(i int, s Slot) {
	for range s.ClickedChan() {
		if fn := p.actions[i].Load(); fn != nil {
			(*fn)()
		}
	}
}

// size is the number of slots this pool was created with.
func (p *slotPool) size() int { return len(p.slots) }

// acquire returns the slot currently bound to id, binding it to a free
// slot first if it has none. ok is false only when every slot is already
// bound to a different id.
func (p *slotPool) acquire(id string) (Slot, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, existing := range p.ids {
		if existing == id {
			return p.slots[i], true
		}
	}
	for i, existing := range p.ids {
		if existing == "" {
			p.ids[i] = id
			return p.slots[i], true
		}
	}
	return nil, false
}

// release unbinds id from its slot, hides the slot, and clears its action
// so the pool can hand it to a different id later without carrying over
// stale state.
func (p *slotPool) release(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, existing := range p.ids {
		if existing == id {
			p.ids[i] = ""
			p.actions[i].Store(nil)
			p.slots[i].Hide()
			return
		}
	}
}

// releaseAllExcept releases every currently bound id not present in keep,
// for a rebuild pass that only knows the new full set of ids that should
// remain visible. A nil keep releases everything.
func (p *slotPool) releaseAllExcept(keep map[string]bool) {
	p.releaseAllExceptFunc(keep, nil)
}

// releaseAllExceptFunc is releaseAllExcept, calling onRelease(id) for each
// released id while it is still bound -- so a caller managing state nested
// under that id (e.g. a profile row's own tunnel sub-pool) can tear it
// down before the id's slot is reused for something else.
func (p *slotPool) releaseAllExceptFunc(keep map[string]bool, onRelease func(id string)) {
	p.mu.Lock()
	var toRelease []string
	for _, id := range p.ids {
		if id != "" && !keep[id] {
			toRelease = append(toRelease, id)
		}
	}
	p.mu.Unlock()
	for _, id := range toRelease {
		if onRelease != nil {
			onRelease(id)
		}
		p.release(id)
	}
}

// setAction rebinds id's click action; a nil fn is a valid "do nothing".
// It is a no-op if id is not currently bound to any slot. Safe to call
// concurrently with the slot's own dispatch goroutine.
func (p *slotPool) setAction(id string, fn func()) {
	p.mu.Lock()
	idx := -1
	for i, existing := range p.ids {
		if existing == id {
			idx = i
			break
		}
	}
	p.mu.Unlock()
	if idx < 0 {
		return
	}
	if fn == nil {
		p.actions[idx].Store(nil)
		return
	}
	p.actions[idx].Store(&fn)
}
