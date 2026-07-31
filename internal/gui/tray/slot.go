package tray

import "fyne.io/systray"

// Slot is the subset of a systray menu item's behavior the pool needs. It
// exists so slotPool's reuse and click-dispatch logic -- the part with
// actual failure modes (a leaked goroutine, a reused slot firing a stale
// action) -- can be driven and asserted on with a fake, with no real tray
// backend involved.
type Slot interface {
	SetTitle(title string)
	SetTooltip(tooltip string)
	Show()
	Hide()
	Enable()
	Disable()
	// ClickedChan is closed when the slot itself is destroyed. systray
	// never destroys menu items, so in production this channel lives for
	// the process's entire lifetime.
	ClickedChan() <-chan struct{}
}

// menuItemSlot adapts *systray.MenuItem to Slot. Every method but
// ClickedChan is already an identical signature on MenuItem itself;
// ClickedChan exists only because ClickedCh is an exported field, not a
// method, and a field can't satisfy an interface directly.
type menuItemSlot struct{ item *systray.MenuItem }

func (s menuItemSlot) SetTitle(title string)        { s.item.SetTitle(title) }
func (s menuItemSlot) SetTooltip(tooltip string)    { s.item.SetTooltip(tooltip) }
func (s menuItemSlot) Show()                        { s.item.Show() }
func (s menuItemSlot) Hide()                        { s.item.Hide() }
func (s menuItemSlot) Enable()                      { s.item.Enable() }
func (s menuItemSlot) Disable()                     { s.item.Disable() }
func (s menuItemSlot) ClickedChan() <-chan struct{} { return s.item.ClickedCh }
