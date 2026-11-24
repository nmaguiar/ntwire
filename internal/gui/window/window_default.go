//go:build !gui

package window

import "time"

// Run opens Settings in the default browser.
func Run(target string) error {
	cleanup, err := launchPrivateBrowser(target)
	if err != nil {
		return err
	}
	defer cleanup()
	time.Sleep(30 * time.Second)
	return nil
}
