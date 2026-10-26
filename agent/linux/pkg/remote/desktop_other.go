//go:build !darwin

package remote

import "errors"

// openNativeDesktop is only used by the macOS screen helper; X11 sessions are opened in-process.
func openNativeDesktop() (Desktop, error) {
	return nil, errors.New("the desktop helper is only used on macOS")
}
