//go:build windows

package shuffle

import (
	"golang.org/x/sys/windows"
)

func IsElevated() bool {
	var token windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token)
	if err != nil {
		return false
	}
	defer token.Close()

	elevated, err := token.IsElevated()
	if err != nil {
		return false
	}
	return elevated
}


// Windows: Check screensaver timeout
func IsAutomaticScreenlockEnabled() (bool, error) {
	// Is screensaver active?
	cmd := exec.Command(
		"reg", "query",
		"HKEY_CURRENT_USER\\Control Panel\\Desktop",
		"/v", "ScreenSaveActive",
	)
	output, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(output), "0x1") {
		return false
	}

	// Check timeout (ScreenSaveTimeOut is in seconds)
	cmd = exec.Command(
		"reg", "query",
		"HKEY_CURRENT_USER\\Control Panel\\Desktop",
		"/v", "ScreenSaveTimeOut",
	)
	output, err = cmd.CombinedOutput()
	if err != nil {
		return false
	}

	// Parse and check
	timeoutStr := extractRegValue(string(output))
	timeout := parseInt(timeoutStr)

	// Compliance: timeout should be <= 15 minutes
	return timeout <= 900
}


