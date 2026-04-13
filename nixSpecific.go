//go:build !windows

package shuffle 

import (
	"os"
	"os/exec"
	"strings"
	"strconv"
	"regexp"

	"runtime"
)

func IsElevated() bool {
	return os.Geteuid() == 0
}

// macOS: Check the timeout value too
func isScreenLockEnabledMacOS() (bool, error) {
	// Is lock enabled?
	cmd := exec.Command(
		"defaults", "read",
		"com.apple.screensaver",
		"askForPassword",
	)
	output, err := cmd.CombinedOutput()
	if err != nil || strings.TrimSpace(string(output)) != "1" {
		return false, nil
	}

	// Check timeout (askForPasswordDelay is in seconds)
	cmd = exec.Command(
		"defaults", "read",
		"com.apple.screensaver",
		"askForPasswordDelay",
	)
	output, err = cmd.CombinedOutput()
	if err != nil {
		return false, nil
	}

	// Parse timeout
	timeoutStr := strings.TrimSpace(string(output))
	timeout := parseInt(timeoutStr)

	// Compliance: timeout should be <= 15 minutes (900 seconds)
	// Adjust per your policy
	return timeout <= 900, nil
}

func getAutoLockTimeout() int {
	out, err := exec.Command(
		"gsettings",
		"get",
		"org.gnome.desktop.session",
		"idle-delay",
	).Output()

	if err == nil {
		s := strings.TrimSpace(string(out))
		s = strings.Trim(s, "uint32()")

		if v, err := strconv.Atoi(s); err == nil {
			return v / 60
		}
	}

	return tryKDETimeout()
}

func tryKDETimeout() int {
	data, err := os.ReadFile(os.ExpandEnv("$HOME/.config/kscreenlockerrc"))
	if err != nil {
		return -1
	}

	re := regexp.MustCompile(`Timeout=(\d+)`)
	m := re.FindSubmatch(data)
	if len(m) != 2 {
		return -1
	}

	v, err := strconv.Atoi(string(m[1]))
	if err != nil {
		return -1
	}

	return v
}

func getDesktop() string {
	// most reliable first
	v := os.Getenv("XDG_CURRENT_DESKTOP")
	if v != "" {
		return strings.ToLower(v)
	}

	v = os.Getenv("DESKTOP_SESSION")
	if v != "" {
		return strings.ToLower(v)
	}

	v = os.Getenv("GDMSESSION")
	return strings.ToLower(v)
}

func isGNOME() bool {
	d := getDesktop()
	return strings.Contains(d, "gnome")
}

func isKDE() bool {
	d := getDesktop()
	return strings.Contains(d, "kde") ||
		strings.Contains(d, "plasma")
}

func getAutoLockTimeoutNix() int {
	switch {
	case isGNOME():
		return getAutoLockTimeout()

	case isKDE():
		return tryKDETimeout()

	default:
		return getAutoLockTimeout()
	}
}

func getScreenPolicyUnix() bool { 
	// 15 minutes check
	lockTimeout := getAutoLockTimeoutNix()
	if lockTimeout > 0 && lockTimeout <= 15 {
		return true
	}

	return false
}

func IsAutomaticScreenlockEnabled() bool { 
	switch runtime.GOOS {
	case "windows":
		return false
	case "darwin":
		enabled, err := isScreenLockEnabledMacOS()
		if err != nil {
			return false
		} else {
			return enabled
		}
	default: // linux, macOS, etc.
		return getScreenPolicyUnix()
	}
}
