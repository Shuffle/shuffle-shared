//go:build !windows

package shuffle 

import (
	"os"
	"os/exec"
	"strings"
	"strconv"
	"regexp"
	"encoding/json"

	"runtime"
)

func parseInt(s string) int {
	s = strings.TrimSpace(s)
	val, err := strconv.Atoi(s)
	if err != nil {
		return 0 // default to 0 if parse fails
	}
	return val
}

func IsElevated() bool {
	return os.Geteuid() == 0
}

func parsePmsetDisplaySleep(out []byte) int {
	lines := strings.Split(string(out), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "displaysleep") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				mins := parseInt(fields[1])
				return mins * 60
			}
		}
	}

	return 0
}

func willLockWithin15MinMac() bool {
	idleSec := getMacIdleTimeSeconds()
	if idleSec <= 0 {
		return false
	}

	lockEnabled := isMacScreenLockEnabled()

	// must both be true
	//return lockEnabled && idleSec <= 900
	return lockEnabled && idleSec <= 10800 
}

func getMacIdleTimeSeconds() int {
	// try currentHost (more reliable than system-wide)
	out, err := exec.Command(
		"defaults",
		"-currentHost",
		"read",
		"com.apple.screensaver",
		"idleTime",
	).Output()

	if err == nil {
		if v := parseInt(strings.TrimSpace(string(out))); v > 0 {
			return v
		}
	}

	// fallback: system-wide pmset
	out, err = exec.Command("pmset", "-g", "custom").Output()
	if err == nil {
		return parsePmsetDisplaySleep(out)
	}

	return 0
}

func isMacScreenLockEnabled() bool {
	out, err := exec.Command(
		"defaults",
		"read",
		"com.apple.screensaver",
		"askForPassword",
	).Output()

	if err != nil {
		// missing key → assume enabled in managed/security contexts
		return true
	}

	return strings.TrimSpace(string(out)) == "1"
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
		return willLockWithin15MinMac()
	default: // linux, macOS, etc.
		return getScreenPolicyUnix()
	}
}

func isEncryptedMac() bool {
	out, err := exec.Command("fdesetup", "status").Output()
	if err != nil {
		return false
	}

	s := strings.ToLower(string(out))
	return strings.Contains(s, "filevault is on")
}

func isEncryptedLinux() bool {
	out, err := exec.Command("lsblk", "-o", "NAME,TYPE").Output()
	if err != nil {
		return false
	}

	s := string(out)

	// look for crypt mapping (LUKS/dm-crypt)
	return strings.Contains(s, "crypt")
}

func IsDiskEncrypted() bool {
	switch runtime.GOOS {
	case "windows":
		return false
	case "darwin":
		return isEncryptedMac()
	default:
		return isEncryptedLinux()
	}
}

func cleanSerial(s string) string {
	return strings.TrimSpace(s)
}

func getProfileMac() string {
	out, err := exec.Command("system_profiler", "SPHardwareDataType").Output()
	if err == nil { 
		return string(out)
	}

	return "failed to locate (macos)"
}

func isValidSerial(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))

	if s == "" {
		return false
	}

	bad := []string{
		"to be filled",
		"default string",
		"o.e.m",
		"unknown",
	}

	for _, b := range bad {
		if strings.Contains(s, b) {
			return false
		}
	}

	return true
}

func getSerialLinux() string {
	paths := []string{
		"/sys/class/dmi/id/product_serial",
		"/sys/class/dmi/id/board_serial",
	}

	for _, p := range paths {
		if data, err := os.ReadFile(p); err == nil {
			s := cleanSerial(string(data))
			if isValidSerial(s) {
				return s
			}
		}
	}

	// fallback (requires root on many systems)
	out, err := exec.Command("dmidecode", "-s", "system-serial-number").Output()
	if err == nil {
		s := cleanSerial(string(out))
		if isValidSerial(s) {
			return s
		}
	}

	return "failed to locate"
}

func GetProfiler() string {
	switch runtime.GOOS {
	case "windows":
		return ""
	case "darwin":
		return getProfileMac()
	default:
		return getSerialLinux()
	}
}

func listRPM() []Software {
	out, err := exec.Command(
		"rpm",
		"-qa",
		"--queryformat",
		"%{NAME} %{VERSION}-%{RELEASE}\n",
	).Output()

	if err != nil {
		return nil
	}

	var result []Software

	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			result = append(result, Software{
				Name:    fields[0],
				Version: fields[1],
			})
		}
	}

	return result
}

func listDpkg() []Software {
	out, err := exec.Command(
		"dpkg-query",
		"-W",
		"-f=${Package} ${Version}\n",
	).Output()

	if err != nil {
		return nil
	}

	var result []Software

	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			result = append(result, Software{
				Name:    fields[0],
				Version: fields[1],
			})
		}
	}

	return result
}

func listLinuxSoftware() []Software {
	// dpkg (Debian/Ubuntu)
	if _, err := exec.LookPath("dpkg-query"); err == nil {
		return listDpkg()
	}

	// rpm (RHEL/Fedora)
	if _, err := exec.LookPath("rpm"); err == nil {
		return listRPM()
	}

	// fallback
	return nil
}

func listBrew() []Software {
	out, err := exec.Command("brew", "list", "--versions").Output()
	if err != nil {
		return nil
	}

	var result []Software

	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			result = append(result, Software{
				Name:    fields[0],
				Version: fields[1],
			})
		}
	}

	return result
}


type MacApp struct {
	Name    string `json:"_name"`
	Version string `json:"version"`
	Path    string `json:"path"`
}

type macProfile struct {
	Apps []MacApp `json:"SPApplicationsDataType"`
}

func listMacSoftware() []Software {
	out, err := exec.Command(
		"system_profiler",
		"SPApplicationsDataType",
		"-json",
	).Output()

	if err != nil {
		return nil
	}

	var p macProfile
	if err := json.Unmarshal(out, &p); err != nil {
		return nil
	}

	result := make([]Software, 0, len(p.Apps))

	for _, app := range p.Apps {
		result = append(result, Software{
			Name:    app.Name,
			Version: app.Version,
		})
	}

	return result
}

func ListInstalledSoftware() []Software {
	switch runtime.GOOS {
	case "windows":
		return []Software{}
	case "darwin":
		systemApps := listMacSoftware()
		homebrew := listBrew()

		return append(systemApps, homebrew...)
	default:
		return listLinuxSoftware()
	}
}
