//go:build windows

package shuffle

import (
	"golang.org/x/sys/windows"
	"os/exec"
	"strings"
	"runtime"
	"encoding/json"
	"log"
)

func IsElevated() bool {
	var token windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token)
	if err != nil {
		return false
	}
	defer token.Close()

	return token.IsElevated()
}

func extractRegValue(output string) string {
	// Windows reg output format:
	// "    ValueName    REG_TYPE    ActualValue"
	// We need to extract "ActualValue"

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip empty lines and the key path line
		if line == "" || strings.HasPrefix(line, "HKEY_") {
			continue
		}

		// Split by whitespace and get the last non-empty field
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			// Last field is the value
			return fields[len(fields)-1]
		}
	}
	return ""
}

// Windows: Check screensaver timeout
func IsAutomaticScreenlockEnabled() (bool) {
	// Is screensaver active?
	cmd := exec.Command(
		"reg", "query",
		"HKEY_CURRENT_USER\\Control Panel\\Desktop",
		"/v", "ScreenSaveActive",
	)
	output, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(output), "0x1") {
		log.Printf("[ERROR] Failed to check ScreenSaveActive: %s", err)
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
		log.Printf("[ERROR] Failed to check ScreenSaveTimeOut: %s", err)
		return false
	}

	// Parse and check
	timeoutStr := extractRegValue(string(output))
	timeout := parseInt(timeoutStr)

	// Compliance: timeout should be <= 15 minutes
	return timeout <= 900
}

func isEncryptedWindows() bool {
	out, err := exec.Command("manage-bde", "-status", "C:").Output()
	if err != nil {
		return false
	}

	s := strings.ToLower(string(out))

	// key signals
	return strings.Contains(s, "protection on")
}

func IsDiskEncrypted() bool {
	switch runtime.GOOS {
	case "windows":
		return isEncryptedWindows()
	default:
		return false
	}
}

func GetProfiler() string {
	cmds := []string{
		"(Get-CimInstance Win32_BIOS).SerialNumber",
		"(Get-CimInstance Win32_ComputerSystemProduct).IdentifyingNumber",
	}

	for _, c := range cmds {
		out, err := exec.Command("powershell", "-Command", c).Output()
		if err == nil {
			s := strings.TrimSpace(string(out))
			if isValidSerial(s) {
				return s
			}
		}
	}

	return "failed to get profiler"
}

func ListInstalledSoftware() []Software {
	cmd := `
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* ,
                 HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
Select-Object DisplayName, DisplayVersion |
Where-Object {$_.DisplayName} |
ConvertTo-Json
`

	out, err := exec.Command("powershell", "-Command", cmd).Output()
	if err != nil {
		return nil
	}

	var pkgs []Software
	json.Unmarshal(out, &pkgs)

	var result []Software
	for _, p := range pkgs {
		result = append(result, Software{
			Name:    p.Name,
			Version: p.Version,
		})
	}

	return result
}
