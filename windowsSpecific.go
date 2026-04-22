//go:build windows

package shuffle

import (
	"strings"
	"runtime"
	"encoding/json"
	"log"
	"os"
	"bytes"
	"time"
	"context"
	"io"
	"errors"
	"fmt"

	"unsafe" // for pointer control. Not ideal, but ok
	"syscall"
	"os/exec"
	"golang.org/x/sys/windows"
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

var (
	kernel32                     = syscall.NewLazyDLL("kernel32.dll")
	procCreateJobObjectW         = kernel32.NewProc("CreateJobObjectW")
	procAssignProcessToJobObject = kernel32.NewProc("AssignProcessToJobObject")
	procTerminateJobObject       = kernel32.NewProc("TerminateJobObject")
)

func createJobObject() (syscall.Handle, error) {
	r1, _, err := procCreateJobObjectW.Call(0, 0)
	if r1 == 0 {
		return 0, err
	}
	return syscall.Handle(r1), nil
}

func assignProcessToJob(job syscall.Handle, p *os.Process) error {
	r1, _, err := procAssignProcessToJobObject.Call(
		uintptr(job),
		uintptr(p.Pid),
	)
	if r1 == 0 {
		return err
	}
	return nil
}

func RunCommandString(command string, timeout time.Duration, onStream StreamFn) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "cmd", "/C", command)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return "", err
	}

	if err := cmd.Start(); err != nil {
		return "", err
	}

	var out bytes.Buffer

	read := func(r io.ReadCloser) {
		buf := make([]byte, 32*1024)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				chunk := buf[:n]
				out.Write(chunk)

				if onStream != nil {
					onStream(string(chunk))
				}
			}
			if err != nil {
				return
			}
		}
	}

	go read(stdout)
	go read(stderr)

	waitCh := make(chan error, 1)
	go func() {
		waitCh <- cmd.Wait()
	}()

	select {
	case err := <-waitCh:
		return out.String(), err

	case <-ctx.Done():
		// timeout path: kill only the parent process
		_ = cmd.Process.Kill()

		<-waitCh // ensure cleanup
		return out.String(), fmt.Errorf("timeout after %s", timeout)
	}
}

func (c *AuditLogCollector) Stop() {
	return
}

func (c *AuditLogCollector) LogCollectorStart(ctx context.Context) error {
	return errors.New("Not implemented on windows") 
}

func NewAuditLogCollector(config TelemetryConfig) (*AuditLogCollector, error) {
	auditLogCollector := AuditLogCollector{}
	return &auditLogCollector, errors.New("Not implemented on windows")
}

func queryRegValue(name string) (string, error) {
	cmd := exec.Command(
		"reg", "query",
		`HKEY_CURRENT_USER\Control Panel\Desktop`,
		"/v", name,
	)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(line, name) {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				return fields[len(fields)-1], nil
			}
		}
	}
	return "", fmt.Errorf("value not found")
}

func IsAutomaticScreenlockEnabled() bool {
	activeStr, err := queryRegValue("ScreenSaveActive")
	if err != nil {
		log.Printf("[ERROR] ScreenSaveActive: %v", err)
		return false
	}

	secureStr, err := queryRegValue("ScreenSaverIsSecure")
	if err != nil {
		log.Printf("[ERROR] ScreenSaverIsSecure: %v", err)
		return false
	}

	timeoutStr, err := queryRegValue("ScreenSaveTimeOut")
	if err != nil {
		log.Printf("[ERROR] ScreenSaveTimeOut: %v", err)
		return false
	}

	active := parseInt(activeStr)
	secure := parseInt(secureStr)
	timeout := parseInt(timeoutStr)

	return active == 1 && secure == 1 && timeout <= 900
}

type osVersionInfoEx struct {
	dwOSVersionInfoSize uint32
	dwMajorVersion      uint32
	dwMinorVersion      uint32
	dwBuildNumber       uint32
	dwPlatformId        uint32
	szCSDVersion        [128]uint16
	wServicePackMajor   uint16
	wServicePackMinor   uint16
	wSuiteMask          uint16
	wProductType        byte
	wReserved           byte
}

func getWindowsSoftware() (Software, error) {
	// Load ntdll and RtlGetVersion (more reliable than GetVersionEx)
	mod := syscall.NewLazyDLL("ntdll.dll")
	proc := mod.NewProc("RtlGetVersion")

	var info osVersionInfoEx
	info.dwOSVersionInfoSize = uint32(unsafe.Sizeof(info))

	r1, _, _ := proc.Call(uintptr(unsafe.Pointer(&info)))
	if r1 != 0 {
		return Software{}, fmt.Errorf("RtlGetVersion failed")
	}

	version := fmt.Sprintf("%d.%d.%d",
		info.dwMajorVersion,
		info.dwMinorVersion,
		info.dwBuildNumber,
	)

	name := "Windows"

	// Light mapping (best-effort, not official API)
	switch {
	case info.dwMajorVersion == 10 && info.dwBuildNumber >= 22000:
		name = fmt.Sprintf("Windows 11 (Build %d)", info.dwBuildNumber)
	case info.dwMajorVersion == 10:
		name = fmt.Sprintf("Windows 10 (Build %d)", info.dwBuildNumber)
	default:
		name = fmt.Sprintf("Windows %d.%d (Build %d)",
			info.dwMajorVersion,
			info.dwMinorVersion,
			info.dwBuildNumber,
		)
	}

	return Software{
		Name:    name,
		Version: version,
	}, nil
}

func listInstalledSoftwareRegistry() []Software {
	cmd := `
$paths = @(
  "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
  "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
  "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

Get-ItemProperty $paths |
Where-Object { $_.DisplayName } |
Select-Object @{Name="name";Expression={$_.DisplayName}}, @{Name="version";Expression={$_.DisplayVersion}} |
ConvertTo-Json -Depth 1 -Compress
`

	out, err := exec.Command("powershell", "-NoProfile", "-Command", cmd).Output()
	if err != nil {
		return nil
	}

	data := bytes.TrimSpace(out)
	if len(data) == 0 {
		return nil
	}

	// normalize single object -> array
	if data[0] == '{' {
		data = append([]byte("["), append(data, ']')...)
	}

	var pkgs []Software
	if err := json.Unmarshal(data, &pkgs); err != nil {
		return nil
	}

	return pkgs
}

func ListInstalledSoftware() []Software {
	allSoftware := []Software{}
	localSoftware, err := getWindowsSoftware()
	if err != nil {
		log.Printf("[ERROR] getLocalSoftware load error: %v", err)
	} else {
		allSoftware = append(allSoftware, localSoftware)
	}

	return append(allSoftware, listInstalledSoftwareRegistry()...)
}

func ListCodeScannerProjects() []ProjectInfo {
	log.Printf("[WARNING] Codescanner not implemented on windows yet.")

	return []ProjectInfo{}
}

const (
	backupFile = "C:\\Windows\\Temp\\firewall_backup_edr.wfw"
)

func isAdmin() bool {
	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	return err == nil
}

func isolateHostWindows(allowIPs []string) error {
	// Must run as admin
	if !isAdmin() {
		return fmt.Errorf("requires administrator privileges")
	}

	// 1. Backup firewall state
	exec.Command("netsh", "advfirewall", "export", backupFile).Run()

	// 2. Set default block policies
	cmds := [][]string{
		{"netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound"},
	}

	for _, c := range cmds {
		if err := exec.Command(c[0], c[1:]...).Run(); err != nil {
			return fmt.Errorf("failed to set firewall policy: %w", err)
		}
	}

	// 3. Allow loopback explicitly
	exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		"name=EDR-Allow-Loopback",
		"dir=in",
		"action=allow",
		"interface=any",
		"enable=yes").Run()

	exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		"name=EDR-Allow-Loopback-Out",
		"dir=out",
		"action=allow",
		"interface=any",
		"enable=yes").Run()

	// 4. Allow EDR endpoints
	for _, ip := range allowIPs {
		exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
			fmt.Sprintf("name=EDR-Allow-%s", ip),
			"dir=out",
			"action=allow",
			fmt.Sprintf("remoteip=%s", ip),
			"enable=yes").Run()

		exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
			fmt.Sprintf("name=EDR-Allow-In-%s", ip),
			"dir=in",
			"action=allow",
			fmt.Sprintf("remoteip=%s", ip),
			"enable=yes").Run()
	}

	return nil
}

func unisolateHostWindows() error {
	if !isAdmin() {
		return fmt.Errorf("requires administrator privileges")
	}

	// Restore firewall config
	return exec.Command("netsh", "advfirewall", "import", backupFile).Run()
}

func isolateHost(allowIPs []string) error {
	return isolateHostWindows(allowIPs)
}

func unisolateHost() error {
	return unisolateHostWindows()
}
