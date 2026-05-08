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

func scanRegistryUninstall() []Software {
	roots := []struct {
		key  registry.Key
		path string
		flag uint32
		source string
	}{
		{registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\Uninstall`, registry.WOW64_64KEY, "registry-lm-64"},
		{registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\Uninstall`, registry.WOW64_32KEY, "registry-lm-32"},
		{registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Uninstall`, 0, "registry-cu"},
	}

	var out []Software

	for _, r := range roots {
		k, err := registry.OpenKey(r.key, r.path, registry.READ|r.flag)
		if err != nil {
			continue
		}
		defer k.Close()

		names, _ := k.ReadSubKeyNames(-1)

		for _, n := range names {
			sk, err := registry.OpenKey(k, n, registry.READ|r.flag)
			if err != nil {
				continue
			}

			name, _, _ := sk.GetStringValue("DisplayName")
			version, _, _ := sk.GetStringValue("DisplayVersion")
			path, _, _ := sk.GetStringValue("InstallLocation")

			sk.Close()

			if name == "" {
				continue
			}

			out = append(out, Software{
				Name:    name,
				Version: version,
				Path:    path,
				Source:  r.source,
			})
		}
	}

	return out
}

// Infrastructure package prefixes to drop.
// These are runtime components, not user-installed apps.
var appxSkipPrefixes = []string{
    "Microsoft.NET.",
    "Microsoft.VCLibs.",
    "Microsoft.VCRedist.",
    "Microsoft.UI.",
    "Microsoft.Windows.",
    "Microsoft.Xbox",
    "Microsoft.Advertising.",
    "Microsoft.Services.",
    "Windows.",
    "MicrosoftCorporationII.",
}

func scanAppx() []Software {
    cmd := `Get-AppxPackage | Select Name, Version | ConvertTo-Json -Compress`
    out, err := exec.Command("powershell", "-NoProfile", "-Command", cmd).Output()
    if err != nil || len(out) == 0 {
        return nil
    }

    type pkg struct {
        Name    string
        Version string
    }

    // ConvertTo-Json emits a bare object (not array) when there's exactly
    // one result. Try array first, fall back to single object.
    var packages []pkg
    if err := json.Unmarshal(out, &packages); err != nil {
        var single pkg
        if err2 := json.Unmarshal(out, &single); err2 != nil {
            return nil
        }
        packages = []pkg{single}
    }

    var res []Software
    for _, p := range packages {
        if isInfraAppx(p.Name) {
            continue
        }
        res = append(res, Software{
            Name:    p.Name,
            Version: p.Version,
            Source:  "appx",
        })
    }
    return res
}

func isInfraAppx(name string) bool {
    for _, prefix := range appxSkipPrefixes {
        if strings.HasPrefix(name, prefix) {
            return true
        }
    }
    return false
}

var roots = []string{
	`C:\Program Files`,
	`C:\Program Files (x86)`,
}

func scanProgramFiles() []Software {
	var out []Software

	for _, root := range roots {
		filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}

			// limit depth (cheap heuristic)
			if strings.Count(path, string(os.PathSeparator)) > 4 {
				return filepath.SkipDir
			}

			if d.IsDir() {
				return nil
			}

			if !strings.HasSuffix(strings.ToLower(d.Name()), ".exe") {
				return nil
			}

			name, version := getFileVersion(path)
			if name == "" {
				return nil
			}

			out = append(out, Software{
				Name:    name,
				Version: version,
				Path:    path,
				Source:  "filesystem",
			})

			return nil
		})
	}

	return out
}

var (
    modVersion             = windows.NewLazySystemDLL("version.dll")
    procGetFileVersionInfo = modVersion.NewProc("GetFileVersionInfoW")
    procGetFileVersionSize = modVersion.NewProc("GetFileVersionInfoSizeW")
    procVerQueryValue      = modVersion.NewProc("VerQueryValueW")
)

func getFileVersion(path string) (name, version string) {
    pathPtr, err := windows.UTF16PtrFromString(path)
    if err != nil {
        return "", ""
    }

    // First call: get required buffer size
    size, _, _ := procGetFileVersionSize.Call(
        uintptr(unsafe.Pointer(pathPtr)),
        0,
    )
    if size == 0 {
        return "", ""
    }

    buf := make([]byte, size)

    // Second call: fill the buffer
    ret, _, _ := procGetFileVersionInfo.Call(
        uintptr(unsafe.Pointer(pathPtr)),
        0,
        size,
        uintptr(unsafe.Pointer(&buf[0])),
    )
    if ret == 0 {
        return "", ""
    }

    // Query the translation table to find the right language/codepage pair
    type langCodepage struct{ lang, codepage uint16 }
    var translations *langCodepage
    var transLen uint32

    ret, _, _ = procVerQueryValue.Call(
        uintptr(unsafe.Pointer(&buf[0])),
        uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(`\VarFileInfo\Translation`))),
        uintptr(unsafe.Pointer(&translations)),
        uintptr(unsafe.Pointer(&transLen)),
    )
    if ret == 0 || transLen == 0 {
        return "", ""
    }

    // Use the first available translation
    lang := fmt.Sprintf(`\StringFileInfo\%04x%04x\`, translations.lang, translations.codepage)

    name = queryStringValue(buf, lang+"ProductName")
    version = queryStringValue(buf, lang+"ProductVersion")
    return name, version
}

func queryStringValue(buf []byte, key string) string {
    keyPtr, err := windows.UTF16PtrFromString(key)
    if err != nil {
        return ""
    }
    var valPtr uintptr
    var valLen uint32
    ret, _, _ := procVerQueryValue.Call(
        uintptr(unsafe.Pointer(&buf[0])),
        uintptr(unsafe.Pointer(keyPtr)),
        uintptr(unsafe.Pointer(&valPtr)),
        uintptr(unsafe.Pointer(&valLen)),
    )
    if ret == 0 || valLen == 0 {
        return ""
    }
    // valPtr points into buf, valLen is in characters (UTF-16)
    utf16Slice := unsafe.Slice((*uint16)(unsafe.Pointer(valPtr)), valLen)
    return windows.UTF16ToString(utf16Slice)
}


func scanWinget() []Software {
    out, err := exec.Command(
        "winget", "list",
        "--disable-interactivity",
        "--accept-source-agreements",
    ).Output()
    if err != nil || len(out) == 0 {
        return nil
    }

    lines := strings.Split(string(out), "\n")

    // Find the header line — it contains "Name" and "Id"
    headerIdx := -1
    for i, l := range lines {
        if strings.Contains(l, "Name") && strings.Contains(l, "Id") {
            headerIdx = i
            break
        }
    }
    if headerIdx < 0 || headerIdx+2 >= len(lines) {
        return nil
    }

    header := lines[headerIdx]

    // Column start positions by header label
    nameCol    := strings.Index(header, "Name")
    idCol      := strings.Index(header, "Id")
    versionCol := strings.Index(header, "Version")
    sourceCol  := strings.Index(header, "Source")  // may be -1

    if nameCol < 0 || idCol < 0 || versionCol < 0 {
        return nil
    }

    // Skip header + separator line (headerIdx+1 is "----")
    var res []Software
    for _, line := range lines[headerIdx+2:] {
        // Trim Windows line endings; skip short/empty lines
        line = strings.TrimRight(line, "\r")
        if len(line) < versionCol+1 {
            continue
        }

        name    := columnSlice(line, nameCol, idCol)
        version := columnSlice(line, versionCol, sourceCol)

        if name == "" {
            continue
        }
        res = append(res, Software{
            Name:    name,
            Version: version,
            Source:  "winget",
        })
    }
    return res
}

// columnSlice extracts text between start and end column positions,
// trimming whitespace. If end is -1 (column not present), reads to EOL.
func columnSlice(line string, start, end int) string {
    if start >= len(line) {
        return ""
    }
    if end < 0 || end >= len(line) {
        return strings.TrimSpace(line[start:])
    }
    return strings.TrimSpace(line[start:end])
}

func dedupe(in []Software) []Software {
	seen := map[string]bool{}
	var out []Software

	for _, s := range in {
		key := strings.ToLower(s.Name + "|" + s.Version)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, s)
	}

	return out
}

func ListInstalledSoftware() []Software {
	var all []Software

	all = append(all, scanRegistryUninstall()...)
	all = append(all, scanAppx()...)
	all = append(all, scanProgramFiles()...)
	all = append(all, scanWinget()...)

	return dedupe(all)
}

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


func ListCodeScannerProjects() []ProjectInfo {
	log.Printf("[WARNING] Codescanner not implemented on windows yet.")

	return []ProjectInfo{}
}
