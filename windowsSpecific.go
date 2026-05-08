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
	"regexp"
	"path/filepath"
	"bufio"
	"io/fs"

	"unsafe" // for pointer control. Not ideal, but ok
	"syscall"
	"os/exec"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
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


// ── Constructor ──────────────────────────────────────────────────────────────

func NewScanner() *Scanner {
	return &Scanner{
		results: make(chan ProjectInfo),
		visited: make(map[string]bool),
	}
}

// ── Public entry point ───────────────────────────────────────────────────────

func (s *Scanner) Scan(rootDir string) ([]ProjectInfo, error) {
	absRoot, err := filepath.Abs(rootDir)
	if err != nil {
		return nil, fmt.Errorf("invalid root directory: %w", err)
	}

	s.wg.Add(1)
	go s.scanDir(absRoot)

	var results []ProjectInfo
	done := make(chan struct{})
	go func() {
		for p := range s.results {
			results = append(results, p)
		}
		close(done)
	}()

	s.wg.Wait()
	close(s.results)
	<-done

	return results, nil
}

// ── Directory walker ─────────────────────────────────────────────────────────

func (s *Scanner) scanDir(dir string) {
	defer s.wg.Done()

	// Resolve symlinks so we never visit the same inode twice.
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return
	}

	s.mu.Lock()
	if s.visited[real] {
		s.mu.Unlock()
		return
	}
	s.visited[real] = true
	s.mu.Unlock()

	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	for _, entry := range entries {
		if shouldSkip(entry.Name()) {
			continue
		}

		fullPath := filepath.Join(dir, entry.Name())

		if !entry.IsDir() {
			continue
		}

		if projectType := detectProjectType(fullPath); projectType != "" {
			packages := extractPackages(fullPath, projectType)
			s.results <- ProjectInfo{
				Path:     fullPath,
				Type:     projectType,
				Packages: packages,
			}
			// Do not recurse into found projects — avoids duplicates.
			continue
		}

		s.wg.Add(1)
		go s.scanDir(fullPath)
	}
}

// ── Skip list ────────────────────────────────────────────────────────────────

// skipDirs is the unified skip list for all platforms.
// Windows-specific entries are appended at init time.
var skipDirs = map[string]bool{
	// VCS
	".git": true,
	".hg":  true,
	".svn": true,

	// Dependency caches
	"node_modules": true,
	"vendor":       true,
	".venv":        true,
	"venv":         true,
	".env":         true,

	// IDE / tooling
	".vscode": true,
	".idea":   true,

	// Build output
	"dist":   true,
	"build":  true,
	"target": true,
	"out":    true,
	"bin":    true,
	"obj":    true, // .NET

	// Caches
	".cache":    true,
	"__pycache__": true,
}

func init() {
	if runtime.GOOS == "windows" {
		// Windows system and user-profile noise — these directories sit under
		// %USERPROFILE% but contain no user code.
		for _, d := range []string{
			"AppData",
			"Application Data",
			"Local Settings",
			"MicrosoftEdgeBackups",
			"OneDrive",         // mirror of cloud files, not local projects
			"Windows",
			"Program Files",
			"Program Files (x86)",
			"ProgramData",
			"$Recycle.Bin",
			"System Volume Information",
			"Recovery",
		} {
			skipDirs[d] = true
		}
	}
}

func shouldSkip(name string) bool {
	if skipDirs[name] {
		return true
	}
	// Hidden directories (dot-prefixed) on Unix; also catches .git etc. on Windows.
	if strings.HasPrefix(name, ".") && name != "." {
		return true
	}
	return false
}

// ── Project detection ────────────────────────────────────────────────────────

func detectProjectType(dir string) string {
	if fileExists(filepath.Join(dir, "go.mod")) {
		return "golang"
	}
	if fileExists(filepath.Join(dir, "pyproject.toml")) ||
		fileExists(filepath.Join(dir, "requirements.txt")) ||
		fileExists(filepath.Join(dir, "Pipfile")) {
		return "python"
	}
	if fileExists(filepath.Join(dir, "package.json")) {
		return "javascript"
	}
	if fileExists(filepath.Join(dir, "pom.xml")) ||
		fileExists(filepath.Join(dir, "build.gradle")) ||
		fileExists(filepath.Join(dir, "build.gradle.kts")) {
		return "java"
	}
	if fileExists(filepath.Join(dir, "Gemfile")) ||
		fileExists(filepath.Join(dir, "Rakefile")) {
		return "ruby"
	}
	// .NET: must ReadDir — glob patterns are not valid os.Stat paths.
	if entries, err := os.ReadDir(dir); err == nil {
		for _, e := range entries {
			n := e.Name()
			if strings.HasSuffix(n, ".csproj") ||
				strings.HasSuffix(n, ".vbproj") ||
				strings.HasSuffix(n, ".fsproj") {
				return "dotnet"
			}
		}
	}
	return ""
}

// ── Dispatcher ───────────────────────────────────────────────────────────────

func extractPackages(dir, projectType string) []Software {
	switch projectType {
	case "golang":
		return extractGoPackages(dir)
	case "python":
		return extractPythonPackages(dir)
	case "javascript":
		return extractJavaScriptPackages(dir)
	case "java":
		return extractJavaPackages(dir)
	case "ruby":
		return extractRubyPackages(dir)
	case "dotnet":
		return extractDotnetPackages(dir)
	}
	return nil
}

// ── Go ───────────────────────────────────────────────────────────────────────

func extractGoPackages(dir string) []Software {
	f, err := os.Open(filepath.Join(dir, "go.mod"))
	if err != nil {
		return nil
	}
	defer f.Close()

	var pkgs []Software
	sc := bufio.NewScanner(f)
	inBlock := false

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())

		switch {
		case line == "require (":
			inBlock = true

		case line == ")" && inBlock:
			inBlock = false

		case strings.HasPrefix(line, "require ") && !inBlock:
			// Single-line form: require github.com/foo/bar v1.2.3
			parts := strings.Fields(line)
			if len(parts) == 3 {
				pkgs = append(pkgs, Software{Name: parts[1], Version: parts[2]})
			}

		case inBlock && line != "" && !strings.HasPrefix(line, "//"):
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				pkgs = append(pkgs, Software{Name: parts[0], Version: parts[1]})
			} else if len(parts) == 1 {
				pkgs = append(pkgs, Software{Name: parts[0]})
			}
		}
	}
	return pkgs
}

// ── Python ───────────────────────────────────────────────────────────────────

func extractPythonPackages(dir string) []Software {
	if data, err := os.ReadFile(filepath.Join(dir, "pyproject.toml")); err == nil {
		if pkgs := parsePyprojectToml(string(data)); len(pkgs) > 0 {
			return pkgs
		}
	}
	if data, err := os.ReadFile(filepath.Join(dir, "requirements.txt")); err == nil {
		if pkgs := parseRequirementsTxt(string(data)); len(pkgs) > 0 {
			return pkgs
		}
	}
	if data, err := os.ReadFile(filepath.Join(dir, "Pipfile")); err == nil {
		return parsePipfile(string(data))
	}
	return nil
}

// versionOps are Python version specifier operators, longest-match first.
var versionOps = []string{">=", "<=", "==", "~=", "!=", ">", "<", ";"}

func splitPyDep(dep string) (name, version string) {
	minIdx := len(dep)
	for _, op := range versionOps {
		if idx := strings.Index(dep, op); idx >= 0 && idx < minIdx {
			minIdx = idx
		}
	}
	if minIdx < len(dep) {
		return strings.TrimSpace(dep[:minIdx]), strings.TrimSpace(dep[minIdx:])
	}
	return strings.TrimSpace(dep), ""
}

func parseRequirementsTxt(content string) []Software {
	var pkgs []Software
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		// Strip inline comments.
		if i := strings.Index(line, " #"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		name, version := splitPyDep(line)
		if name != "" {
			pkgs = append(pkgs, Software{Name: name, Version: version})
		}
	}
	return pkgs
}

func parsePyprojectToml(content string) []Software {
	var pkgs []Software
	inDeps := false
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())

		if strings.Contains(line, "[tool.poetry.dependencies]") ||
			strings.Contains(line, "[project]") && strings.Contains(line, "requires") {
			inDeps = true
			continue
		}
		// Any new section ends deps block.
		if inDeps && strings.HasPrefix(line, "[") {
			inDeps = false
		}
		// Array-style: "django>=3.0"
		if inDeps && strings.HasPrefix(line, `"`) {
			raw := strings.Trim(line, `",`)
			name, version := splitPyDep(raw)
			if name != "" {
				pkgs = append(pkgs, Software{Name: name, Version: version})
			}
		}
		// TOML key = "version" style: django = ">=3.0"
		if inDeps && strings.Contains(line, "=") && !strings.HasPrefix(line, "[") {
			parts := strings.SplitN(line, "=", 2)
			name := strings.TrimSpace(parts[0])
			version := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
			if name != "" && name != "python" {
				pkgs = append(pkgs, Software{Name: name, Version: version})
			}
		}
	}
	return pkgs
}

func parsePipfile(content string) []Software {
	var pkgs []Software
	inPackages := false
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "[packages]" || line == "[dev-packages]" {
			inPackages = true
			continue
		}
		if inPackages && strings.HasPrefix(line, "[") {
			inPackages = false
		}
		if inPackages && line != "" && strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			name := strings.TrimSpace(parts[0])
			version := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
			if name != "" {
				pkgs = append(pkgs, Software{Name: name, Version: version})
			}
		}
	}
	return pkgs
}

// ── JavaScript / TypeScript ──────────────────────────────────────────────────

func extractJavaScriptPackages(dir string) []Software {
	data, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		return nil
	}
	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil
	}
	var pkgs []Software
	for n, v := range pkg.Dependencies {
		pkgs = append(pkgs, Software{Name: n, Version: v})
	}
	for n, v := range pkg.DevDependencies {
		pkgs = append(pkgs, Software{Name: n, Version: v})
	}
	return pkgs
}

// ── Java ─────────────────────────────────────────────────────────────────────

func extractJavaPackages(dir string) []Software {
	if data, err := os.ReadFile(filepath.Join(dir, "pom.xml")); err == nil {
		return parsePomXml(string(data))
	}
	if data, err := os.ReadFile(filepath.Join(dir, "build.gradle")); err == nil {
		return parseGradleBuild(string(data))
	}
	if data, err := os.ReadFile(filepath.Join(dir, "build.gradle.kts")); err == nil {
		return parseGradleBuild(string(data))
	}
	return nil
}

// parsePomXml collects groupId:artifactId pairs from Maven pom.xml.
// The original code only collected groupId, producing half-names like "org.springframework".
func parsePomXml(content string) []Software {
	var pkgs []Software
	inDeps := false
	var groupID, artifactID string

	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())

		if strings.Contains(line, "<dependencies>") {
			inDeps = true
			continue
		}
		if strings.Contains(line, "</dependencies>") {
			inDeps = false
			groupID, artifactID = "", ""
			continue
		}
		if strings.Contains(line, "</dependency>") {
			groupID, artifactID = "", ""
			continue
		}

		if !inDeps {
			continue
		}

		if groupID == "" {
			if v := extractXmlValue(line, "groupId"); v != "" {
				groupID = v
			}
		}
		if artifactID == "" {
			if v := extractXmlValue(line, "artifactId"); v != "" {
				artifactID = v
			}
		}

		if groupID != "" && artifactID != "" {
			version := extractXmlValue(line, "version")
			pkgs = append(pkgs, Software{
				Name:    groupID + ":" + artifactID,
				Version: version,
			})
			groupID, artifactID = "", ""
		}
	}
	return pkgs
}

// gradleDepRe matches both groovy and Kotlin DSL dependency strings:
//
//	implementation 'group:artifact:version'
//	implementation("group:artifact:version")
var gradleDepRe = regexp.MustCompile(`(?:implementation|compile|api|testImplementation|runtimeOnly)\s*[\("']([^"']+)[\("']`)

func parseGradleBuild(content string) []Software {
	var pkgs []Software
	for _, match := range gradleDepRe.FindAllStringSubmatch(content, -1) {
		dep := match[1]
		parts := strings.Split(dep, ":")
		switch len(parts) {
		case 3:
			pkgs = append(pkgs, Software{Name: parts[0] + ":" + parts[1], Version: parts[2]})
		case 2:
			pkgs = append(pkgs, Software{Name: parts[0], Version: parts[1]})
		}
	}
	return pkgs
}

// ── Ruby ─────────────────────────────────────────────────────────────────────

// gemRe matches lines like:
//
//	gem 'rails', '~> 7.0'
//	gem "devise", ">= 4.0"
//	gem 'puma'
var gemRe = regexp.MustCompile(`^\s*gem\s+['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?`)

func extractRubyPackages(dir string) []Software {
	data, err := os.ReadFile(filepath.Join(dir, "Gemfile"))
	if err != nil {
		return nil
	}
	return parseGemfile(string(data))
}

func parseGemfile(content string) []Software {
	var pkgs []Software
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := sc.Text()
		if m := gemRe.FindStringSubmatch(line); m != nil {
			pkgs = append(pkgs, Software{Name: m[1], Version: m[2]})
		}
	}
	return pkgs
}

// ── .NET ─────────────────────────────────────────────────────────────────────

func extractDotnetPackages(dir string) []Software {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	for _, e := range entries {
		n := e.Name()
		if strings.HasSuffix(n, ".csproj") ||
			strings.HasSuffix(n, ".vbproj") ||
			strings.HasSuffix(n, ".fsproj") {
			data, err := os.ReadFile(filepath.Join(dir, n))
			if err != nil {
				continue
			}
			return parseDotnetProjectFile(string(data))
		}
	}
	return nil
}

func parseDotnetProjectFile(content string) []Software {
	var pkgs []Software
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.Contains(line, "PackageReference") {
			continue
		}
		name := extractXmlAttr(line, "Include")
		version := extractXmlAttr(line, "Version")
		if name != "" {
			pkgs = append(pkgs, Software{Name: name, Version: version})
		}
	}
	return pkgs
}

// ── XML helpers ──────────────────────────────────────────────────────────────

// extractXmlValue extracts a simple tag value: <tag>value</tag>
func extractXmlValue(line, tag string) string {
	open := "<" + tag + ">"
	close := "</" + tag + ">"
	s := strings.Index(line, open)
	e := strings.Index(line, close)
	if s >= 0 && e > s {
		return line[s+len(open) : e]
	}
	return ""
}

// extractXmlAttr extracts an XML attribute value: attr="value"
func extractXmlAttr(line, attr string) string {
	needle := attr + `="`
	s := strings.Index(line, needle)
	if s < 0 {
		return ""
	}
	s += len(needle)
	e := strings.Index(line[s:], `"`)
	if e < 0 {
		return ""
	}
	return line[s : s+e]
}


// ── Public API ───────────────────────────────────────────────────────────────

// goModCacheDir returns the OS-appropriate Go module cache path fragment
// so we can filter it regardless of platform.
func goModCacheDir() string {
	// GOPATH may be set explicitly; fall back to the default ~/go.
	gopath := os.Getenv("GOPATH")
	if gopath == "" {
		home, _ := os.UserHomeDir()
		gopath = filepath.Join(home, "go")
	}
	return filepath.Join(gopath, "pkg", "mod")
}

//func ListCodeScannerProjects() []ProjectInfo {
//	log.Printf("[WARNING] Codescanner not implemented on windows yet.")
//
//	return []ProjectInfo{}
//}

func ListCodeScannerProjects() []ProjectInfo {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting home directory: %v\n", err)
		return nil
	}

	modCache := goModCacheDir()

	sc := NewScanner()
	projects, err := sc.Scan(homeDir)
	if err != nil {
		log.Printf("[ERROR] Problem in codescanner: %v\n", err)
	}

	var out []ProjectInfo
	for _, p := range projects {
		if p.Path == "" || len(p.Packages) == 0 {
			continue
		}
		// Skip the Go module download cache — these are vendored copies,
		// not the user's own projects.
		if strings.HasPrefix(p.Path, modCache) {
			continue
		}
		out = append(out, p)
	}
	return out
}
