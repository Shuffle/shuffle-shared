//go:build !windows

package shuffle 

import (
	"os"
	"os/exec"
	"strings"
	"strconv"
	"regexp"
	"encoding/json"
	"time"
	"context"
	"bytes"
	"io"
	"fmt"
	"log"
	"bufio"
	"path/filepath"

	"syscall"
	"runtime"
)

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

func listPacman() []Software {
	out, err := exec.Command(
		"pacman",
		"-Q",
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

func listYay() []Software {
	out, err := exec.Command(
		"yay",
		"-Q",
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

func listAPK() []Software {
	out, err := exec.Command(
		"apk",
		"info",
		"-v",
	).Output()

	if err != nil {
		return nil
	}

	var result []Software

	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// split on last "-" because names can contain hyphens
		i := strings.LastIndex(line, "-")
		if i <= 0 || i == len(line)-1 {
			continue
		}

		result = append(result, Software{
			Name:    line[:i],
			Version: line[i+1:],
		})
	}

	return result
}

func listLinuxSoftware() []Software {
	// dpkg (Debian/Ubuntu)
	found := []Software{}
	if _, err := exec.LookPath("dpkg-query"); err == nil {
		found = listDpkg()
		if len(found) > 0 { 
			return found
		}
	}

	// rpm (RHEL/Fedora)
	if _, err := exec.LookPath("rpm"); err == nil {
		found = listRPM()
		if len(found) > 0 { 
			return found
		}
	}

	if _, err := exec.LookPath("pacman"); err == nil {
		found = listPacman() 
		if len(found) > 0 { 
			return found
		}
	}

	if _, err := exec.LookPath("yay"); err == nil {
		found = listYay() 
		if len(found) > 0 { 
			return found
		}
	}

	if _, err := exec.LookPath("apk"); err == nil {
		found = listAPK() 
		if len(found) > 0 { 
			return found
		}
	}

	// fallback
	return []Software{}
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

func GetLinuxSoftware() (Software, error) {
	file, err := os.Open("/etc/os-release")
	if err != nil {
		return Software{}, err
	}
	defer file.Close()

	var name, version, codename string

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := parts[0]
		value := strings.Trim(parts[1], `"`)

		switch key {
		case "NAME":
			name = value
		case "VERSION_ID":
			version = value
		case "VERSION_CODENAME":
			codename = value
		}
	}

	if err := scanner.Err(); err != nil {
		return Software{}, err
	}

	fullName := name
	if version != "" {
		fullName = fmt.Sprintf("%s %s", name, version)
	}
	if codename != "" {
		fullName = fmt.Sprintf("%s (%s)", fullName, codename)
	}

	return Software{
		Name:    fullName,
		Version: version,
	}, nil
}

func FindSystemVersionMacOS() Software {
	get := func(flag string) (string, error) {
	out, err := exec.Command("sw_vers", flag).Output()
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(out)), nil
	}

	productName, err := get("-productName")
	if err != nil {
		return Software{}
	}

	version, err := get("-productVersion")
	if err != nil {
		return Software{}
	}

	build, err := get("-buildVersion")
	if err != nil {
		return Software{}
	}

	return Software{
		Name:    fmt.Sprintf("%s %s (%s)", productName, version, build),
		Version: version,
	}
}

func ListInstalledSoftware() []Software {
	switch runtime.GOOS {
	case "windows":
		return []Software{}
	case "darwin":
		systemInfo := FindSystemVersionMacOS()
		systemApps := listMacSoftware()
		homebrew := listBrew()

		allSoftware := []Software{systemInfo}
		allSoftware = append(allSoftware, systemApps...)
		allSoftware = append(allSoftware, homebrew...)
		return allSoftware
	default:
		allSoftware := []Software{}
		defaultSoftware, err := GetLinuxSoftware() 
		if err != nil { 
			log.Printf("[WARNING] Failed to get Linux distribution info: %v", err)
		} else {
			allSoftware = append(allSoftware, defaultSoftware)
		}

		return append(allSoftware, listLinuxSoftware()...)
	}
}

// EDR and Telemetry Functions
// NewAuditLogCollector creates a new audit log collector for the current platform
func NewAuditLogCollector(config TelemetryConfig) (*AuditLogCollector, error) {
	platform := runtime.GOOS

	if config.BufferSize == 0 {
		config.BufferSize = 1000
	}

	if config.FlushInterval == 0 {
		config.FlushInterval = 10 * time.Second
	}

	collector := &AuditLogCollector{
		Config:     config,
		Platform:   platform,
		LogChannel: make(chan AuditLogEntry, config.BufferSize),
		StopChan:   make(chan bool),
	}

	return collector, nil
}

func (c *AuditLogCollector) LogCollectorStart(ctx context.Context) error {
	if !c.Config.Enabled {
		return nil
	}

	auditLogEnabled := false
	for _, mode := range c.Config.Modes {
		if mode == "audit_log" {
			auditLogEnabled = true
			break
		}
	}

	if !auditLogEnabled {
		return nil
	}

	log.Printf("[INFO] Starting audit log collector for platform: %s", c.Platform)

	switch c.Platform {
	case "linux":
		go c.collectLinuxAuditLogs(ctx)
	case "darwin":
		go c.collectMacOSAuditLogs(ctx)
	default:
		return fmt.Errorf("unsupported platform: %s", c.Platform)
	}

	go c.processTelemetryLogs(ctx)

	return nil
}

// Stop stops the audit log collection
func (c *AuditLogCollector) Stop() {
	log.Printf("[INFO] Stopping audit log collector")
	close(c.StopChan)
}

// collectLinuxAuditLogs collects audit logs on Linux systems
func (c *AuditLogCollector) collectLinuxAuditLogs(ctx context.Context) {
	// Check for auditd logs
	auditLogPath := "/var/log/audit/audit.log"
	syslogPath := "/var/log/syslog"
	journalAvailable := c.isJournalAvailable()

	// Use journalctl if available
	if journalAvailable {
		go c.collectJournalLogs(ctx)
	}

	// Monitor audit.log if it exists
	if _, err := os.Stat(auditLogPath); err == nil {
		go c.tailLogFile(ctx, auditLogPath, "auditd")
	}

	// Monitor syslog
	if _, err := os.Stat(syslogPath); err == nil {
		go c.tailLogFile(ctx, syslogPath, "syslog")
	}
}

func (c *AuditLogCollector) collectMacOSAuditLogs(ctx context.Context) {
	go c.collectMacOSSecurityLogs(ctx)
}

// collectMacOSSecurityLogs collects all security-relevant logs with one predicate
func (c *AuditLogCollector) collectMacOSSecurityLogs(ctx context.Context) {
	log.Printf("[INFO] Starting macOS security log collection")

	predicate := `(subsystem == "com.apple.opendirectoryd" && category == "auth") ||
		process == "login" ||
		process == "sshd" ||
		process == "sudo" ||
		process == "su"`

	cmd := exec.Command("log", "stream",
		"--predicate", predicate,
		"--info", "--debug",
		"--style", "json")

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Printf("[ERROR] Failed to create stdout pipe for security log stream: %v", err)
		return
	}

	if err := cmd.Start(); err != nil {
		log.Printf("[ERROR] Failed to start security log stream: %v", err)
		return
	}

	log.Printf("[INFO] Successfully started security log stream")

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			cmd.Process.Kill()
			return
		case <-c.StopChan:
			cmd.Process.Kill()
			return
		default:
			line := scanner.Text()
			if line != "" {
				c.parseMacOSLogEntry(line)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("[ERROR] Error reading security log stream: %v", err)
	}
}

func (c *AuditLogCollector) parseMacOSLogEntry(line string) {
	// First, let's see what we're actually getting
	log.Printf("[DEBUG] Raw log line: %s", line)

	var logData map[string]interface{}
	if err := json.Unmarshal([]byte(line), &logData); err != nil {
		log.Printf("[ERROR] Failed to parse JSON: %v", err)
		// If JSON parsing fails, treat it as plain text
		c.parseSimpleMacOSLogEntry(line)
		return
	}

	log.Printf("[DEBUG] Parsed JSON log entry: %v", logData)

	entry := AuditLogEntry{
		Timestamp: time.Now(),
		Platform:  "darwin",
		RawData:   line,
		Metadata:  logData,
	}

	if eventType, ok := logData["eventType"].(string); ok {
		entry.EventType = eventType
	}

	if eventMessage, ok := logData["eventMessage"].(string); ok {
		entry.Message = eventMessage
	}

	if processID, ok := logData["processID"].(float64); ok {
		entry.ProcessInfo = &ProcessInfo{
			PID: int(processID),
		}

		if processImagePath, ok := logData["processImagePath"].(string); ok {
			entry.ProcessInfo.ProcessName = filepath.Base(processImagePath)
		}
	}

	if c.shouldFilterLog(&entry) {
		return
	}

	select {
	case c.LogChannel <- entry:
	default:
		// log.Printf("[WARNING] Log channel full, dropping log entry")
	}
}

func (c *AuditLogCollector) parseSimpleMacOSLogEntry(line string) {
	// this just looks for keywords in the log line
	// not sure how reliable this is, but it's a start lol
	lowerLine := strings.ToLower(line)
	isSecurityRelevant := strings.Contains(lowerLine, "login") ||
		strings.Contains(lowerLine, "auth") ||
		strings.Contains(lowerLine, "sudo") ||
		strings.Contains(lowerLine, "password") ||
		strings.Contains(lowerLine, "session") ||
		strings.Contains(lowerLine, "security") ||
		strings.Contains(lowerLine, "loginwindow") ||
		strings.Contains(lowerLine, "securityd")

	if !isSecurityRelevant {
		return
	}

	entry := AuditLogEntry{
		Timestamp: time.Now(),
		Platform:  "darwin",
		Source:    "unified_log",
		Message:   line,
		RawData:   line,
		EventType: "security",
	}

	// Basic process extraction from log format
	if strings.Contains(line, ": ") {
		parts := strings.Split(line, ": ")
		if len(parts) > 1 {
			processField := parts[0]
			if strings.Contains(processField, "[") {
				procParts := strings.Split(processField, "[")
				if len(procParts) > 0 {
					entry.ProcessInfo = &ProcessInfo{
						ProcessName: strings.TrimSpace(procParts[0]),
					}
				}
			}
		}
	}

	if c.shouldFilterLog(&entry) {
		return
	}

	select {
	case c.LogChannel <- entry:
	default:
		// Channel full, drop the log
	}
}

// collectMacOSAuthLogs monitors auth.log and system authentication events
func (c *AuditLogCollector) collectMacOSAuthLogs(ctx context.Context) {
	log.Printf("[INFO] Starting macOS auth log collection")

	// Just monitor some basic log files that might exist
	logPaths := []string{
		"/var/log/auth.log",
		"/var/log/system.log",
		"/var/log/secure.log",
	}

	for _, logPath := range logPaths {
		if _, err := os.Stat(logPath); err == nil {
			log.Printf("[INFO] Monitoring log file: %s", logPath)
			go c.tailLogFile(ctx, logPath, filepath.Base(logPath))
		}
	}
}

// collectMacOSBSMaudit collects from macOS BSM audit system
func (c *AuditLogCollector) collectMacOSBSMaudit(ctx context.Context) {
	// Check if audit is enabled
	cmd := exec.Command("sudo", "audit", "-s")
	if err := cmd.Run(); err != nil {
		log.Printf("[WARNING] BSM audit not available or not enabled: %v", err)
		return
	}

	// Monitor current audit trail
	auditDir := "/var/audit"
	if _, err := os.Stat(auditDir); err != nil {
		log.Printf("[WARNING] Audit directory not accessible: %v", err)
		return
	}

	// Use praudit to read audit records in real-time
	cmd = exec.Command("sudo", "praudit", "-l")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Printf("[ERROR] Failed to create stdout pipe for praudit: %v", err)
		return
	}

	if err := cmd.Start(); err != nil {
		log.Printf("[ERROR] Failed to start praudit: %v", err)
		return
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			cmd.Process.Kill()
			return
		case <-c.StopChan:
			cmd.Process.Kill()
			return
		default:
			line := scanner.Text()
			c.parseBSMAuditEntry(line)
		}
	}
}

// parseBSMAuditEntry parses BSM audit entries
func (c *AuditLogCollector) parseBSMAuditEntry(line string) {
	entry := AuditLogEntry{
		Timestamp: time.Now(),
		Platform:  "darwin",
		Source:    "bsm_audit",
		Message:   line,
		RawData:   line,
		EventType: "audit",
	}

	// Extract process info if available (basic parsing)
	if strings.Contains(line, "process") {
		// This is a simplified parser - BSM audit format is complex
		fields := strings.Fields(line)
		for i, field := range fields {
			if field == "process" && i+1 < len(fields) {
				entry.ProcessInfo = &ProcessInfo{
					ProcessName: fields[i+1],
				}
				break
			}
		}
	}

	if c.shouldFilterLog(&entry) {
		return
	}

	select {
	case c.LogChannel <- entry:
	default:
		// Channel full, drop the log
	}
}

func (c *AuditLogCollector) collectJournalLogs(ctx context.Context) {
	cmd := exec.Command("journalctl", "-f", "-o", "json", "--since", "now")

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Printf("[ERROR] Failed to create stdout pipe for journalctl: %v", err)
		return
	}

	if err := cmd.Start(); err != nil {
		log.Printf("[ERROR] Failed to start journalctl: %v", err)
		return
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			cmd.Process.Kill()
			return
		case <-c.StopChan:
			cmd.Process.Kill()
			return
		default:
			line := scanner.Text()
			c.parseJournalEntry(line)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("[ERROR] Error reading journalctl: %v", err)
	}
}

// parseJournalEntry parses a systemd journal entry
func (c *AuditLogCollector) parseJournalEntry(line string) {
	var journalData map[string]interface{}
	if err := json.Unmarshal([]byte(line), &journalData); err != nil {
		return
	}

	entry := AuditLogEntry{
		Timestamp: time.Now(),
		Platform:  "linux",
		Source:    "journal",
		RawData:   line,
		Metadata:  journalData,
	}

	// Extract standard journal fields
	if priority, ok := journalData["PRIORITY"].(string); ok {
		entry.Level = c.priorityToLevel(priority)
	}

	if message, ok := journalData["MESSAGE"].(string); ok {
		entry.Message = message
	}

	if syslogID, ok := journalData["SYSLOG_IDENTIFIER"].(string); ok {
		entry.EventType = syslogID
	}

	// Process information
	if pid, ok := journalData["_PID"].(string); ok {
		pidInt, _ := strconv.Atoi(pid)
		entry.ProcessInfo = &ProcessInfo{
			PID: pidInt,
		}

		if comm, ok := journalData["_COMM"].(string); ok {
			entry.ProcessInfo.ProcessName = comm
		}

		if cmdline, ok := journalData["_CMDLINE"].(string); ok {
			entry.ProcessInfo.CommandLine = cmdline
		}
	}

	// User information
	if uid, ok := journalData["_UID"].(string); ok {
		entry.UserInfo = &UserInfo{
			UserID: uid,
		}
	}

	// Apply filters
	if c.shouldFilterLog(&entry) {
		return
	}

	select {
	case c.LogChannel <- entry:
	default:
		// Channel full, drop the log
	}
}

// tailLogFile monitors a log file for new entries
func (c *AuditLogCollector) tailLogFile(ctx context.Context, filepath string, source string) {
	file, err := os.Open(filepath)
	if err != nil {
		log.Printf("[ERROR] Failed to open log file %s: %v", filepath, err)
		return
	}
	defer file.Close()

	// Seek to end of file
	file.Seek(0, 2)

	scanner := bufio.NewScanner(file)
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.StopChan:
			return
		default:
			if scanner.Scan() {
				line := scanner.Text()
				entry := AuditLogEntry{
					Timestamp: time.Now(),
					Platform:  c.Platform,
					Source:    source,
					Message:   line,
					RawData:   line,
				}

				// Apply filters
				if c.shouldFilterLog(&entry) {
					continue
				}

				select {
				case c.LogChannel <- entry:
				default:
					// Channel full, drop the log
				}
			} else {
				// No new data, sleep briefly
				time.Sleep(100 * time.Millisecond)
			}
		}
	}
}

func (c *AuditLogCollector) processTelemetryLogs(ctx context.Context) {
	buffer := make([]AuditLogEntry, 0, c.Config.BufferSize)
	ticker := time.NewTicker(c.Config.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			c.flushLogs(buffer)
			return
		case <-c.StopChan:
			c.flushLogs(buffer)
			return
		case entry := <-c.LogChannel:
			buffer = append(buffer, entry)
			if len(buffer) >= c.Config.BufferSize {
				c.flushLogs(buffer)
				buffer = buffer[:0]
			}
		case <-ticker.C:
			if len(buffer) > 0 {
				c.flushLogs(buffer)
				buffer = buffer[:0]
			}
		}
	}
}

// flushLogs outputs collected logs (for now just printing)
func (c *AuditLogCollector) flushLogs(logs []AuditLogEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, log := range logs {
		// For now, just print the logs
		fmt.Printf("[AUDIT] %s | %s | %s | %s\n",
			log.Timestamp.Format(time.RFC3339),
			log.Platform,
			log.EventType,
			log.Message)
	}
}

func (c *AuditLogCollector) shouldFilterLog(entry *AuditLogEntry) bool {
	for _, filter := range c.Config.Filters {
		switch filter.Type {
		case "event_type":
			if len(filter.Include) > 0 {
				included := false
				for _, inc := range filter.Include {
					if strings.Contains(entry.EventType, inc) {
						included = true
						break
					}
				}
				if !included {
					return true
				}
			}

			for _, exc := range filter.Exclude {
				if strings.Contains(entry.EventType, exc) {
					return true
				}
			}
		case "message":
			if len(filter.Include) > 0 {
				included := false
				for _, inc := range filter.Include {
					if strings.Contains(entry.Message, inc) {
						included = true
						break
					}
				}
				if !included {
					return true
				}
			}

			for _, exc := range filter.Exclude {
				if strings.Contains(entry.Message, exc) {
					return true
				}
			}
		}
	}

	return false
}

// isJournalAvailable checks if systemd journal is available
func (c *AuditLogCollector) isJournalAvailable() bool {
	cmd := exec.Command("which", "journalctl")
	err := cmd.Run()
	return err == nil
}

// priorityToLevel converts systemd priority to log level
func (c *AuditLogCollector) priorityToLevel(priority string) string {
	switch priority {
	case "0", "1", "2", "3":
		return "ERROR"
	case "4":
		return "WARNING"
	case "5", "6":
		return "INFO"
	case "7":
		return "DEBUG"
	default:
		return "INFO"
	}
}

func RunCommandString(command string, timeout time.Duration, onStream StreamFn) (string, error) {
	if debug { 
		log.Printf("[DEBUG] Running command (timeout: %#v): '%s'", timeout, command)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sh", "-c", command)

	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		return "", err
	}

	var out bytes.Buffer

	stream := func(r io.ReadCloser) {
		buf := make([]byte, 32*1024)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				out.Write(buf[:n])
				if onStream != nil {
					onStream(string(buf[:n]))
				}
			}
			if err != nil {
				return
			}
		}
	}

	go stream(stdout)
	go stream(stderr)

	// IMPORTANT: wait in separate goroutine
	waitCh := make(chan error, 1)
	go func() {
		waitCh <- cmd.Wait()
	}()

	select {
	case err := <-waitCh:
		return out.String(), err

	case <-ctx.Done():
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		return out.String(), fmt.Errorf("process timeout after %s", timeout)
	}	
}

// NewScanner creates a new project scanner
func NewScanner() *Scanner {
	return &Scanner{
		results: make(chan ProjectInfo),
		visited: make(map[string]bool),
	}
}

// Scan starts scanning from the given root directory
func (s *Scanner) Scan(rootDir string) ([]ProjectInfo, error) {
	absRoot, err := filepath.Abs(rootDir)
	if err != nil {
		return nil, fmt.Errorf("invalid root directory: %w", err)
	}

	// Start the scanner goroutine
	s.wg.Add(1)
	go s.scanDir(absRoot)

	// Collect results in a separate goroutine
	results := make([]ProjectInfo, 0)
	done := make(chan bool)

	go func() {
		for project := range s.results {
			results = append(results, project)
		}
		done <- true
	}()

	// Wait for all scanning to complete
	s.wg.Wait()
	close(s.results)
	<-done

	return results, nil
}

// scanDir recursively scans a directory for projects (runs in goroutine)
func (s *Scanner) scanDir(dir string) {
	defer s.wg.Done()

	// Prevent infinite loops from symlinks
	s.mu.Lock()
	if s.visited[dir] {
		s.mu.Unlock()
		return
	}
	s.visited[dir] = true
	s.mu.Unlock()

	entries, err := os.ReadDir(dir)
	if err != nil {
		return // Skip unreadable directories
	}

	for _, entry := range entries {
		// Skip hidden files and common non-project directories
		if shouldSkip(entry.Name()) {
			continue
		}

		fullPath := filepath.Join(dir, entry.Name())

		if entry.IsDir() {
			// Check if this directory is a project
			if projectType := detectProjectType(fullPath); projectType != "" {
				packages := extractPackages(fullPath, projectType)
				s.results <- ProjectInfo{
					Path:     fullPath,
					Type:     projectType,
					Packages: packages,
				}
				// Don't recurse into found projects (to avoid duplicates)
				continue
			}

			// Recurse into subdirectory in a new goroutine
			s.wg.Add(1)
			go s.scanDir(fullPath)
		}
	}
}

// shouldSkip returns true if a directory should be skipped
func shouldSkip(name string) bool {
	skipDirs := map[string]bool{
		".git":        true,
		".hg":         true,
		"node_modules": true,
		"vendor":      true,
		".venv":       true,
		"venv":        true,
		".env":        true,
		".vscode":     true,
		".idea":       true,
		"dist":        true,
		"build":       true,
		"target":      true,
		".cache":      true,
	}

	if strings.HasPrefix(name, ".") && name != "." {
		return true // Skip hidden dirs in general
	}

	return skipDirs[name]
}

// detectProjectType checks if a directory is a project and returns its type
func detectProjectType(dir string) string {
	// Check for Go project
	if fileExists(filepath.Join(dir, "go.mod")) {
		return "golang"
	}

	// Check for Python project
	if fileExists(filepath.Join(dir, "pyproject.toml")) ||
		fileExists(filepath.Join(dir, "requirements.txt")) ||
		fileExists(filepath.Join(dir, "Pipfile")) {
		return "python"
	}

	// Check for JavaScript/TypeScript project
	if fileExists(filepath.Join(dir, "package.json")) {
		return "javascript"
	}

	// Check for Java project
	if fileExists(filepath.Join(dir, "pom.xml")) ||
		fileExists(filepath.Join(dir, "build.gradle")) ||
		fileExists(filepath.Join(dir, "build.gradle.kts")) {
		return "java"
	}

	// Check for Ruby project
	if fileExists(filepath.Join(dir, "Gemfile")) ||
		fileExists(filepath.Join(dir, "Rakefile")) {
		return "ruby"
	}

	// Check for .NET project
	if fileExists(filepath.Join(dir, "*.csproj")) ||
		fileExists(filepath.Join(dir, "*.vbproj")) ||
		fileExists(filepath.Join(dir, "*.fsproj")) ||
		fileExists(filepath.Join(dir, ".csproj")) ||
		fileExists(filepath.Join(dir, ".vbproj")) ||
		fileExists(filepath.Join(dir, ".fsproj")) {
		return "dotnet"
	}
	// Also check for .NET by looking for project files with glob
	if entries, err := os.ReadDir(dir); err == nil {
		for _, entry := range entries {
			name := entry.Name()
			if strings.HasSuffix(name, ".csproj") ||
				strings.HasSuffix(name, ".vbproj") ||
				strings.HasSuffix(name, ".fsproj") {
				return "dotnet"
			}
		}
	}

	return ""
}

// extractPackages reads the appropriate dependency file and extracts package names with versions
func extractPackages(dir string, projectType string) []Software {
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
	return []Software{}
}

// extractGoPackages parses go.mod file and extracts packages with versions
func extractGoPackages(dir string) []Software {
	goModPath := filepath.Join(dir, "go.mod")
	file, err := os.Open(goModPath)
	if err != nil {
		return []Software{}
	}
	defer file.Close()

	var packages []Software
	scanner := bufio.NewScanner(file)
	inRequire := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "require (" {
			inRequire = true
			continue
		}
		if line == ")" && inRequire {
			inRequire = false
			continue
		}

		if inRequire && line != "" && !strings.HasPrefix(line, "//") {
			// Parse: package-name version
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				packages = append(packages, Software{
					Name:    parts[0],
					Version: parts[1],
				})
			} else if len(parts) == 1 {
				packages = append(packages, Software{
					Name:    parts[0],
					Version: "",
				})
			}
		}
	}

	return packages
}

// extractPythonPackages parses Python dependency files
func extractPythonPackages(dir string) []Software {
	var packages []Software

	// Try pyproject.toml first
	if data, err := os.ReadFile(filepath.Join(dir, "pyproject.toml")); err == nil {
		packages = parsePyprojectToml(string(data))
		if len(packages) > 0 {
			return packages
		}
	}

	// Fall back to requirements.txt
	if data, err := os.ReadFile(filepath.Join(dir, "requirements.txt")); err == nil {
		packages = parseRequirementsTxt(string(data))
		if len(packages) > 0 {
			return packages
		}
	}

	// Try Pipfile
	if data, err := os.ReadFile(filepath.Join(dir, "Pipfile")); err == nil {
		packages = parsePipfile(string(data))
	}

	return packages
}

// parseRequirementsTxt extracts package names and versions from requirements.txt
func parseRequirementsTxt(content string) []Software {
	var packages []Software
	scanner := bufio.NewScanner(strings.NewReader(content))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse: package>=1.0.0 or package==1.0.0, etc.
		var name, version string

		// Find first version specifier
		versionOps := []string{">=", "<=", "==", "~=", "!=", ">", "<", ";"}
		minIdx := len(line)
		for _, op := range versionOps {
			if idx := strings.Index(line, op); idx >= 0 && idx < minIdx {
				minIdx = idx
			}
		}

		if minIdx < len(line) {
			name = strings.TrimSpace(line[:minIdx])
			version = strings.TrimSpace(line[minIdx:])
		} else {
			name = line
			version = ""
		}

		if name != "" {
			packages = append(packages, Software{
				Name:    name,
				Version: version,
			})
		}
	}

	return packages
}

// parsePyprojectToml extracts dependencies from pyproject.toml
func parsePyprojectToml(content string) []Software {
	var packages []Software
	inDeps := false

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.Contains(line, "dependencies") || strings.Contains(line, "requires") {
			inDeps = true
			continue
		}

		if inDeps && strings.HasPrefix(line, "[") {
			inDeps = false
		}

		if inDeps && strings.HasPrefix(line, "\"") {
			// Extract package name from dependency string like: "django>=3.0,<4.0"
			pkg := strings.Trim(line, "\",")

			// Find first version specifier
			versionOps := []string{">=", "<=", "==", "~=", "!=", ">", "<", ";"}
			minIdx := len(pkg)
			for _, op := range versionOps {
				if idx := strings.Index(pkg, op); idx >= 0 && idx < minIdx {
					minIdx = idx
				}
			}

			var name, version string
			if minIdx < len(pkg) {
				name = strings.TrimSpace(pkg[:minIdx])
				version = strings.TrimSpace(pkg[minIdx:])
			} else {
				name = pkg
				version = ""
			}

			if name != "" {
				packages = append(packages, Software{
					Name:    name,
					Version: version,
				})
			}
		}
	}

	return packages
}

// parsePipfile extracts dependencies from Pipfile
func parsePipfile(content string) []Software {
	var packages []Software
	inPackages := false

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.Contains(line, "[packages]") {
			inPackages = true
			continue
		}

		if inPackages && strings.HasPrefix(line, "[") {
			inPackages = false
		}

		if inPackages && line != "" && !strings.HasPrefix(line, "[") {
			// Parse: package = "==1.0" or package = "*"
			parts := strings.Split(line, "=")
			if len(parts) >= 2 {
				name := strings.TrimSpace(parts[0])
				version := strings.TrimSpace(strings.Join(parts[1:], "="))
				version = strings.Trim(version, "\"'")
				packages = append(packages, Software{
					Name:    name,
					Version: version,
				})
			}
		}
	}

	return packages
}

// extractJavaScriptPackages parses package.json and extracts packages with versions
func extractJavaScriptPackages(dir string) []Software {
	packageJsonPath := filepath.Join(dir, "package.json")
	data, err := os.ReadFile(packageJsonPath)
	if err != nil {
		return []Software{}
	}

	var pkgData map[string]interface{}
	if err := json.Unmarshal(data, &pkgData); err != nil {
		return []Software{}
	}

	var packages []Software

	// Extract dependencies
	if deps, ok := pkgData["dependencies"].(map[string]interface{}); ok {
		for pkg, ver := range deps {
			version := ""
			if v, ok := ver.(string); ok {
				version = v
			}
			packages = append(packages, Software{
				Name:    pkg,
				Version: version,
			})
		}
	}

	// Extract devDependencies
	if devDeps, ok := pkgData["devDependencies"].(map[string]interface{}); ok {
		for pkg, ver := range devDeps {
			version := ""
			if v, ok := ver.(string); ok {
				version = v
			}
			packages = append(packages, Software{
				Name:    pkg,
				Version: version,
			})
		}
	}

	return packages
}

// extractJavaPackages parses Maven pom.xml or Gradle build files
func extractJavaPackages(dir string) []Software {
	// Try Maven first
	pomPath := filepath.Join(dir, "pom.xml")
	if data, err := os.ReadFile(pomPath); err == nil {
		return parsePomXml(string(data))
	}

	// Try Gradle
	gradlePath := filepath.Join(dir, "build.gradle")
	if data, err := os.ReadFile(gradlePath); err == nil {
		return parseGradleBuild(string(data))
	}

	// Try Gradle Kotlin DSL
	gradleKtsPath := filepath.Join(dir, "build.gradle.kts")
	if data, err := os.ReadFile(gradleKtsPath); err == nil {
		return parseGradleBuild(string(data))
	}

	return []Software{}
}

// parsePomXml extracts dependencies from Maven pom.xml
func parsePomXml(content string) []Software {
	var packages []Software
	inDeps := false
	var currentGroupId string

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.Contains(line, "<dependencies>") {
			inDeps = true
			continue
		}
		if strings.Contains(line, "</dependencies>") {
			inDeps = false
			continue
		}

		if inDeps {
			if strings.Contains(line, "<groupId>") {
				currentGroupId = extractXmlValue(line, "groupId")
			}
			if strings.Contains(line, "<version>") && currentGroupId != "" {
				version := extractXmlValue(line, "version")
				packages = append(packages, Software{
					Name:    currentGroupId,
					Version: version,
				})
				currentGroupId = ""
			}
		}
	}

	return packages
}

// parseGradleBuild extracts dependencies from Gradle build files
func parseGradleBuild(content string) []Software {
	var packages []Software
	inDeps := false

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.Contains(line, "dependencies") || strings.Contains(line, "dependencies {") {
			inDeps = true
			continue
		}

		if inDeps && strings.HasPrefix(line, "}") {
			inDeps = false
			continue
		}

		if inDeps && (strings.HasPrefix(line, "implementation") ||
			strings.HasPrefix(line, "compile") ||
			strings.HasPrefix(line, "testImplementation")) {

			// Extract dependency string: implementation 'group:artifact:version'
			start := strings.Index(line, "'")
			end := strings.LastIndex(line, "'")
			if start >= 0 && end > start {
				dep := line[start+1 : end]
				parts := strings.Split(dep, ":")
				if len(parts) >= 3 {
					packages = append(packages, Software{
						Name:    parts[0] + ":" + parts[1],
						Version: parts[2],
					})
				} else if len(parts) >= 2 {
					packages = append(packages, Software{
						Name:    parts[0],
						Version: parts[1],
					})
				}
			}
		}
	}

	return packages
}

// extractRubyPackages parses Gemfile for Ruby dependencies
func extractRubyPackages(dir string) []Software {
	gemfilePath := filepath.Join(dir, "Gemfile")
	data, err := os.ReadFile(gemfilePath)
	if err != nil {
		return []Software{}
	}

	return parseGemfile(string(data))
}

// parseGemfile extracts gem names and versions from Gemfile
func parseGemfile(content string) []Software {
	var packages []Software

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and blank lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Match: gem 'gem-name' or gem "gem-name" or gem 'gem-name', '~> 1.0'
		if strings.HasPrefix(line, "gem") {
			// Extract gem name and version
			var name, version string

			if strings.Contains(line, "'") {
				start := strings.Index(line, "'") + 1
				end := strings.Index(line[start:], "'")
				if end > 0 {
					name = line[start : start+end]
					// Look for version specification after the name
					rest := line[start+end+1:]
					if strings.Contains(rest, "'") || strings.Contains(rest, "\"") {
						// Extract version from second quoted string
						var versionStart, versionEnd int
						if strings.Contains(rest, "'") {
							versionStart = strings.Index(rest, "'") + 1
							versionEnd = strings.Index(rest[versionStart:], "'")
						} else if strings.Contains(rest, "\"") {
							versionStart = strings.Index(rest, "\"") + 1
							versionEnd = strings.Index(rest[versionStart:], "\"")
						}
						if versionEnd > 0 {
							version = rest[versionStart : versionStart+versionEnd]
						}
					}
				}
			} else if strings.Contains(line, "\"") {
				start := strings.Index(line, "\"") + 1
				end := strings.Index(line[start:], "\"")
				if end > 0 {
					name = line[start : start+end]
					// Look for version specification after the name
					rest := line[start+end+1:]
					if strings.Contains(rest, "'") || strings.Contains(rest, "\"") {
						var versionStart, versionEnd int
						if strings.Contains(rest, "'") {
							versionStart = strings.Index(rest, "'") + 1
							versionEnd = strings.Index(rest[versionStart:], "'")
						} else if strings.Contains(rest, "\"") {
							versionStart = strings.Index(rest, "\"") + 1
							versionEnd = strings.Index(rest[versionStart:], "\"")
						}
						if versionEnd > 0 {
							version = rest[versionStart : versionStart+versionEnd]
						}
					}
				}
			}

			if name != "" {
				packages = append(packages, Software{
					Name:    name,
					Version: version,
				})
			}
		}
	}

	return packages
}

// extractDotnetPackages parses .NET project files for dependencies
func extractDotnetPackages(dir string) []Software {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return []Software{}
	}

	// Find the first .csproj, .vbproj, or .fsproj file
	var projFile string
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasSuffix(name, ".csproj") ||
			strings.HasSuffix(name, ".vbproj") ||
			strings.HasSuffix(name, ".fsproj") {
			projFile = filepath.Join(dir, name)
			break
		}
	}

	if projFile == "" {
		return []Software{}
	}

	data, err := os.ReadFile(projFile)
	if err != nil {
		return []Software{}
	}

	return parseDotnetProjectFile(string(data))
}

// parseDotnetProjectFile extracts NuGet package references from .csproj/.vbproj/.fsproj
func parseDotnetProjectFile(content string) []Software {
	var packages []Software

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Look for <PackageReference Include="PackageName" Version="..." />
		if strings.Contains(line, "PackageReference") && strings.Contains(line, "Include") {
			// Extract Include attribute value (package name)
			var pkgName string
			start := strings.Index(line, "Include=\"") + len("Include=\"")
			end := strings.Index(line[start:], "\"")
			if end > 0 {
				pkgName = line[start : start+end]
			}

			// Extract Version attribute value
			var version string
			if versionIdx := strings.Index(line, "Version=\""); versionIdx >= 0 {
				start := versionIdx + len("Version=\"")
				end := strings.Index(line[start:], "\"")
				if end > 0 {
					version = line[start : start+end]
				}
			}

			if pkgName != "" {
				packages = append(packages, Software{
					Name:    pkgName,
					Version: version,
				})
			}
		}
	}

	return packages
}

// extractXmlValue is a helper to extract simple XML tag values
func extractXmlValue(line string, tag string) string {
	openTag := "<" + tag + ">"
	closeTag := "</" + tag + ">"

	start := strings.Index(line, openTag)
	end := strings.Index(line, closeTag)

	if start >= 0 && end > start {
		return line[start+len(openTag) : end]
	}

	return ""
}

// fileExists checks if a file exists
func checkFileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func ListCodeScannerProjects() []ProjectInfo {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting home directory: %v\n", err)
	}

	scanner := NewScanner()
	projects, err := scanner.Scan(homeDir)
	if err != nil {
		log.Printf("[ERROR] Problem in codescanner: %v\n", err)
	} 

	parsedProjects := []ProjectInfo{}
	for _, project := range projects { 
		if len(project.Path) == 0 {
			continue
		}

		if project.Packages == nil || len(project.Packages) == 0 {
			continue
		}

		parsedProjects = append(parsedProjects, project)
	}

	return parsedProjects 
}

type MacApp struct {
	Name          string `json:"_name"`
	Version       string `json:"version"`
	BundleVersion string `json:"bundle_version"`
	Path          string `json:"path"`
	Info string `json:"info"`
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
		version := app.Version
		if version == "" {
			version = app.BundleVersion
		}

		if version == "" {
			version = app.Info
		}

		result = append(result, Software{
			Name:    app.Name,
			Version: version,
		})
	}

	return result
}
