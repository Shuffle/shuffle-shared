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
