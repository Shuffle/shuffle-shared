package shuffle

import (
	"net/http"
	"fmt"
	"strconv"
	"io/ioutil"
	"encoding/json"
	"log"
	"strings"
	"context"
	"errors"
	"time"
	"math/rand"
	"runtime"
	"os/exec"
	"os"
	"bufio"
	"regexp"
	"bytes"
	"path/filepath"
	"io"
)

func GetCorrelations(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[AUDIT] Authentication failed in GetCorrelations: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Authentication failed"}`))
		return
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Printf("[WARNING] Failed to read body in GetCorrelations: %s", err)
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false, "reason": "Invalid input body"}`))
		return
	}

	correlationData := CorrelationRequest{} 
	err = json.Unmarshal(body, &correlationData)
	if err != nil {
		log.Printf("[WARNING] Failed to parse JSON in GetCorrelations: %s", err)
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false, "reason": "Invalid JSON format"}`))
		return
	}

	ctx := GetContext(request)
	correlations := []NGramItem{}
	if len(correlationData.Category) == 0 {
		searchKey := fmt.Sprintf("%s", correlationData.Key)
		ngramItem, err := GetDatastoreNGramItem(ctx, searchKey)
		if err != nil {
			log.Printf("[WARNING] Failed to get ngram item in GetCorrelations: %s", err)
			resp.WriteHeader(400)
			resp.Write([]byte(`{"success": false, "reason": "No correlations found"}`))
			return
		}

		correlations = []NGramItem{*ngramItem}
	} else {
		searchKey := fmt.Sprintf("%s|%s", correlationData.Category, correlationData.Key)
		availableTypes := []string{"datastore"}
		if len(correlationData.Type) == 0 { 
			correlationData.Type = "datastore" 
		}

		if correlationData.Type == "datastore" {
			// Nothing to do as we have the right key already
		} else {
			log.Printf("[WARNING] Invalid type in GetCorrelations: %#v. Available types: %#v", correlationData.Type, strings.Join(availableTypes, ", "))
			resp.WriteHeader(400)
			resp.Write([]byte(`{"success": false, "reason": "Invalid type"}`))
			return
		}

		correlations, err = GetDatastoreNgramItems(ctx, user.ActiveOrg.Id, searchKey, 50)
		if err != nil {
			log.Printf("[ERROR] Failed to get correlations from DB in GetCorrelations: %s", err)
			resp.WriteHeader(500)
			resp.Write([]byte(`{"success": false, "reason": "Internal server error"}`))
			return
		}
	}

	newCorrelations := []NGramItem{}
	for _, item := range correlations {
		if item.OrgId != user.ActiveOrg.Id {
			continue
		}

		item.OrgId = ""
		newCorrelations = append(newCorrelations, item)
	}

	correlations = newCorrelations
	marshalledCorrelations, err := json.Marshal(correlations)
	if err != nil {
		log.Printf("[ERROR] Failed to marshal correlations in GetCorrelations: %s", err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false, "reason": "Internal server error: Failed to marshal correlations"}`))
		return
	}

	resp.WriteHeader(200)
	resp.Write([]byte(marshalledCorrelations))

}

// Used to cross-correlate data
// Not YET doing proper ngram by breaking everything down, but it's easy to
// Modify this into doing that as well

// Issues:
// Only does strings
// Only does top-level in JSON (no recursion)
func crossCorrelateNGrams(ctx context.Context, orgId, category, datastoreKey, value string, enrichments []Observable) error {
	if len(orgId) == 0 || len(category) == 0 || len(datastoreKey) == 0 || len(value) == 0 {
		return errors.New("Invalid parameters for cross-correlate ngrams. All parameters must be set. orgId, category, key, value")
	}

	// Skipping searchability for protected keys
	if strings.ToLower(category) == "protected" {
		return nil
	}

	// Random sleeptime between 0-1000ms because we're inside a goroutine
	// and want to ensure there aren't a ton of concurrent writes to the datastore
	time.Sleep(time.Duration(rand.Intn(1000)) * time.Millisecond)

	unmarshalled := map[string]interface{}{}
	if err := json.Unmarshal([]byte(value), &unmarshalled); err != nil {
		log.Printf("[WARNING] Failed unmarshalling value for cross-correlate ngrams: %s. Storing the key directly.", err)
		unmarshalled = map[string]interface{}{
			"key": value,
		}
	}

	// Simple workaround for dates
	// hardcoded for now just to remove certain things
	skippableKeys := []string{"spec_version", "version", "pattern_type", "created", "edited", "creation"}
	skippableValues := []string{"indicator", "stix", "active"}
	invalidStarts := []string{"[", "{", "$", "202", "203", "204"} // Specific for timestamps

	//for jsonKey, val := range unmarshalled {
	amountAdded := 0
	maxAmountToAdd := 5
	for jsonKey, val := range unmarshalled {
		if ArrayContains(skippableKeys, jsonKey) {
			continue
		}

		// Only handle strings for now
		if val == nil {
			continue
		}

		if _, ok := val.(string); !ok {
			// FIXME: Check here if it's a map, then recurse down
			// to find more string
			continue
		}

		parsedValue := val.(string)

		// FIXME: Arbitrary limits
		// About ngram: We will want to do additional splitting,
		// but to start with, we just do the whole thing
		if len(parsedValue) > 70 || len(parsedValue) < 2 {
			continue
		}

		skip := false
		for _, invalidStart := range invalidStarts {
			if strings.HasPrefix(parsedValue, invalidStart) {
				skip = true
				break
			}
		}

		if skip || ArrayContains(skippableValues, parsedValue) {
			continue
		}

		if strings.HasPrefix(parsedValue, "$") {
			continue
		}

		// Make sure we don't add more than 5 items (for now)
		if amountAdded > maxAmountToAdd {
			break
		}

		parsedValue = strings.ToLower(strings.TrimSpace(
			strings.ReplaceAll(
				strings.ReplaceAll(
					parsedValue, "\n", "",
				), " ", "",
			),
		))

		parsedCategory := strings.ToLower(strings.ReplaceAll(category, " ", "_"))

		// Doing it WITHOUT the JSON key & Org, as we only want to partially cross-correlate to find items among each other
		referenceKey := fmt.Sprintf("%s|%s", parsedCategory, datastoreKey)

		// FIXME: May need to hash the parsedValue to make search work well
		// as we are doing the full string right now
		ngramSearchKey := fmt.Sprintf("%s_%s", orgId, parsedValue)
		ngramItem, err := GetDatastoreNGramItem(ctx, ngramSearchKey)

		// FIXME: Key may disappear/be overwritten if connectivity to backend fails briefly?
		if err != nil || ngramItem == nil || ngramItem.Key == "" {
			ngramItem = &NGramItem{
				Key:   parsedValue,
				OrgId: orgId,

				Amount: 1,
				Ref: []string{
					referenceKey,
				},
			}

			err = SetDatastoreNGramItem(ctx, ngramSearchKey, ngramItem)
			if err != nil {
				log.Printf("[WARNING] Failed setting ngram item for cross-correlate: %s", err)
			}

			amountAdded += 1
			if debug { 
				log.Printf("[DEBUG] Created new ngram item for %s with key '%s'", ngramSearchKey, parsedValue)
			}
			continue
		}

		if ArrayContains(ngramItem.Ref, referenceKey) {
			continue
		}

		// Add the reference to the ngram item
		amountAdded += 1
		ngramItem.Ref = append(ngramItem.Ref, referenceKey)
		ngramItem.Amount = len(ngramItem.Ref)

		err = SetDatastoreNGramItem(ctx, ngramSearchKey, ngramItem)
		if err != nil {
			log.Printf("[WARNING] Failed setting ngram item for cross-correlate: %s", err)
		} else {
			if debug { 
				log.Printf("[DEBUG] Updated ngram item for %s with key %s", ngramSearchKey, parsedValue)
			}
		}

		log.Println()
	}

	for enrichmentCnt, enrichment := range enrichments {
		if enrichmentCnt > 50 {
			break
		}

		parsedValue := strings.ToLower(strings.TrimSpace(
			strings.ReplaceAll(
				strings.ReplaceAll(
					enrichment.Value, "\n", "",
				), " ", "",
			),
		))

		parsedCategory := strings.ToLower(strings.ReplaceAll(category, " ", "_"))

		// Doing it WITHOUT the JSON key & Org, as we only want to partially cross-correlate to find items among each other
		referenceKey := fmt.Sprintf("%s|%s", parsedCategory, datastoreKey)

		// FIXME: May need to hash the parsedValue to make search work well
		// as we are doing the full string right now
		ngramSearchKey := fmt.Sprintf("%s_%s", orgId, parsedValue)
		ngramItem, err := GetDatastoreNGramItem(ctx, ngramSearchKey)

		// FIXME: Key may disappear/be overwritten if connectivity to backend fails briefly?
		if err != nil || ngramItem == nil || ngramItem.Key == "" {
			ngramItem = &NGramItem{
				Key:   parsedValue,
				OrgId: orgId,

				Amount: 1,
				Ref: []string{
					referenceKey,
				},
			}

			err = SetDatastoreNGramItem(ctx, ngramSearchKey, ngramItem)
			if err != nil {
				log.Printf("[WARNING] Failed setting ngram item for cross-correlate: %s", err)
			}

			amountAdded += 1
			if debug { 
				log.Printf("[DEBUG] Created new ngram item for %s with key '%s'", ngramSearchKey, parsedValue)
			}

			continue
		}

		if ArrayContains(ngramItem.Ref, referenceKey) {
			continue
		}

		// Add the reference to the ngram item
		amountAdded += 1
		ngramItem.Ref = append(ngramItem.Ref, referenceKey)
		ngramItem.Amount = len(ngramItem.Ref)

		err = SetDatastoreNGramItem(ctx, ngramSearchKey, ngramItem)
		if err != nil {
			log.Printf("[WARNING] Failed setting ngram item for cross-correlate: %s", err)
		} else {
			if debug { 
				log.Printf("[DEBUG] Updated ngram item for %s with key %s", ngramSearchKey, parsedValue)
			}
		}
	}

	return nil

}

func parseInt(s string) int {
	s = strings.TrimSpace(s)
	val, err := strconv.Atoi(s)
	if err != nil {
		return 0 // default to 0 if parse fails
	}
	return val
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

// MINOR validation:
// RCECleanup sanitizes a command string to reduce attack surface
// It removes/escapes shell metacharacters and dangerous patterns
func RCECleanup(command string) string {
	if strings.HasPrefix(command, "script:") {
		return command 
	}

	// Not allowing large commands at all (for now)
	maxCommandSize := 50
	if os.Getenv("RCE_MAX_COMMAND_SIZE") != "" {
		envSize := parseInt(os.Getenv("RCE_MAX_COMMAND_SIZE"))
		if envSize > 0 {
			maxCommandSize = envSize
		}
	}

	if len(command) > maxCommandSize { 
		return ""
	}

	// Trim whitespace
	command = strings.TrimSpace(command)

	// Remove shell operators
	dangerous := []string{
		";",  // Command chaining
		"|",  // Pipes
		"&",  // Background/AND
		">",  // Redirect
		"<",  // Redirect
		"`",  // Command substitution
		"$",  // Variable expansion
		"\\", // Escape character
	}

	for _, char := range dangerous {
		command = strings.ReplaceAll(command, char, "")
	}

	// Remove control characters (0x00-0x1F except tab/newline)
	re := regexp.MustCompile(`[\x00-\x08\x0B-\x1F\x7F]`)
	command = re.ReplaceAllString(command, "")

	// Collapse multiple spaces
	command = strings.Join(strings.Fields(command), " ")

	return command
}

type StreamFn func(line string)
func RunCommandString(
	command string,
	timeout time.Duration,
	onStream StreamFn,
) (string, error) {

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var cmd *exec.Cmd

	// Use system shell to interpret full command string
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "cmd", "/C", command)
	} else {
		cmd = exec.CommandContext(ctx, "sh", "-c", command)
	}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return "", err
	}

	if err := cmd.Start(); err != nil {
		return "", err
	}

	var output bytes.Buffer

	readStream := func(scanner *bufio.Scanner) {
		// increase max token size (important for long lines)
		buf := make([]byte, 0, 64*1024)
		scanner.Buffer(buf, 1024*1024)

		for scanner.Scan() {
			line := scanner.Text()
			output.WriteString(line + "\n")

			if onStream != nil {
				onStream(line)
			}
		}
	}

	done := make(chan struct{}, 2)

	go func() {
		readStream(bufio.NewScanner(stdoutPipe))
		done <- struct{}{}
	}()

	go func() {
		readStream(bufio.NewScanner(stderrPipe))
		done <- struct{}{}
	}()

	<-done
	<-done

	err = cmd.Wait()

	if ctx.Err() == context.DeadlineExceeded {
		return output.String(), fmt.Errorf("command timed out after %s", timeout)
	}

	return output.String(), err
}

func HandleSensorResponseAction(sensorDetails SensorMode, incRequest ExecutionRequest) {
	if len(incRequest.ExecutionId) == 0 || len(incRequest.Authorization) == 0 {
		log.Printf("[WARNING] Invalid execution request: missing execution ID or action")
		return
	}

	if sensorDetails.ResponseActions != "controlled" && sensorDetails.ResponseActions != "full" {
		return 
	}

	if incRequest.Start == "" { 
		log.Printf("[WARNING] Invalid execution request: missing start ID for action reference")
		return
	}

	// From Orborus
	backendUrl := os.Getenv("BASE_URL")
	if backendUrl == "" {
		log.Printf("[ERROR] BASE_URL environment variable not set. Cannot execute response action.")
		return
	}

	command := incRequest.ExecutionArgument
	if sensorDetails.ResponseActions == "controlled" { 
		if !strings.HasPrefix(command, "script:") { 
			log.Printf("[WARNING] Invalid execution argument for controlled response action: %s. Must start with 'script:', which points to a valid cloud script.", command)
			return
		}
	}

	command = RCECleanup(command)

	var out string
	var err error
	if strings.HasPrefix(command, "script:") { 
		log.Printf("[ERROR] Script-based response actions are not yet available. Cannot execute script: %s", command)

		out = "Not available yet"
		err = fmt.Errorf("script-based response actions are not available yet")
	} else { 
		if len(command) == 0 {
			return
		}

		if debug { 
			log.Printf("[DEBUG] RUNNING COMMAND '%s'", command)
		}

		out, err = RunCommandString(
			command,
			30*time.Second,
			func(line string) {
				if debug { 
					fmt.Println("DEBUG STREAM:", command, line)
				}
			},
		)
	}

	parsedResult := RCEResult{
		Success: true,
		Command: command,
		Output: out,
		Error: "",
	}

	if err != nil { 
		parsedResult.Success = false
		parsedResult.Error = err.Error()
	}

	marshalledResult, err := json.Marshal(parsedResult)
	if err != nil {
		log.Printf("[ERROR][%s] Failed to marshal RCE result: %s", incRequest.ExecutionId, err)
		return
	}

	// From Orborus
	fullUrl := fmt.Sprintf("%s/api/v1/streams", backendUrl)
	topClient := GetExternalClient(fullUrl)

	if debug { 
		log.Printf("[DEBUG] INCREQUEST: %#v", incRequest)
	}

	fullResult := ActionResult{ 
		ExecutionId: incRequest.ExecutionId,
		Authorization: incRequest.Authorization,
		Action: Action{
			AppName: "sensor",
			AppID: "sensor",
			ID: incRequest.Start,
		},
		Result: string(marshalledResult),
	}

	fullResultData, err := json.Marshal(fullResult)
	if err != nil {
		log.Printf("[ERROR][%s] Failed to marshal action result: %s", incRequest.ExecutionId, err)
		return 
	}

	req, err := http.NewRequest(
		"POST",
		fullUrl,
		bytes.NewBuffer([]byte(fullResultData)),
	)

	if err != nil { 
		log.Printf("[ERROR][%s] Failed to create HTTP request for response action result: %s", incRequest.ExecutionId, err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	resp, err := topClient.Do(req)
	if err != nil {
		log.Printf("[ERROR][%s] Failed to send response action result: %s", incRequest.ExecutionId, err)
		return
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[ERROR][%s] Failed to read response body after sending action result: %s", incRequest.ExecutionId, err)
		return
	}

	if resp.StatusCode != 200 {
		log.Printf("[ERROR][%s] Received non-200 response when sending action result to %s: %d. Body: %s", fullUrl, incRequest.ExecutionId, resp.StatusCode, string(respBody))
		return
	}

	log.Printf("[INFO][%s] Successfully sent command action result. Status: %d, Result: %s. Bytes sent: %d", incRequest.ExecutionId, resp.StatusCode, string(respBody), len(fullResultData))
}
