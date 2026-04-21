package shuffle

import (
	"net/http"
	"net/url"
	"fmt"
	"strconv"
	"io/ioutil"
	"encoding/json"
	"log"
	"time"
	"strings"
	"context"
	"errors"
	"math/rand"
	"os"
	"regexp"
	"bytes"
	"io"
	"net"

	// For BOM scans
	//"github.com/CycloneDX/cyclonedx-gomod/pkg/generate/app"
	//"github.com/CycloneDX/cyclonedx-gomod/pkg/generate/mod"
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
	skippableKeys := []string{"spec_version", "version", "pattern_type", "created", "edited", "creation", "status"}
	skippableValues := []string{"indicator", "stix", "active", "false", "true", "inprogress", "new", "closed", "resolved", "escalated"}
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

		if skip || ArrayContains(skippableValues, strings.ToLower(parsedValue)) {
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

func HandleSensorResponseAction(hostname string, sensorDetails SensorMode, incRequest ExecutionRequest) {
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

	startTime := time.Now().Unix()

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
	if strings.HasPrefix(strings.ToLower(command), "script:") { 

		if strings.HasPrefix(command, "script:isolate") { 
			allowedIPs := []string{}

			// Nslookup the current backendUrl 
			if backendUrl != "" {
				parsedUrl, err := url.Parse(backendUrl)
				if err != nil {
					log.Printf("[ERROR] Failed to parse backend URL '%s': %s", backendUrl, err)
				} else {
					host := parsedUrl.Hostname()
					ips, err := net.LookupIP(host)
					if err != nil {
						log.Printf("[ERROR] Failed to lookup IP for host '%s': %s", host, err)
					} else {
						for _, ip := range ips {
							if ip.String() == "::1" || strings.HasPrefix(ip.String(), "127.0.0") {
								continue
							}

							allowedIPs = append(allowedIPs, ip.String())
						}
					}
				}
			}

			if len(allowedIPs) == 0 {
				out = "Failed to determine allowed IPs for isolation. Host isolation requires at least one allowed IP to be determined."
			} else {
				log.Printf("[WARNING] Isolating with URL %s. Allowed IPs: %#v", backendUrl, allowedIPs)

				err := isolateHost(allowedIPs) 
				if err != nil { 
					log.Printf("[ERROR] Failed to isolate host: %s", err)
					out = fmt.Sprintf("Failed to isolate host: %s", err.Error())
				} else {
					out = "Host isolated successfully"
					err = nil

					os.Setenv("HOST_ISOLATED", "true")
				}
			}
		} else if strings.HasPrefix(command, "script:unisolate") {
			err := unisolateHost()
			if err != nil {
				log.Printf("[ERROR] Failed to un-isolate host: %s", err)
			} else {
				out = "Host un-isolated successfully"
				os.Setenv("HOST_ISOLATED", "false")
			}
		} else if strings.HasPrefix(command, "script:cbom ") { 
			filepath := strings.TrimPrefix(command, "script:cbom ")
			out = fmt.Sprintf("CBOM scan of '%s' is not available yet", filepath)
			err = nil

			// For scanning a module at a specific path:
			//app.NewGenerator(moduleDir) - For scanning applications
			//bin.NewGenerator(binaryPath) - For scanning compiled binaries

			//generator, err := mod.NewGenerator(
			/*
			generator, err := app.NewGenerator(
				filepath,
			)
			if err != nil {
				log.Printf("[ERROR] Failed to create CBOM generator: %s", err)
				out = fmt.Sprintf("Failed to create CBOM gen: %s", err.Error())
			} else {
				bom, err := generator.Generate()
				if err != nil {
					log.Printf("[ERROR] Failed to generate CBOM: %s", err)
					out = fmt.Sprintf("Failed run cbom generate: %s", err.Error())
				} else {
					outBytes, err := json.Marshal(bom)
					if err != nil {
						log.Printf("[ERROR] Failed to marshal CBOM output: %s", err)
						out = fmt.Sprintf("Failed to marshal CBOM: %s", err.Error())
					} else {
						out = string(outBytes)
					}
				}
			}
			*/

		} else {
			log.Printf("[ERROR] Script-based response actions are not yet available. Cannot execute script: %s", command)

			out = "Not available yet"
			err = fmt.Errorf("script-based response actions are not available yet")
		}
	} else { 
		if len(command) == 0 {
			return
		}

		if debug { 
			log.Printf("[DEBUG] RUNNING COMMAND '%s'", command)
		}

		out, err = RunCommandString(
			command,
			10*time.Second,
			func(line string) {
				if debug { 
					fmt.Println("DEBUG STREAM:", command, line)
				}
			},
		)
	}

	if debug { 
		log.Printf("[DEBUG] Command output: '%s'. Error: %s", out, err)
	}

	parsedResult := RCEResult{
		Success: true,
		Hostname: hostname,
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
		StartedAt: startTime,
		CompletedAt: time.Now().Unix(),
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

type StreamFn func(line string)

func truncateString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func sanitizePURL(name string) string {
	return strings.ToLower(strings.ReplaceAll(name, " ", "-"))
}

func nvdTagsToOSVRefType(tags []string) string {
	for _, tag := range tags {
		switch strings.ToLower(tag) {
		case "patch", "fix":
			return "FIX"
		case "exploit":
			return "EVIDENCE"
		case "issue tracking", "third party advisory":
			return "REPORT"
		case "vendor advisory":
			return "ADVISORY"
		case "mailing list", "technical description":
			return "ARTICLE"
		}
	}
	return "WEB"
}

// cvssScoreToSeverity maps a CVSS base score to a severity label.
func cvssScoreToSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	case score > 0:
		return "LOW"
	default:
		return "UNKNOWN"
	}
}

func stripNoise(name string) string {
	noiseTokens := []string{
		"(x64)", "(x86)", "(arm64)", "(aarch64)",
		"64-bit", "32-bit", "arm64", "aarch64",
		" sdk", " runtime", " redistributable",
		" service pack", " update", " patch",
		".app", ".exe",
	}
	lower := strings.ToLower(name)
	for _, tok := range noiseTokens {
		lower = strings.ReplaceAll(lower, tok, "")
	}
	return strings.TrimSpace(lower)
}

// replaceCPEVersion swaps the version field (part [5]) in a CPE 2.3 string.
func replaceCPEVersion(cpe, version string) string {
	if version == "" {
		return cpe
	}
	parts := strings.Split(cpe, ":")
	// cpe:2.3:type:vendor:product:VERSION:...
	//  0   1    2    3       4      5
	if len(parts) < 6 {
		return cpe
	}
	parts[5] = version
	return strings.Join(parts, ":")
}

// Special NVD handler
func (c *NVDClient) get(endpoint string, params url.Values) (*http.Response, error) {
	u := "https://services.nvd.nist.gov/rest/json/" + endpoint + "?" + params.Encode()
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, err
	}
	if c.apiKey != "" {
		req.Header.Set("apiKey", c.apiKey)
	}
	// NVD recommends a short sleep between requests when paginating.
	// With an API key you get 50 req/30s; without, 5 req/30s.
	// Caller is responsible for rate-limiting across concurrent use.
	return c.httpClient.Do(req)
}

func (c *NVDClient) resolveCPE(name, version string) (string, error) {
	cleaned := stripNoise(name)

	params := url.Values{}
	params.Set("keywordSearch", cleaned)
	params.Set("resultsPerPage", "100")

	resp, err := c.get("cpes/2.0", params)
	if err != nil {
		log.Printf("[ERROR] CPE search request failed for query %q: %s", cleaned, err)
		return "", fmt.Errorf("CPE search request: %w", err)
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("[ERROR] CPE search HTTP %d for query %q", resp.StatusCode, cleaned)
		return "", fmt.Errorf("CPE search HTTP %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[ERROR] CPE search read body failed for query %q: %s", cleaned, err)
		return "", fmt.Errorf("CPE search read body: %w", err)
	}

	var result NVDCPEResponse
	err = json.Unmarshal(body, &result)
	if err != nil {
		log.Printf("[ERROR] CPE search decode failed for query %q: %s", cleaned, err)
		return "", fmt.Errorf("CPE search decode: %w", err)
	}

	if len(result.Products) == 0 {
		log.Printf("[INFO] No CPEs found for query %q", cleaned)
		return "", fmt.Errorf("no CPE found for %q", name)
	}

	// Pick the CPE whose product segment most closely matches our name,
	// then inject the caller-supplied version into the CPE string.
	best := result.Products[0].CPE.CPEName
	bestScore := 0
	cleanedWords := strings.Fields(cleaned)

	// FIXME: Use the oldest version from the last 10 years somehow?
	// Or how should it be done? The goal is to grab as many CVEs as possible
	// IF the version itself can't be found
	for _, p := range result.Products {
		if len(version) > 5 && strings.Contains(strings.ToLower(p.CPE.CPEName), cleaned) && strings.Contains(strings.ToLower(p.CPE.CPEName), version) {
			return p.CPE.CPEName, nil
		}

		// Has to be within the last 10 years
		// Parse it from string first (2026-04-18T15:27:02.827)
		lastModified, err := time.Parse("2006-01-02T15:04:05.999", p.CPE.LastModified)
		if err != nil {
			log.Printf("[ERROR] Failed to parse last modified date for CPE %s. Date: %s: %s", p.CPE.CPEName, p.CPE.LastModified, err)
			continue
		}

		if lastModified.Before(time.Now().AddDate(-10, 0, 0)) {
			continue
		}

		cpe := p.CPE.CPEName
		score := 0
		cpeLower := strings.ToLower(cpe)
		for _, word := range cleanedWords {
			if strings.Contains(cpeLower, word) {
				score++
			}
		}

		if score > bestScore {
			bestScore = score
			best = cpe
		}
	}

	// CPE format: cpe:2.3:a:vendor:product:VERSION:...
	// Replace the version segment (index 5) with the supplied version.
	return replaceCPEVersion(best, version), nil
}

// buildOSVRange converts an NVD CPE match string into an OSV ECOSYSTEM range.
func buildOSVRange(match NVDCPEMatch) *OSVRange {
	var events []OSVEvent

	introduced := match.VersionStartIncluding
	if introduced == "" && match.VersionStartExcluding == "" {
		introduced = "0" // open-ended start
	}
	if introduced != "" {
		events = append(events, OSVEvent{Introduced: introduced})
	} else if match.VersionStartExcluding != "" {
		// OSV doesn't have a direct "start excluding" — use introduced="0"
		// and note this is an approximation.
		events = append(events, OSVEvent{Introduced: "0"})
	}

	if match.VersionEndExcluding != "" {
		events = append(events, OSVEvent{Fixed: match.VersionEndExcluding})
	} else if match.VersionEndIncluding != "" {
		events = append(events, OSVEvent{LastAffected: match.VersionEndIncluding})
	}

	if len(events) == 0 {
		return nil
	}

	return &OSVRange{
		Type:   "ECOSYSTEM",
		Events: events,
	}
}

type NVDClient struct {
	apiKey     string
	httpClient *http.Client
}

func NewNVDClient() *NVDClient {
	return &NVDClient{
		apiKey: os.Getenv("NVD_APIKEY"),
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func NVDToOSV(nvd NVDCVEDetail, softwareName, version string) OSVVulnerability {

	lastModified, err := time.Parse("2006-01-02T15:04:05.999", nvd.LastModified)
	if err != nil {
		log.Printf("[ERROR] Failed to parse last modified date for CVE %s: %s", nvd.ID, err)
	}

	published, err := time.Parse("2006-01-02T15:04:05.999", nvd.Published)
	if err != nil {
		log.Printf("[ERROR] Failed to parse published date for CVE %s: %s", nvd.ID, err)
	}

	osv := OSVVulnerability{
		SchemaVersion: "1.4.0",
		ID:            nvd.ID,
		Modified:      lastModified,
		Published:     published,
	}

	// Summary = first English description (truncated to ~120 chars for the field).
	for _, d := range nvd.Descriptions {
		if d.Lang == "en" {
			osv.Summary = truncateString(d.Value, 120)
			osv.Details = d.Value
			break
		}
	}

	// Aliases: NVD ID is authoritative; no additional aliases from this API.
	// (If you have GHSA data, you'd add them here.)

	// References — map NVD tags to OSV reference types.
	for _, ref := range nvd.References {
		osv.References = append(osv.References, OSVReference{
			Type: nvdTagsToOSVRefType(ref.Tags),
			URL:  ref.URL,
		})
	}
	// Always add the NVD page itself.
	osv.References = append(osv.References, OSVReference{
		Type: "ADVISORY",
		URL:  "https://nvd.nist.gov/vuln/detail/" + nvd.ID,
	})

	// Severity — prefer CVSS v3.1, fall back to v3.0, then v2.
	var cvssVector string
	var cvssScore float64
	var cvssType string

	switch {
	case len(nvd.Metrics.CVSSMetricV31) > 0:
		m := nvd.Metrics.CVSSMetricV31[0]
		cvssVector = m.CVSSData.VectorString
		cvssScore = m.CVSSData.BaseScore
		cvssType = "CVSS_V3"
	case len(nvd.Metrics.CVSSMetricV30) > 0:
		m := nvd.Metrics.CVSSMetricV30[0]
		cvssVector = m.CVSSData.VectorString
		cvssScore = m.CVSSData.BaseScore
		cvssType = "CVSS_V3"
	case len(nvd.Metrics.CVSSMetricV2) > 0:
		m := nvd.Metrics.CVSSMetricV2[0]
		cvssVector = m.CVSSData.VectorString
		cvssScore = m.CVSSData.BaseScore
		cvssType = "CVSS_V2"
	}

	if cvssVector != "" {
		osv.Severity = []OSVSeverity{{Type: cvssType, Score: cvssVector}}
	}

	// Affected block — one entry per software item.
	affected := OSVAffected{
		Package: OSVPackage{
			Name:      softwareName,
			Ecosystem: "NVD",
			Purl:      fmt.Sprintf("pkg:generic/%s@%s", sanitizePURL(softwareName), version),
		},
		EcosystemSpecific: OSVEcosystemSpecific{
			Severity: cvssScoreToSeverity(cvssScore),
		},
		DatabaseSpecific: OSVDatabaseSpecific{
			Source: "https://nvd.nist.gov/vuln/detail/" + nvd.ID,
		},
	}

	// Version ranges from CPE match data.
	var ranges []OSVRange
	for _, config := range nvd.Configurations {
		for _, node := range config.Nodes {
			for _, match := range node.CPEMatch {
				if !match.Vulnerable {
					continue
				}
				r := buildOSVRange(match)
				if r != nil {
					ranges = append(ranges, *r)
				}
			}
		}
	}
	if len(ranges) > 0 {
		affected.Ranges = ranges
	} else if version != "" {
		// Fallback: we know at least the queried version is affected.
		affected.Ranges = []OSVRange{{
			Type: "ECOSYSTEM",
			Events: []OSVEvent{
				{Introduced: version},
			},
		}}
	}

	osv.Affected = []OSVAffected{affected}

	// database_specific: carry CISA KEV data if present.
	if nvd.CISAExploitAdd != "" {
		osv.DatabaseSpecific = OSVDatabaseSpecific{
			DateAdded:      nvd.CISAExploitAdd,
			ActionDue:      nvd.CISAActionDue,
			RequiredAction: nvd.CISARequiredAction,
			Vulnerability:   nvd.CISAVulnerabilityName,
		}
	}

	// CWE weaknesses → database_specific on the top-level.
	var cwes []string
	for _, w := range nvd.Weaknesses {
		for _, d := range w.Description {
			if d.Lang == "en" {
				cwes = append(cwes, d.Value)
			}
		}
	}
	if len(cwes) > 0 {
		osv.DatabaseSpecific.CWEs = cwes
	}

	return osv
}

func (c *NVDClient) fetchCVEsForCPE(cpeName string) ([]NVDCVEDetail, error) {
	maxAmount := 100
	const pageSize = 100
	var all []NVDCVEDetail
	startIndex := 0

	for {
		if len(all) >= maxAmount {
			break
		}

		params := url.Values{}
		params.Set("cpeName", cpeName)
		params.Set("resultsPerPage", fmt.Sprintf("%d", pageSize))
		params.Set("startIndex", fmt.Sprintf("%d", startIndex))

		resp, err := c.get("cves/2.0", params)
		if err != nil {
			log.Printf("[ERROR] CVE fetch request failed for CPE %q: %s", cpeName, err)
			break
		}

		if resp.StatusCode != http.StatusOK {
			log.Printf("[ERROR] CVE fetch HTTP %d for CPE %q", resp.StatusCode, cpeName)
			resp.Body.Close()
			break
		}

		var page NVDCVEResponse
		if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
			log.Printf("[ERROR] CVE fetch decode failed for CPE %q: %s", cpeName, err)
			resp.Body.Close()
			break
		}

		resp.Body.Close()
		for _, item := range page.Vulnerabilities {
			all = append(all, item.CVE)
		}

		startIndex += page.ResultsPerPage
		if startIndex >= page.TotalResults {
			break
		}

		// Respect NVD rate limits between pages.
		log.Printf("[DEBUG] Fetched %d CVEs for CPE %q, total so far: %d. Sleeping before next page...", len(page.Vulnerabilities), cpeName, len(all))
		if len(all) >= maxAmount {
			break
		}

		time.Sleep(600 * time.Millisecond)
	}

	return all, nil
}

// LookupVulnerabilities takes a software name and version, queries NVD,
// and returns a slice of OSV-schema vulnerabilities.
func LookupNVDVulnerabilities(ctx context.Context, name, version string) ([]OSVVulnerability, error) {
	client := NewNVDClient()

	cpeName, err := client.resolveCPE(name, version)
	if err != nil {
		return nil, fmt.Errorf("resolve CPE for %q: %w", name, err)
	}

	if !strings.Contains(strings.ToLower(cpeName), stripNoise(name)) {
		return nil, fmt.Errorf("resolved CPE %q does not contain software name %q; likely no relevant CVEs", cpeName, name)
	}

	cves, err := client.fetchCVEsForCPE(cpeName)
	if err != nil {
		return nil, fmt.Errorf("fetch CVEs for CPE %q: %w", cpeName, err)
	}

	//osvVulns := make([]OSVVulnerability, 0, len(cves))
	osvVulns := []OSVVulnerability{}
	for _, cve := range cves {
		translated := NVDToOSV(cve, name, version)
		
		osvVulns = append(osvVulns, translated)
		go SetVulnerability(ctx, translated)
		break
	}

	return osvVulns, nil
}

// the caller can enrich them if needed.
func LookupCVEByID(cveID string) (*OSVVulnerability, error) {
	client := NewNVDClient()

	params := url.Values{}
	params.Set("cveId", cveID)

	resp, err := client.get("cves/2.0", params)
	if err != nil {
		return nil, fmt.Errorf("CVE lookup request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("CVE %q not found", cveID)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CVE lookup HTTP %d", resp.StatusCode)
	}

	var result NVDCVEResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("CVE lookup decode: %w", err)
	}

	if len(result.Vulnerabilities) == 0 {
		return nil, fmt.Errorf("CVE %q not found", cveID)
	}

	osv := NVDToOSV(result.Vulnerabilities[0].CVE, "", "")
	return &osv, nil
}

func GetVulnerability(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	gceProject := os.Getenv("SHUFFLE_GCEPROJECT")
	if gceProject != "shuffler" && gceProject != sandboxProject && len(gceProject) > 0 {
		log.Printf("[DEBUG] Redirecting request to vulnerability endpoint to avoid hitting quota for project %s", gceProject)
		RedirectUserRequest(resp, request)
		return
	}

	// Rate limit IF no auth
	_, err := HandleApiAuthentication(resp, request)
	if err != nil {
		// Rate limit
		err := ValidateRequestOverload(resp, request)
		if err != nil {
			log.Printf("[INFO] Request overload for IP %s in get vulnerability", GetRequestIp(request))
			resp.WriteHeader(429)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Too many requests"}`)))
			return
		}
	}

	requestVuln := VulnerabilityQuery{}
	if request.Method == "GET" { 
		// Check for an ID to get in /api/v1/vulnerability/{id}
		pathParts := strings.Split(request.URL.Path, "/")
		if len(pathParts) == 5 && pathParts[4] != "" {
			requestVuln.ID = pathParts[4]
		}
	} else {
		body, err := ioutil.ReadAll(request.Body)
		if err != nil {
			log.Printf("[WARNING] Failed to read body in GetVulnerability: %s", err)
			resp.WriteHeader(400)
			resp.Write([]byte(`{"success": false, "reason": "Invalid input body"}`))
			return
		}

		err = json.Unmarshal(body, &requestVuln)
		if err != nil {
			log.Printf("[WARNING] Failed to parse JSON in GetVulnerability: %s", err)
			resp.WriteHeader(400)
			resp.Write([]byte(`{"success": false, "reason": "Invalid JSON format"}`))
			return
		}
	}

	ctx := context.Background()
	preparedOutput := VulnDbOutput{}
	cacheId := fmt.Sprintf("%s|%s|%s|%s", requestVuln.ID, requestVuln.Package.Name, requestVuln.Package.Ecosystem, requestVuln.Version)
	cache, err := GetCache(ctx, cacheId)
	if err == nil {
		cacheData := []byte(cache.([]uint8))
		err = json.Unmarshal(cacheData, &preparedOutput)
		//if err == nil && len(preparedOutput.Vulns) > 0 {
		if err == nil {
			resp.WriteHeader(200)
			resp.Write(cacheData)
			return
		}
	}

	// 1. Check cached response
	// 2. Check local database
	// 3. Query api.osv.dev
	// 3.1: ALWAYS get the whole detail for a package. That way we build over time
	// 3.2: Store them with the same ID that api.osv.dev uses, so we can easily check if we have it or not. We can also use that ID to update details over time as api.osv.dev updates them
	// 4. Store in local database AND cache (long-term?)

	allVulns := []OSVVulnerability{}
	vulnDbUrl := "https://api.osv.dev/v1/query"
	requestMethod := "POST"
	if len(requestVuln.ID) > 0 {
		// FIXME: can't handle old CVEs. E.g. CVE-2008-4340. Need to failover to NVD?
		vulnDbUrl = fmt.Sprintf("https://api.osv.dev/v1/vulns/%s", requestVuln.ID)
		requestMethod = "GET"
	} else {
		// Special handler with NVD (normal software - not dev)
		// Uses tons of CVSS stuff
		if (requestVuln.Package.Ecosystem == "" || requestVuln.Package.Ecosystem == "macos" || requestVuln.Package.Ecosystem == "linux" || requestVuln.Package.Ecosystem == "windows") {
			log.Printf("[DEBUG] Using NVD for vulnerability search for package '%s' in ecosystem '%s'", requestVuln.Package.Name, requestVuln.Package.Ecosystem)

			// Used in examples during test
			//vulnDbUrl = fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cpes/2.0?keywordSearch=%s", requestVuln.Package.Name)
			
			vulnerabilities, err := LookupNVDVulnerabilities(ctx, requestVuln.Package.Name, requestVuln.Version)
			log.Printf("[DEBUG] Found %d vulnerabilities in NVD for package '%s' version '%s'", len(vulnerabilities), requestVuln.Package.Name, requestVuln.Version)
			if err != nil {
				log.Printf("[ERROR] Failed to lookup vulnerabilities in NVD for package '%s' version '%s': %s", requestVuln.Package.Name, requestVuln.Version, err)
			}

			preparedOutput.Vulns = vulnerabilities 
			marshalledVulns, err := json.Marshal(preparedOutput)
			if err != nil {
				log.Printf("[ERROR][%s] Failed to marshal vulnerability information: %s", GetRequestIp(request), err)
				resp.WriteHeader(500)
				resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed to marshal vulnerability information (amount: %d): %s"}`, len(allVulns), err.Error())))
				return
			}

			// Store the specifics for 24 hours max. 
			if project.CacheDb {
				err = SetCache(ctx, cacheId, marshalledVulns, 1440)
				if err != nil {
					log.Printf("[WARNING][%s] Failed to set vulnerability information in cache: %s", GetRequestIp(request), err)
				}
			}

			resp.WriteHeader(200)
			resp.Write(marshalledVulns)
			return
		}
	}

	topClient := GetExternalClient(vulnDbUrl)
	nextPageToken := ""

	var respError error	
	for {
		if len(nextPageToken) > 0 { 
			requestVuln.PageToken = nextPageToken
		}

		preparedBody := io.NopCloser(bytes.NewBuffer(nil))
		if requestMethod == "POST" {
			marshalledBody, respError := json.Marshal(requestVuln)
			if respError != nil {
				log.Printf("[ERROR] Failed to marshal vulnerability query body: %s", respError)
				break
			}

			preparedBody = io.NopCloser(bytes.NewBuffer(marshalledBody))
		}

		req, respError := http.NewRequest(
			requestMethod,
			vulnDbUrl,
			preparedBody,
		)

		if respError != nil { 
			log.Printf("[ERROR][%s] Failed to create HTTP request for vulnerability query: %s", GetRequestIp(request), respError)
			break
		}

		req.Header.Set("Content-Type", "application/json")
		requestResp, respError := topClient.Do(req)
		if respError != nil {
			log.Printf("[ERROR][%s] Failed to send vulnerability query: %s", GetRequestIp(request), respError)
			break
		}

		respBody, respError := io.ReadAll(requestResp.Body)
		if respError != nil {
			log.Printf("[ERROR][%s] Failed to read response body after sending vulnerability query: %s", GetRequestIp(request), respError)
			break
		}

		unmarshalledResponse := VulnDbOutput{}
		if requestMethod == "GET" { 
			unmarshalledSingle := OSVVulnerability{}
			respError = json.Unmarshal(respBody, &unmarshalledSingle)
			if respError != nil {
				log.Printf("[ERROR][%s] Failed to parse vulnerability database response: %s. Response body: %s", GetRequestIp(request), respError, string(respBody))
				break
			}

			if unmarshalledSingle.Code > 0 && len(unmarshalledSingle.Message) > 0 {
				preparedOutput.Message = unmarshalledSingle.Message
				preparedOutput.Code = unmarshalledSingle.Code
				break
			}

			unmarshalledResponse.Vulns = []OSVVulnerability{unmarshalledSingle}
		} else {
			respError = json.Unmarshal(respBody, &unmarshalledResponse)
			if respError != nil {
				log.Printf("[ERROR][%s] Failed to parse vulnerability database response: %s. Response body: %s", GetRequestIp(request), respError, string(respBody))
				break
			}
		}

		if unmarshalledResponse.Code > 0 && len(unmarshalledResponse.Message) > 0 {
			preparedOutput.Message = unmarshalledResponse.Message
			preparedOutput.Code = unmarshalledResponse.Code
			break
		}

		if len(unmarshalledResponse.Vulns) == 0 {
			break
		} else {
			for vulnIndex, _ := range unmarshalledResponse.Vulns {
				unmarshalledResponse.Vulns[vulnIndex].CreatedAt = time.Now().Unix()

				allVulns = append(allVulns, unmarshalledResponse.Vulns[vulnIndex])
				go SetVulnerability(ctx, unmarshalledResponse.Vulns[vulnIndex])
			}
		}

		if len(unmarshalledResponse.NextPageToken) == 0 { 
			break
		} else {
			nextPageToken = unmarshalledResponse.NextPageToken
		}
	}

	// NVD fallback for e.g. CVE-2008-4340
	if len(requestVuln.ID) > 0 && requestMethod == "GET" && len(allVulns) == 0 {
		respError = nil
		foundVuln, err := LookupCVEByID(requestVuln.ID) 
		if err != nil { 
			log.Printf("[WARNING] No vuln found for %s", requestVuln.ID) 
		} else {
			preparedOutput.Code = 0
			preparedOutput.Message = ""
			allVulns = []OSVVulnerability{*foundVuln}

			// A bit of extensibility
			for vulnIndex, _ := range allVulns {
				allVulns[vulnIndex].CreatedAt = time.Now().Unix()

				go SetVulnerability(ctx, allVulns[vulnIndex])
			}
		}

	}

	if respError != nil {
		log.Printf("[ERROR][%s] Failed to retrieve vulnerability information after multiple attempts: %s", GetRequestIp(request), respError)
		if len(allVulns) == 0 {
			resp.WriteHeader(500)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed to retrieve vulnerability information: %s"}`, respError.Error())))
			return
		}
	}

	preparedOutput.Vulns = allVulns
	marshalledVulns, err := json.Marshal(preparedOutput)
	if err != nil {
		log.Printf("[ERROR][%s] Failed to marshal vulnerability information: %s", GetRequestIp(request), err)
		resp.WriteHeader(500)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed to marshal vulnerability information (amount: %d): %s"}`, len(allVulns), err.Error())))
		return
	}

	// Store the specifics for 24 hours max. 
	if project.CacheDb {
		err = SetCache(ctx, cacheId, marshalledVulns, 1440)
		if err != nil {
			log.Printf("[WARNING][%s] Failed to set vulnerability information in cache: %s", GetRequestIp(request), err)
		}
	}

	resp.WriteHeader(200)
	resp.Write(marshalledVulns)
}

func GetVulnerabilities(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	gceProject := os.Getenv("SHUFFLE_GCEPROJECT")
	if gceProject != "shuffler" && gceProject != sandboxProject && len(gceProject) > 0 {
		log.Printf("[DEBUG] Redirecting request to vulnerability endpoint to avoid hitting quota for project %s", gceProject)
		RedirectUserRequest(resp, request)
		return
	}

	// Rate limit IF no auth
	_, err := HandleApiAuthentication(resp, request)
	if err != nil {
		// Rate limit
		err := ValidateRequestOverload(resp, request)
		if err != nil {
			log.Printf("[INFO] Request overload for IP %s in get vulnerability", GetRequestIp(request))
			resp.WriteHeader(429)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Too many requests"}`)))
			return
		}
	}

	ctx := context.Background()
	ecosystem := request.URL.Query().Get("ecosystem")
	cursor := request.URL.Query().Get("cursor")
	
	vulns, outputcursor, err := ListVulnerabilities(ctx, ecosystem, cursor) 
	if err != nil {
		log.Printf("[ERROR] Failed to list vulnerabilities: %s", err)
		resp.WriteHeader(500)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed to retrieve vulnerabilities: %s"}`, err.Error())))
		return
	}

	if vulns == nil { 
		vulns = []OSVVulnerability{}
	}

	response := VulnDbOutput{
		Vulns: vulns,
		Cursor: outputcursor,
	}

	responseData, err := json.Marshal(response)
	if err != nil {
		log.Printf("[ERROR] Failed to marshal vulnerability list response: %s", err)
		resp.WriteHeader(500)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed to marshal response: %s"}`, err.Error())))
		return
	}

	resp.WriteHeader(200)
	resp.Write(responseData)
}
