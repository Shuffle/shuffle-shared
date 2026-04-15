package shuffle

import (
	"net/http"
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

type StreamFn func(line string)
