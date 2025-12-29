package shuffle

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"path/filepath"
)

// MockToolCall represents a single tool call with its request and response
type MockToolCall struct {
	URL      string                 `json:"url"`
	Method   string                 `json:"method"`
	Fields   map[string]string      `json:"fields"`
	Response map[string]interface{} `json:"response"`
}

// MockUseCaseData represents the test data for a single use case
type MockUseCaseData struct {
	UseCase           string                   `json:"use_case"`
	UserPrompt        string                   `json:"user_prompt"`
	ToolCalls         []MockToolCall           `json:"tool_calls"`
	ExpectedDecisions []map[string]interface{} `json:"expected_decisions"`
}

// RunAgentDecisionMockHandler handles agent decision execution in test mode
// This function is called instead of the real Singul endpoint when AGENT_TEST_MODE=true
//
// # It loads mock data based on use case and matches tool calls by URL and fields
//
// Parameters:
//   - execution: The full workflow execution context
//   - decision: The agent decision to execute containing Tool, Action, Fields, etc.
//
// Returns:
//   - rawResponse: The mock tool result as bytes (in Singul format)
//   - debugUrl: Debug URL (empty in test mode)
//   - appname: The app name (same as decision.Tool)
//   - error: Any error that occurred
func RunAgentDecisionMockHandler(execution WorkflowExecution, decision AgentDecision) ([]byte, string, string, error) {
	log.Printf("[DEBUG][%s] Mock handler called for tool=%s, action=%s", execution.ExecutionId, decision.Tool, decision.Action)

	// Get the use case name from environment variable
	useCase := os.Getenv("AGENT_TEST_USE_CASE")
	if useCase == "" {
		log.Printf("[ERROR][%s] AGENT_TEST_USE_CASE not set - cannot determine which test data to load", execution.ExecutionId)
		return nil, "", decision.Tool, errors.New("AGENT_TEST_USE_CASE environment variable not set")
	}

	// Get mock response from the hypothetical function
	response, err := GetMockSingulResponse(useCase, decision.Fields)
	if err != nil {
		log.Printf("[ERROR][%s] Failed to get mock response: %s", execution.ExecutionId, err)
		return nil, "", decision.Tool, err
	}

	// Parse the response to extract raw_response (same as real Singul handler does)
	var outputMapped SchemalessOutput
	err = json.Unmarshal(response, &outputMapped)
	if err != nil {
		log.Printf("[ERROR][%s] Failed to unmarshal mock response: %s", execution.ExecutionId, err)
		return response, "", decision.Tool, err
	}

	// Extract the raw_response field (same logic as RunAgentDecisionSingulActionHandler)
	body := response
	if val, ok := outputMapped.RawResponse.(string); ok {
		body = []byte(val)
	} else if val, ok := outputMapped.RawResponse.([]byte); ok {
		body = val
	} else if val, ok := outputMapped.RawResponse.(map[string]interface{}); ok {
		marshalledRawResp, err := json.MarshalIndent(val, "", "  ")
		if err != nil {
			log.Printf("[ERROR][%s] Failed to marshal raw response: %s", execution.ExecutionId, err)
		} else {
			body = marshalledRawResp
		}
	}

	log.Printf("[DEBUG][%s] Returning mock response for %s (success=%v, response_size=%d bytes)",
		execution.ExecutionId, decision.Tool, outputMapped.Success, len(body))

	// Return in same format as real Singul handler: (body, debugUrl, appname, error)
	return body, "", decision.Tool, nil
}

// GetMockSingulResponse is the hypothetical function that returns mock Singul responses
// It loads the use case data and matches based on URL and fields
//
// Parameters:
//   - useCase: The use case name (e.g., "get_weather_kakinada")
//   - fields: The request fields containing url, method, headers, body
//
// Returns:
//   - response: The mock Singul response as bytes (in Singul format)
//   - error: Any error that occurred
func GetMockSingulResponse(useCase string, fields []Valuereplace) ([]byte, error) {
	// Load the use case data from file
	useCaseData, err := loadUseCaseData(useCase)
	if err != nil {
		return nil, err
	}

	// Extract URL from fields
	requestURL := extractFieldValue(fields, "url")
	if requestURL == "" {
		return nil, errors.New("no URL found in request fields")
	}

	log.Printf("[DEBUG] Looking for mock data with URL: %s", requestURL)

	// Find matching tool calls by URL (order‑independent)
	var candidates []MockToolCall
	reqURLParsed, err := url.Parse(requestURL)
	if err != nil {
		log.Printf("[ERROR] Invalid request URL %s: %v", requestURL, err)
		return nil, fmt.Errorf("invalid request URL: %w", err)
	}
	for _, tc := range useCaseData.ToolCalls {
		if urlsEqual(reqURLParsed, tc.URL) {
			candidates = append(candidates, tc)
		}
	}

	// If no exact matches, try fuzzy matching
	if len(candidates) == 0 {
		log.Printf("[DEBUG] No exact match, trying fuzzy matching...")
		bestMatch, score := findBestFuzzyMatch(reqURLParsed, useCaseData.ToolCalls)
		if score >= 0.80 {
			log.Printf("[INFO] Found fuzzy match with %.1f%% similarity: %s", score*100, bestMatch.URL)
			candidates = append(candidates, bestMatch)
		} else {
			return nil, fmt.Errorf("no mock data found for URL: %s in use case: %s (best match: %.1f%%)", requestURL, useCase, score*100)
		}
	}

	// If only one match, return it
	if len(candidates) == 1 {
		log.Printf("[DEBUG] Found exact match for URL: %s", requestURL)
		return marshalResponse(candidates[0].Response)
	}

	// Multiple matches - compare fields to find exact match
	log.Printf("[DEBUG] Found %d candidates for URL, comparing fields...", len(candidates))
	for _, candidate := range candidates {
		if fieldsMatch(fields, candidate.Fields) {
			log.Printf("[DEBUG] Found exact match based on fields")
			return marshalResponse(candidate.Response)
		}
	}

	// No exact match - return first candidate with a warning
	log.Printf("[WARNING] No exact field match found, returning first candidate")
	return marshalResponse(candidates[0].Response)
}

// urlsEqual compares two URLs ignoring query‑parameter order and allowing fuzzy matching when the sets are equal.
func urlsEqual(req *url.URL, stored string) bool {
	storedURL, err := url.Parse(stored)
	if err != nil {
		log.Printf("[WARN] Invalid stored URL %s: %v", stored, err)
		return false
	}
	// Compare scheme, host, and path exactly
	if req.Scheme != storedURL.Scheme || req.Host != storedURL.Host || req.Path != storedURL.Path {
		return false
	}
	// Parse query parameters into maps
	reqQuery := req.Query()
	storedQuery := storedURL.Query()
	// If the number of parameters differs, not a match
	if len(reqQuery) != len(storedQuery) {
		return false
	}
	// Ensure each key/value pair matches (order‑independent)
	for key, reqVals := range reqQuery {
		storedVals, ok := storedQuery[key]
		if !ok {
			return false
		}
		if len(reqVals) != len(storedVals) {
			return false
		}
		for i, v := range reqVals {
			if v != storedVals[i] {
				return false
			}
		}
	}
	return true
}

// loadUseCaseData loads the test data for a given use case from JSON file
func loadUseCaseData(useCase string) (*MockUseCaseData, error) {
	// Try multiple possible paths
	possiblePaths := []string{}

	// 1. Environment variable (highest priority)
	if envPath := os.Getenv("AGENT_TEST_DATA_PATH"); envPath != "" {
		possiblePaths = append(possiblePaths, envPath)
	}

	// 2. Current directory
	possiblePaths = append(possiblePaths, "agent_test_data")

	// 3. Parent directory (if running from backend)
	possiblePaths = append(possiblePaths, "../shuffle-shared/agent_test_data")

	// 4. Common absolute paths
	possiblePaths = append(possiblePaths, "C:/Users/hari krishna/Documents/shuffle-shared/agent_test_data")
	possiblePaths = append(possiblePaths, "/home/shuffle-shared/agent_test_data")

	var filePath string
	var foundPath string

	// Try each path
	for _, basePath := range possiblePaths {
		testPath := filepath.Join(basePath, fmt.Sprintf("%s.json", useCase))
		if _, err := os.Stat(testPath); err == nil {
			filePath = testPath
			foundPath = basePath
			break
		}
	}

	if filePath == "" {
		return nil, fmt.Errorf("could not find test data file %s.json in any of these paths: %v", useCase, possiblePaths)
	}

	log.Printf("[DEBUG] Loading use case data from: %s", filePath)

	// Read the file
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read use case file %s: %s", filePath, err)
	}

	// Parse JSON
	var useCaseData MockUseCaseData
	err = json.Unmarshal(data, &useCaseData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse use case data: %s", err)
	}

	log.Printf("[DEBUG] Loaded use case '%s' with %d tool calls from %s", useCaseData.UseCase, len(useCaseData.ToolCalls), foundPath)

	return &useCaseData, nil
}

// extractFieldValue extracts a field value by key from the fields array
func extractFieldValue(fields []Valuereplace, key string) string {
	for _, field := range fields {
		if field.Key == key {
			return field.Value
		}
	}
	return ""
}

// fieldsMatch checks if the request fields match the stored fields
func fieldsMatch(requestFields []Valuereplace, storedFields map[string]string) bool {
	// Convert request fields to map for easier comparison
	requestMap := make(map[string]string)
	for _, field := range requestFields {
		requestMap[field.Key] = field.Value
	}

	// Compare all stored fields
	for key, storedValue := range storedFields {
		requestValue, exists := requestMap[key]
		if !exists || requestValue != storedValue {
			return false
		}
	}

	return true
}

// marshalResponse marshals the response map to JSON bytes
func marshalResponse(response map[string]interface{}) ([]byte, error) {
	data, err := json.Marshal(response)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response: %s", err)
	}
	return data, nil
}
