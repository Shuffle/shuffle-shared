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
	"strings"
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

	useCase := os.Getenv("AGENT_TEST_USE_CASE")
	if useCase == "" {
		log.Printf("[ERROR][%s] AGENT_TEST_USE_CASE not set - cannot determine which test data to load", execution.ExecutionId)
		return nil, "", decision.Tool, errors.New("AGENT_TEST_USE_CASE environment variable not set")
	}

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

	// Extract the raw_response field
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

// GetMockSingulResponse is the function that returns mock Singul responses
// It loads the use case data and matches based on URL and fields
//
// Parameters:
//   - useCase: The use case name
//   - fields: The request fields containing url, method, headers, body
//
// Returns:
//   - response: The mock Singul response as bytes (in Singul format)
//   - error: Any error that occurred
func GetMockSingulResponse(useCase string, fields []Valuereplace) ([]byte, error) {
	useCaseData, err := loadUseCaseData(useCase)
	if err != nil {
		return nil, err
	}

	requestURL := extractFieldValue(fields, "url")
	if requestURL == "" {
		return nil, errors.New("no URL found in request fields")
	}

	log.Printf("[DEBUG] Looking for mock data with URL: %s", requestURL)

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
	if req.Scheme != storedURL.Scheme || req.Host != storedURL.Host || req.Path != storedURL.Path {
		return false
	}
	reqQuery := req.Query()
	storedQuery := storedURL.Query()
	// If the number of parameters differs, not a match
	if len(reqQuery) != len(storedQuery) {
		return false
	}

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
	possiblePaths := []string{}

	if envPath := os.Getenv("AGENT_TEST_DATA_PATH"); envPath != "" {
		possiblePaths = append(possiblePaths, envPath)
	}

	possiblePaths = append(possiblePaths, "agent_test_data")
	possiblePaths = append(possiblePaths, "../shuffle-shared/agent_test_data")
	possiblePaths = append(possiblePaths, "../../shuffle-shared/agent_test_data")

	if homeDir, err := os.UserHomeDir(); err == nil {
		possiblePaths = append(possiblePaths, filepath.Join(homeDir, "Documents", "shuffle-shared", "agent_test_data"))
	}

	var filePath string
	var foundPath string

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

	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read use case file %s: %s", filePath, err)
	}

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

func fieldsMatch(requestFields []Valuereplace, storedFields map[string]string) bool {
	// Convert request fields to map for easier comparison
	requestMap := make(map[string]string)
	for _, field := range requestFields {
		requestMap[field.Key] = field.Value
	}

	for key, storedValue := range storedFields {
		requestValue, exists := requestMap[key]
		if !exists || requestValue != storedValue {
			return false
		}
	}

	return true
}

func marshalResponse(response map[string]interface{}) ([]byte, error) {
	data, err := json.Marshal(response)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response: %s", err)
	}
	return data, nil
}

// analyzeTestFailureWithLLM uses LLM to provide detailed analysis of why a test failed
func analyzeTestFailureWithLLM(actualDecisions []interface{}, expectedDecisions []map[string]interface{}, isTimeout bool) string {
	cleanActual := stripRawResponses(actualDecisions)
	cleanExpected := stripRawResponsesFromMaps(expectedDecisions)

	actualJSON, err := json.MarshalIndent(cleanActual, "", "  ")
	if err != nil {
		return "Failed to analyze: could not marshal actual decisions"
	}

	expectedJSON, err := json.MarshalIndent(cleanExpected, "", "  ")
	if err != nil {
		return "Failed to analyze: could not marshal expected decisions"
	}

	systemMessage := `You are analyzing agent test failures.
Focus on what the agent ACTUALLY did and where it got stuck.

Output rules:
- Start with what the agent successfully completed
- Identify the SPECIFIC action and tool where it failed or got stuck
- Compare only that failure point with what was expected
- Ignore answer and finish actions - focus only on API calls and tool usage
- Be concise (max 2-3 sentences)
- Use plain language without special characters like quotes, backticks, or brackets
- Name the specific API or tool that failed

Example output format:
Agent completed geocoding API call successfully. Got stuck on weather API call - agent used URL with different parameters than expected (missing daily forecast params and using timezone=auto instead of Asia/Kolkata).`

	var userMessage string
	if isTimeout {
		userMessage = fmt.Sprintf(`The agent test timed out.

What the agent ACTUALLY did:
%s

What was EXPECTED (full test plan):
%s

Analyze from the agent's perspective:
1. Which API calls or tools did the agent successfully complete?
2. Where exactly did it get stuck or fail?
3. What was different about that specific action compared to what was expected?
4. Ignore any answer or finish actions - focus only on the actual work (API calls, tools).`, string(actualJSON), string(expectedJSON))
	} else {
		userMessage = fmt.Sprintf(`The agent test failed.

What the agent ACTUALLY did:
%s

What was EXPECTED:
%s

Analyze from the agent's perspective:
1. Which actions did the agent complete successfully?
2. Which specific action/tool failed and why?
3. What was the difference between what the agent did vs what was expected?
4. Ignore any answer or finish actions.`, string(actualJSON), string(expectedJSON))
	}

	responseBody, err := RunAiQuery(systemMessage, userMessage)
	if err != nil {
		log.Printf("[ERROR] Failed to get LLM analysis: %s", err)
		return "Failed to analyze with LLM"
	}

	failureReason := strings.TrimSpace(responseBody)
	if after, ok := strings.CutPrefix(failureReason, "```"); ok {
		failureReason = after
	}
	if after, ok := strings.CutSuffix(failureReason, "```"); ok {
		failureReason = after
	}
	failureReason = strings.TrimSpace(failureReason)

	log.Printf("[INFO] LLM Analysis: %s", failureReason)
	return failureReason
}

// Hmmm, let's see if this helps with token usage, stripRawResponses removes raw_response fields from decisions to save LLM tokens
func stripRawResponses(decisions []interface{}) []interface{} {
	cleaned := make([]interface{}, len(decisions))
	for i, d := range decisions {
		if decisionMap, ok := d.(map[string]interface{}); ok {
			cleanedDecision := make(map[string]interface{})
			for k, v := range decisionMap {
				// Skip raw_response and other verbose fields
				if k != "raw_response" && k != "RawResponse" && k != "debug_url" && k != "DebugUrl" {
					cleanedDecision[k] = v
				}
			}
			cleaned[i] = cleanedDecision
		} else {
			cleaned[i] = d
		}
	}
	return cleaned
}

// stripRawResponsesFromMaps removes raw_response fields from expected decisions
func stripRawResponsesFromMaps(decisions []map[string]interface{}) []map[string]interface{} {
	cleaned := make([]map[string]interface{}, len(decisions))
	for i, decisionMap := range decisions {
		cleanedDecision := make(map[string]interface{})
		for k, v := range decisionMap {
			if k != "raw_response" && k != "RawResponse" && k != "debug_url" && k != "DebugUrl" {
				cleanedDecision[k] = v
			}
		}
		cleaned[i] = cleanedDecision
	}
	return cleaned
}

// findBestFuzzyMatch finds the most similar URL from stored tool calls
// Returns the best match and its similarity score (0.0 to 1.0)
func findBestFuzzyMatch(reqURL *url.URL, toolCalls []MockToolCall) (MockToolCall, float64) {
	var bestMatch MockToolCall
	bestScore := 0.0

	for _, tc := range toolCalls {
		storedURL, err := url.Parse(tc.URL)
		if err != nil {
			continue
		}

		score := calculateURLSimilarity(reqURL, storedURL)
		if score > bestScore {
			bestScore = score
			bestMatch = tc
		}
	}

	return bestMatch, bestScore
}

// calculateURLSimilarity returns a score from 0.0 to 1.0 indicating how similar two URLs are
func calculateURLSimilarity(url1, url2 *url.URL) float64 {
	score := 0.0
	totalWeight := 0.0

	// Scheme (10% weight)
	if url1.Scheme == url2.Scheme {
		score += 0.10
	}
	totalWeight += 0.10

	// Host (20% weight)
	if url1.Host == url2.Host {
		score += 0.20
	}
	totalWeight += 0.20

	// Path (20% weight)
	if url1.Path == url2.Path {
		score += 0.20
	}
	totalWeight += 0.20

	// Query parameters (50% weight)
	query1 := url1.Query()
	query2 := url2.Query()

	if len(query1) == 0 && len(query2) == 0 {
		score += 0.50
	} else if len(query1) > 0 || len(query2) > 0 {
		matchingParams := 0
		totalParams := 0

		allKeys := make(map[string]bool)
		for k := range query1 {
			allKeys[k] = true
		}
		for k := range query2 {
			allKeys[k] = true
		}
		totalParams = len(allKeys)

		// Count how many match
		for key := range allKeys {
			val1, ok1 := query1[key]
			val2, ok2 := query2[key]

			if ok1 && ok2 {
				// Both have this key - check if values match
				if len(val1) == len(val2) {
					allMatch := true
					for i := range val1 {
						if val1[i] != val2[i] {
							allMatch = false
							break
						}
					}
					if allMatch {
						matchingParams++
					}
				}
			}
		}

		if totalParams > 0 {
			paramScore := float64(matchingParams) / float64(totalParams)
			score += paramScore * 0.50
		}
	}
	totalWeight += 0.50

	return score / totalWeight
}
