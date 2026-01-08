package shuffle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"path/filepath"
)

func RunAgentDecisionMockHandler(execution WorkflowExecution, decision AgentDecision) ([]byte, string, string, error) {
	log.Printf("[DEBUG][%s] Mock handler called for tool=%s, action=%s", execution.ExecutionId, decision.Tool, decision.Action)

	// Get mock response
	response, err := GetMockSingulResponse(execution.ExecutionId, decision.Fields)
	if err != nil {
		log.Printf("[ERROR][%s] Failed to get mock response: %s", execution.ExecutionId, err)
		return nil, "", decision.Tool, err
	}

	// Parse the response to extract raw_response
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

	return body, "", decision.Tool, nil
}

func GetMockSingulResponse(executionId string, fields []Valuereplace) ([]byte, error) {
	ctx := context.Background()
	mockCacheKey := fmt.Sprintf("agent_mock_%s", executionId)
	cache, err := GetCache(ctx, mockCacheKey)

	if err == nil {
		cacheData := cache.([]uint8)
		log.Printf("[DEBUG][%s] Using cached mock data (%d bytes)", executionId, len(cacheData))

		var toolCalls []MockToolCall
		err = json.Unmarshal(cacheData, &toolCalls)
		if err != nil {
			log.Printf("[ERROR][%s] Failed to unmarshal cached mock data: %s", executionId, err)
			return nil, fmt.Errorf("failed to unmarshal cached mock data: %w", err)
		}

		return GetMockResponseFromToolCalls(toolCalls, fields)
	}

	testDataPath := os.Getenv("AGENT_TEST_DATA_PATH")
	if testDataPath == "" {
		return nil, fmt.Errorf("no mock data in cache for execution %s and AGENT_TEST_DATA_PATH not set", executionId)
	}

	log.Printf("[DEBUG][%s] Cache miss, using file-based mocks from: %s", executionId, testDataPath)

	useCase := os.Getenv("AGENT_TEST_USE_CASE")
	if useCase == "" {
		return nil, errors.New("AGENT_TEST_USE_CASE not set")
	}

	useCaseData, err := loadUseCaseData(useCase)
	if err != nil {
		return nil, err
	}

	return GetMockResponseFromToolCalls(useCaseData.ToolCalls, fields)
}

// GetMockResponseFromToolCalls finds and returns the matching mock response from tool calls
func GetMockResponseFromToolCalls(toolCalls []MockToolCall, fields []Valuereplace) ([]byte, error) {
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
	for _, tc := range toolCalls {
		if urlsEqual(reqURLParsed, tc.URL) {
			candidates = append(candidates, tc)
		}
	}

	// If no exact matches, try fuzzy matching
	if len(candidates) == 0 {
		log.Printf("[DEBUG] No exact match, trying fuzzy matching...")
		bestMatch, score := findBestFuzzyMatch(reqURLParsed, toolCalls)
		if score >= 0.80 {
			log.Printf("[INFO] Found fuzzy match with %.1f%% similarity: %s", score*100, bestMatch.URL)
			candidates = append(candidates, bestMatch)
		} else {
			return nil, fmt.Errorf("no mock data found for URL: %s (best match: %.1f%%)", requestURL, score*100)
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