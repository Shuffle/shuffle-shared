package shuffle

import (
	"net/url"
)

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

	// Query parameters (50% weight - most important)
	query1 := url1.Query()
	query2 := url2.Query()

	if len(query1) == 0 && len(query2) == 0 {
		score += 0.50
	} else if len(query1) > 0 || len(query2) > 0 {
		// Count matching parameters
		matchingParams := 0
		totalParams := 0

		// Get all unique keys from both queries
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
