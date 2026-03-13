package shuffle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"time"
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
func crossCorrelateNGrams(ctx context.Context, orgId, category, datastoreKey, value string) error {
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
			log.Printf("[DEBUG] Created new ngram item for %s with key '%s'", ngramSearchKey, parsedValue)
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
			log.Printf("[DEBUG] Updated ngram item for %s with key %s", ngramSearchKey, parsedValue)
		}

		log.Println()
	}

	return nil

}
