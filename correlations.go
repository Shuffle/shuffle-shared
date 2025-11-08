package shuffle

import (
	"net/http"
	"fmt"
	"io/ioutil"
	"encoding/json"
	"log"
	"strings"
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

	log.Printf("[DEBUG] GetCorrelations request body: %s", string(body))

	correlationData := CorrelationRequest{} 
	err = json.Unmarshal(body, &correlationData)
	if err != nil {
		log.Printf("[WARNING] Failed to parse JSON in GetCorrelations: %s", err)
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false, "reason": "Invalid JSON format"}`))
		return
	}

	log.Printf("Correlation request data: %#v", correlationData)

	// Process correlationData as needed
	if correlationData.OrgId != user.ActiveOrg.Id {
		log.Printf("[AUDIT] User %s attempted to access correlations for org %d", user.Username, correlationData.OrgId)
		resp.WriteHeader(403)
		resp.Write([]byte(`{"success": false, "reason": "Forbidden"}`))
		return
	}

	searchKey := fmt.Sprintf("%s|%s", correlationData.Category, correlationData.Key)

	availableTypes := []string{"datastore"}
	if correlationData.Type == "datastore" {
		// Nothing to do as we have the right key already
	} else {
		log.Printf("[WARNING] Invalid type in GetCorrelations: %#v. Available types: %#v", correlationData.Type, strings.Join(availableTypes, ", "))
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false, "reason": "Invalid type"}`))
		return
	}

	ctx := GetContext(request)
	correlations, err := GetDatastoreNgramItems(ctx, correlationData.OrgId, searchKey, 50)
	if err != nil {
		log.Printf("[ERROR] Failed to get correlations from DB in GetCorrelations: %s", err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false, "reason": "Internal server error"}`))
		return
	}

	newCorrelations := []NGramItem{}
	for _, item := range correlations {
		if item.OrgId != correlationData.OrgId {
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
