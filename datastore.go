package shuffle

import ( 
	"net/http"
	"net/http/httptest"
	"net/url"

	"context"
	"errors"
	"bytes"
	"strings"
	"log"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strconv"
	"sort"
	"crypto/sha1"

	uuid "github.com/satori/go.uuid"

)

// Fallback with redirect
// POST r.HandleFunc("/api/v2/{datastore_category}/{datastore_key}", shuffle.HandleDatastoreGetRedirect).Methods("POST", "OPTIONS")
func HandleDatastorePostRedirect(resp http.ResponseWriter, request *http.Request) {
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

	location := strings.Split(request.URL.Path, "/")
	var category string
	var key string
	if location[1] == "api" {
		if len(location) <= 4 {
			resp.WriteHeader(400)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		category = location[3]
		if len(location) >= 4 { 
			key = location[4]
		}
	}

	if len(category) == 0 || len(key) == 0 { 
		log.Printf("[WARNING] Missing category or key datastore redirect wrapper")
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false, "reason": "No category found in datastore redirect wrapper"}`))
		return
	}

	// Handles query pathing
	if strings.Contains(category, "?") {
		category = strings.Split(category, "?")[0]
	} else if strings.Contains(key, "?") {
		key = strings.Split(key, "?")[0]
	}

	// Try to get the key first to check if it exists (?)
	ctx := GetContext(request)
	key, err = url.QueryUnescape(strings.Trim(key, " "))
	if err != nil {
		log.Printf("[WARNING] Failed to unescape cache key (dynamic datastore) %s: %s", key, err)
		key = strings.Trim(key, " ")
	}

	// Validates which key to use
	parsedKey := fmt.Sprintf("%s_%s", user.ActiveOrg.Id, key)
	keyRet, err := GetDatastoreKey(ctx, parsedKey, category) 
	if err != nil || len(keyRet.Value) == 0 {
		if !strings.HasPrefix(category, "shuffle-security_") {
			originalCategory := category
			category = fmt.Sprintf("shuffle-security_%s", category)
			keyRet2, err := GetDatastoreKey(ctx, parsedKey, category)
			if err != nil || len(keyRet2.Value) == 0 {
				category = originalCategory
			}
		}
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Printf("[WARNING] Failed to read request body in datastore redirect wrapper: %s", err)
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false, "reason": "Failed to read request body"}`))
		return
	}

	newRequest := request.Clone(context.Background())
	newRequest.Method = "POST"
	newRequest.URL.Path = fmt.Sprintf("/api/v2/datastore/%s/%s", category, key)
	newRequest.Body = ioutil.NopCloser(bytes.NewBuffer(body))
	// r.HandleFunc("/api/v2/datastore/{category_key}/{key}", shuffle.HandleSetDatastoreKey).Methods("POST", "PUT", "OPTIONS")

	q := newRequest.URL.Query()
	q.Set("category", category)
	newRequest.URL.RawQuery = q.Encode()

	// Check direct first, then fall back to shuffle-security_* if no values
	recorder := httptest.NewRecorder()
	HandleSetDatastoreKey(recorder, newRequest)

	cacheReturn := CacheReturn{}
	result := recorder.Result()
	defer result.Body.Close()
	respbody, err := io.ReadAll(result.Body)
	if err == nil && len(respbody) > 0 {
		respError := json.Unmarshal(respbody, &cacheReturn)
		if respError == nil && (cacheReturn.Amount > 0 || (cacheReturn.Key == key && len(cacheReturn.Value) > 0)) {
			resp.WriteHeader(result.StatusCode)
			resp.Write(respbody)
			return
		}
	}

	resp.WriteHeader(result.StatusCode)
	resp.Write(respbody)
}

// Fallback with redirect
// GET r.HandleFunc("/api/v2/{datastore_category}", shuffle.HandleDatastoreRedirect).Methods("GET")
// GET r.HandleFunc("/api/v2/{datastore_category}/{datastore_key}", shuffle.HandleDatastoreGetRedirect).Methods("GET", "OPTIONS")

// Does NOT need authentication, as this is handled in the "sub-function" 
func HandleDatastoreGetRedirect(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	location := strings.Split(request.URL.Path, "/")
	var category string
	var key string
	if location[1] == "api" {
		if len(location) <= 3 {
			resp.WriteHeader(400)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		category = location[3]
		if len(location) > 4 { 
			key = location[4]
		}
	}

	if len(category) == 0 { 
		log.Printf("[WARNING] No category found in datastore redirect wrapper")
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false, "reason": "No category found in datastore redirect wrapper"}`))
		return
	}

	// Handles query pathing
	if strings.Contains(category, "?") {
		category = strings.Split(category, "?")[0]
	} else if strings.Contains(key, "?") {
		key = strings.Split(key, "?")[0]
	}

	newRequest := request.Clone(context.Background())
	newRequest.URL.Path = "/api/v2/datastore"
	if len(key) > 0 {
		newRequest.URL.Path = fmt.Sprintf("/api/v2/datastore/category/%s/%s", category, key)
	}

	q := newRequest.URL.Query()
	q.Set("category", category)
	newRequest.URL.RawQuery = q.Encode()

	// Check direct first, then fall back to shuffle-security_* if no values
	recorder := httptest.NewRecorder()
	if len(key) > 0 { 
		HandleGetCacheKey(recorder, newRequest)
	} else {
		HandleListCacheKeys(recorder, newRequest)
	}

	cacheReturn := CacheReturn{}
	result := recorder.Result()
	defer result.Body.Close()
	body, err := io.ReadAll(result.Body)
	if err == nil && len(body) > 0 {
		respError := json.Unmarshal(body, &cacheReturn)
		if respError == nil && (cacheReturn.Amount > 0 || (cacheReturn.Key == key && len(cacheReturn.Value) > 0)) {
			// Makes the return better
			if len(key) == 0 && len(cacheReturn.Keys) > 0 { 
				newKeys := make([]map[string]interface{}, 0)
				for _, cacheKey := range cacheReturn.Keys {
					if len(cacheKey.Value) == 0 { 
						continue
					}

					if !strings.HasPrefix(cacheKey.Value, "{") || !strings.HasSuffix(cacheKey.Value, "}") {
						continue
					}

					mappedValue := map[string]interface{}{}
					err := json.Unmarshal([]byte(cacheKey.Value), &mappedValue)
					if err != nil {
						log.Printf("[ERROR] Failed to unmarshal cacheKey.Value in datastore redirect wrapper: %s", err)
					}

					newKeys = append(newKeys, mappedValue)
				}

				if len(newKeys) > 0 { 
					marshalled, err := json.Marshal(newKeys)
					if err == nil {
						body = marshalled
					} else {
						log.Printf("[ERROR] Failed to marshal cacheReturn in datastore redirect wrapper: %s", err)
					}
				}
			}

			resp.WriteHeader(result.StatusCode)
			resp.Write(body)
			return
		}
	}

	// Same again with shuffle-security prefix
	if !strings.HasPrefix(category, "shuffle-security_") {
		category = "shuffle-security_" + category
		newRequest = request.Clone(context.Background())
		newRequest.URL.Path = "/api/v2/datastore"
		if len(key) > 0 {
			newRequest.URL.Path = fmt.Sprintf("/api/v2/datastore/category/%s/%s", category, key)
		}

		q := newRequest.URL.Query()
		q.Set("category", category)
		newRequest.URL.RawQuery = q.Encode()

		// Check direct first, then fall back to shuffle-security_* if no values
		recorder := httptest.NewRecorder()
		if len(key) > 0 { 
			HandleGetCacheKey(recorder, newRequest)
		} else {
			HandleListCacheKeys(recorder, newRequest)
		}

		cacheReturn := CacheReturn{}
		result := recorder.Result()
		defer result.Body.Close()
		body, err = io.ReadAll(result.Body)
		if err == nil && len(body) > 0 {
			respError := json.Unmarshal(body, &cacheReturn)
			if respError == nil && (cacheReturn.Amount > 0 || (cacheReturn.Key == key && len(cacheReturn.Value) > 0)) {

				// Makes the return better
				if len(key) == 0 && len(cacheReturn.Keys) > 0 { 
					newKeys := make([]map[string]interface{}, 0)
					for _, cacheKey := range cacheReturn.Keys {
						if len(cacheKey.Value) == 0 { 
							continue
						}

						if !strings.HasPrefix(cacheKey.Value, "{") || !strings.HasSuffix(cacheKey.Value, "}") {
							continue
						}

						mappedValue := map[string]interface{}{}
						err := json.Unmarshal([]byte(cacheKey.Value), &mappedValue)
						if err != nil {
							log.Printf("[ERROR] Failed to unmarshal cacheKey.Value in datastore redirect wrapper: %s", err)
						}

						newKeys = append(newKeys, mappedValue)
					}

					if len(newKeys) > 0 { 
						marshalled, err := json.Marshal(newKeys)
						if err == nil {
							body = marshalled
						} else {
							log.Printf("[ERROR] Failed to marshal cacheReturn in datastore redirect wrapper: %s", err)
						}
					}
				}

				resp.WriteHeader(result.StatusCode)
				resp.Write(body)
				return
			}
		}
	}

	resp.WriteHeader(404)
	resp.Write([]byte(`{"success": false, "reason": "No values found for this key and category"}`))
}

func HandleGetCacheKey(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	//for key, value := range data.Apps {
	var fileId string
	location := strings.Split(request.URL.String(), "/")

	///api/v2/datastore/category/{category_key}/{key}
	///api/v1/orgs/{orgId}/get_cache
	///api/v1/get_cache
	///api/v1/orgs/{orgId}/datastore/{cache_key}
	///api/v1/orgs/{orgId}/cache/{cache_key}
	if location[1] == "api" {
		if len(location) <= 4 {
			log.Printf("[ERROR] Path too short: %d", len(location))
			fileId = ""
			//resp.WriteHeader(401)
			//resp.Write([]byte(`{"success": false}`))
			//return
		} else {
			fileId = location[4]
		}
	}

	if strings.Contains(fileId, "?") {
		fileId = strings.Split(fileId, "?")[0]
	}

	// Check if request method is POST
	// 3 different auth mechanisms due to public exposing of this endpoint, and for use in workflows
	query := request.URL.Query()
	requireCacheAuth := false
	skipExecutionAuth := false

	var tmpData CacheKeyData
	if request.Method == "POST" {
		body, err := ioutil.ReadAll(request.Body)
		if err != nil {
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Failed reading body"}`))
			return
		}

		err = json.Unmarshal(body, &tmpData)
		if err != nil {
			log.Printf("[WARNING] Failed unmarshalling in POST get value for datastore: %s", err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		if tmpData.OrgId != fileId {
			if fileId == "" {
				fileId = tmpData.OrgId
			} else {
				log.Printf("[INFO] OrgId %s and %s don't match", tmpData.OrgId, fileId)
				resp.WriteHeader(401)
				resp.Write([]byte(`{"success": false, "reason": "Organization ID's don't match"}`))
				return
			}
		}

		user, err := HandleApiAuthentication(resp, request)
		if err == nil {
			if len(fileId) == 0 {
				fileId = user.ActiveOrg.Id
				tmpData.OrgId = user.ActiveOrg.Id
			} else {
				user.ActiveOrg.Id = fileId
			}

			skipExecutionAuth = true

			if user.ActiveOrg.Id != fileId {
				log.Printf("[INFO] OrgId %s and %s don't match in get cache key list. Checking cache auth", user.ActiveOrg.Id, fileId)

				requireCacheAuth = true
				skipExecutionAuth = false
				user.ActiveOrg.Id = fileId
			}
		}
	} else {
		if len(location) <= 6 {
			log.Printf("[ERROR] Cache Path too short: %d", len(location))
			resp.WriteHeader(400)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		if strings.Contains(location[6], "?") {
			location[6] = strings.Split(location[6], "?")[0]
		}

		// urlescape
		parsedCacheKey, err := url.QueryUnescape(location[6])
		if err != nil {
			log.Printf("[ERROR] Failed to unescape cache key: %s", err)
			resp.WriteHeader(400)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		tmpData = CacheKeyData{
			OrgId: fileId,
			Key:   parsedCacheKey,
		}

		// Use normal user auth
		user, usererr := HandleApiAuthentication(resp, request)
		if usererr != nil {
			// Check if authorization query exists
			if len(query.Get("authorization")) == 0 {
				log.Printf("[INFO] Failed to authenticate user in GET datastore key: %s", err)
				resp.WriteHeader(401)
				resp.Write([]byte(`{"success": false, "reason": "No authorization provided"}`))
				return
			}

			requireCacheAuth = true
			user.ActiveOrg.Id = fileId
		}

		if user.ActiveOrg.Id != fileId && len(fileId) == 36 {
			log.Printf("[INFO] OrgId %s and %s don't match in get cache key list. Checking cache auth", user.ActiveOrg.Id, fileId)

			requireCacheAuth = true
			user.ActiveOrg.Id = fileId

			/*
				resp.WriteHeader(401)
				resp.Write([]byte(`{"success": false, "reason": "Organization ID's don't match"}`))
				return
			*/
		}

		// /api/v2/datastore/category/{category_key}/{key}
		if tmpData.OrgId == "category" && len(location) == 7 {
			tmpData.OrgId = user.ActiveOrg.Id
			tmpData.Category = location[5]
			tmpData.Key = location[6]

			if strings.Contains(tmpData.Key, "?") {
				tmpData.Key = strings.Split(tmpData.Key, "?")[0]
			}
		}

		skipExecutionAuth = true
	}

	ctx := GetContext(request)
	org, err := GetOrg(ctx, tmpData.OrgId)
	if err != nil {
		log.Printf("[INFO] Organization '%s' doesn't exist in get cache: %s", tmpData.OrgId, err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	executionId := ""
	if !skipExecutionAuth {
		workflowExecution, err := GetWorkflowExecution(ctx, tmpData.ExecutionId)
		if err != nil {
			log.Printf("[INFO] Failed getting the execution: %s", err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "No permission to get execution"}`))
			return
		}

		// Allows for execution auth AND user auth
		if workflowExecution.Authorization != tmpData.Authorization {
			// Get the user?
			user, err := HandleApiAuthentication(resp, request)
			if err != nil {
				log.Printf("[INFO] Execution auth %s and %s don't match", workflowExecution.Authorization, tmpData.Authorization)
				resp.WriteHeader(401)
				resp.Write([]byte(`{"success": false, "reason": "Failed authentication"}`))
				return
			} else {
				if user.ActiveOrg.Id != org.Id {
					log.Printf("[INFO] Execution auth %s and %s don't match (2)", workflowExecution.Authorization, tmpData.Authorization)
					resp.WriteHeader(401)
					resp.Write([]byte(`{"success": false, "reason": "Failed authentication"}`))
					return
				}
			}
		}

		if workflowExecution.ExecutionOrg != org.Id {
			log.Printf("[INFO] Org %s wasn't used to execute %s", org.Id, workflowExecution.ExecutionId)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Bad organization specified"}`))
			return
		}

		/*
			if workflowExecution.Status != "EXECUTING" {
				log.Printf("[INFO] Workflow %s isn't executing and shouldn't be searching", workflowExecution.ExecutionId)
				resp.WriteHeader(401)
				resp.Write([]byte(`{"success": false, "reason": "Workflow isn't executing (3)"}`))
				return
			}
		*/

		executionId = workflowExecution.ExecutionId
	}

	//if debug {
	//	log.Printf("\n\n[DEBUG] Getting key '%s' from category '%s'\n\n", tmpData.Key, tmpData.Category)
	//}

	tmpData.Key = strings.Trim(tmpData.Key, " ")
	cacheId := fmt.Sprintf("%s_%s", tmpData.OrgId, tmpData.Key)
	cacheData, err := GetDatastoreKey(ctx, cacheId, tmpData.Category)
	if err != nil {
		log.Printf("[WARNING] Failed to GET cache key '%s' for org %s (get) and cacheId %s", tmpData.Key, tmpData.OrgId, cacheId)
		// Doing a last resort search, e.g. to handle spaces and the like
		limit := 50
		if os.Getenv("SHUFFLE_GCEPROJECT") == "shuffle-europe-west3" {
			limit = 2000
		}

		allkeys, _, err := GetAllCacheKeys(ctx, org.Id, "", limit, "")
		if err == nil {
			cacheData = &CacheKeyData{}
			searchkey := strings.ReplaceAll(strings.Trim(strings.ToLower(tmpData.Key), " "), " ", "_")

			for _, key := range allkeys {
				tmpkey := strings.ReplaceAll(strings.Trim(strings.ToLower(key.Key), " "), " ", "_")

				//log.Printf("%s vs %s", tmpkey, searchkey)
				if tmpkey == searchkey {
					if debug {
						log.Printf("\n\n[DEBUG] Found key %s for org %s\n\n", key.Key, org.Id)
					}
					cacheData = &key
					break
				}
			}

			if cacheData.Key == "" {
				log.Printf("[WARNING] Failed to GET datastore key %s for org %s (get)", tmpData.Key, tmpData.OrgId)
				resp.WriteHeader(400)
				resp.Write([]byte(`{"success": false, "reason": "Failed authentication or key doesn't exist"}`))
				return
			}

		} else {
			log.Printf("[WARNING][%s] Failed to GET datastore key %s for org %s (get)", executionId, tmpData.Key, tmpData.OrgId)
			resp.WriteHeader(400)
			resp.Write([]byte(`{"success": false, "reason": "Failed authentication or key doesn't exist"}`))
			return
		}
	}

	if len(cacheData.PublicAuthorization) == 0 && cacheData.Category != "protected" {
		cacheId := fmt.Sprintf("%s_%s", tmpData.OrgId, tmpData.Key)
		if len(tmpData.Category) > 0 && tmpData.Category != "default" {
			cacheId = fmt.Sprintf("%s_%s", cacheId, tmpData.Category)
		}

		cacheId = url.QueryEscape(cacheId)
		parsedKey := fmt.Sprintf("org_cache_%s", cacheId)
		go DeleteCache(ctx, parsedKey)
	}

	if requireCacheAuth {
		authQuery := query.Get("authorization")
		log.Printf("[INFO] Cache auth required for '%s'. Input auth: %s. Required auth: %#v", tmpData.Key, authQuery, cacheData.PublicAuthorization)
		if cacheData.PublicAuthorization == "" || authQuery != cacheData.PublicAuthorization {
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Failed authentication or key doesn't exist"}`))
			return
		}

		if cacheData.Category == "protected" {
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Failed authentication or key doesn't exist"}`))
			return
		}
	}

	cacheData.Success = true
	cacheData.ExecutionId = ""
	cacheData.Authorization = ""
	cacheData.OrgId = ""
	cacheData.UpdatedBy = ""
	cacheData.PublicAuthorization = ""

	// Look for query param "type"
	typeQuery := query.Get("type")

	// Check for header accept
	if typeQuery == "text" || typeQuery == "raw" || request.Header.Get("Accept") == "text/plain" {
		if typeQuery == "text" {
			// Check if the value is valid JSON or not

			var newstring = ""
			var jsonCheck []interface{}
			// If it's valid JSON list, add all items to a string with newlines

			err := json.Unmarshal([]byte(cacheData.Value), &jsonCheck)
			if err == nil {
				for _, item := range jsonCheck {
					newstring += fmt.Sprintf("%v\n", item)
				}
			}

			if newstring != "" {
				cacheData.Value = newstring
			}
		}

		resp.Header().Set("Content-Type", "text/plain")
		resp.WriteHeader(200)
		resp.Write([]byte(cacheData.Value))

		return
	} else if typeQuery == "json" {
		resp.Header().Set("Content-Type", "application/json")

		//validate if it's json or not
		isValidJson := false
		cacheData.Value = strings.Trim(cacheData.Value, " ")
		if strings.HasPrefix(cacheData.Value, "{") && strings.HasSuffix(cacheData.Value, "}") || strings.HasPrefix(cacheData.Value, "[") && strings.HasSuffix(cacheData.Value, "]") {
			// Check if it's a list of JSON
			listMarshalled := []interface{}{}
			err := json.Unmarshal([]byte(cacheData.Value), &listMarshalled)
			if err == nil {
				isValidJson = true

				outputBody, err := json.MarshalIndent(listMarshalled, "", "  ")
				if err == nil {
					cacheData.Value = string(outputBody)
				}
			} else {
				objectMarshalled := map[string]interface{}{}
				err := json.Unmarshal([]byte(cacheData.Value), &objectMarshalled)
				if err == nil {
					isValidJson = true

					outputBody, err := json.MarshalIndent(objectMarshalled, "", "  ")
					if err == nil {
						cacheData.Value = string(outputBody)
					}
				} else {
					//log.Printf("[INFO] Cache key %s for org %s isn't valid JSON: '%s'", tmpData.Key, tmpData.OrgId, cacheData.Value)
					isValidJson = false
				}
			}
		}

		if !isValidJson {
			jsonlist := []string{}
			if strings.Contains(cacheData.Value, "\n") {
				if strings.Count(cacheData.Value, "\n") == 1 {
					if strings.Contains(cacheData.Value, ",") {
						jsonlist = strings.Split(cacheData.Value, ",")
					} else {
						jsonlist = strings.Split(cacheData.Value, "\n")
					}
				} else {
					jsonlist = strings.Split(cacheData.Value, "\n")
				}
			}

			parsedJsonlist, err := json.MarshalIndent(jsonlist, "", "  ")
			if err != nil {
				log.Printf("[WARNING] Failed to parse JSON list for key %s for org %s", tmpData.Key, tmpData.OrgId)
				resp.WriteHeader(500)
				resp.Write([]byte(`{"success": false, "reason": "Failed to parse JSON list"}`))
				return
			}

			cacheData.Value = string(parsedJsonlist)
		}

		resp.WriteHeader(200)
		resp.Write([]byte(cacheData.Value))
		return
	}

	b, err := json.Marshal(cacheData)
	if err != nil {
		log.Printf("[WARNING] Failed to marshal cache data %s for org %s", tmpData.Key, tmpData.OrgId)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false, "reason": "Failed to get key. Does it exist?"}`))
		return
	}

	resp.WriteHeader(200)
	resp.Write(b)
}

func HandleSetDatastoreKey(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Printf("[WARNING] Failed reading body in set cache: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed reading set datastore key body"}`))
		return
	}

	user, usererr := HandleApiAuthentication(resp, request)

	var tmpData []CacheKeyData
	err = json.Unmarshal(body, &tmpData)
	if err != nil || len(tmpData) == 0 {

		var tmpDataOverride CacheKeyDataFallback
		err = json.Unmarshal(body, &tmpDataOverride)
		if err != nil || len(tmpDataOverride.Key) == 0 {
			if usererr != nil || len(user.Id) == 0 || len(user.ActiveOrg.Id) == 0 { 
				log.Printf("[WARNING] Failed unmarshalling in setvalue (1): %s", err)
				resp.Write([]byte(`{"success": false}`))
				resp.WriteHeader(400)
				return
			}

			// Handling failover and auto-build in case POST body is 
			// JUST a value
			location := strings.Split(request.URL.Path, "/")
			var category string
			var key string
			if location[1] == "api" {
				if len(location) <= 5 {
					resp.WriteHeader(400)
					resp.Write([]byte(`{"success": false}`))
					return
				}

				category = location[4]
				if len(location) >= 5 { 
					key = location[5]
				}
			}

			if len(category) == 0 || len(key) == 0 { 
				log.Printf("[WARNING] Missing category or key update datastore value")
				resp.WriteHeader(400)
				resp.Write([]byte(`{"success": false}`))
				return
			}

			log.Printf("[INFO] Allowing fallback for setvalue for org %s, category %s, key %s", user.ActiveOrg.Id, category, key)
			tmpDataOverride.OrgId = user.ActiveOrg.Id 
			tmpDataOverride.Key = key
			tmpDataOverride.Category = category
			tmpDataOverride.Value = string(body)
		}

		// Check if value is a map[] or []map first
		parsedValue := ""
		if _, ok := tmpDataOverride.Value.(string); ok {
			parsedValue = tmpDataOverride.Value.(string)
		} else {
			marshalledValue, err := json.Marshal(tmpDataOverride.Value)
			if err == nil {
				parsedValue = string(marshalledValue)
			} else {
				log.Printf("[WARNING] Failed to marshal value in setvalue: %s", err)
				resp.WriteHeader(400)
				resp.Write([]byte(`{"success": false, "reason": "Failed to parse value. Make sure it is in the [{"key": "key", "value": "value"}] format."}`))
				return
			}
		}

		tmpData = append(tmpData, CacheKeyData{
			OrgId:       tmpDataOverride.OrgId,
			Key:         tmpDataOverride.Key,
			Category:    tmpDataOverride.Category,
			Tags:        tmpDataOverride.Tags,
			Enrichments: tmpDataOverride.Enrichments,

			Value: parsedValue,
		})
	}

	if len(tmpData) == 0 {
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false, "reason": "No data provided. Value of each key should be a string."}`))
		return
	}

	ctx := GetContext(request)
	if usererr != nil || len(user.ActiveOrg.Id) == 0 {
		sourceExecution, sourceExecutionOk := request.URL.Query()["execution_id"]
		sourceAuth, sourceAuthOk := request.URL.Query()["authorization"]
		if !sourceAuthOk || !sourceExecutionOk {
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Failed authentication (1)"}`))
			return
		}

		foundExec, err := GetWorkflowExecution(ctx, sourceExecution[0])
		if err != nil {
			log.Printf("[WARNING] Failed getting exec during cache set: %s", err)
			resp.WriteHeader(500)
			resp.Write([]byte(`{"success": false, "reason": "No permission to get execution (2)"}`))
			return
		}

		if sourceAuth[0] != foundExec.Authorization {
			log.Printf("[INFO] Execution auth %s and %s don't match", foundExec.Authorization, sourceAuth[0])
			resp.WriteHeader(403)
			resp.Write([]byte(`{"success": false, "reason": "Failed authentication (3)"}`))
			return
		}

		if len(foundExec.ExecutionOrg) == 0 {
			log.Printf("[WARNING] Execution %s doesn't have an org set", foundExec.ExecutionId)
			resp.WriteHeader(403)
			resp.Write([]byte(`{"success": false, "reason": "Failed authentication (4)"}`))
			return
		}

		user.ActiveOrg.Id = foundExec.ExecutionOrg
	}

	mainCategory := ""
	for itemIndex, _ := range tmpData {
		tmpData[itemIndex].UpdatedBy = user.Username
		tmpData[itemIndex].OrgId = user.ActiveOrg.Id

		mainCategory = tmpData[itemIndex].Category
		if strings.ToLower(tmpData[itemIndex].Category) == "default" {
			tmpData[itemIndex].Category = ""
		}
	}

	log.Printf("[AUDIT] Running bulk upload for org '%s' to category '%s'. Keys: %d. Tags: %#v", user.ActiveOrg.Id, mainCategory, len(tmpData), tmpData[0].Tags)

	existingInfo, err := SetDatastoreKeyBulk(ctx, tmpData)
	if err != nil {
		log.Printf("[ERROR] Failed to set %d datastore key(s) for org %s", len(tmpData), user.ActiveOrg.Id)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false, "reason": "Failed to set data. Please try again, or contact support@shuffler.io"}`))
		return
	}

	log.Printf("[INFO] Successfully set %d datastore keys (or less) for org '%s' (%s)", len(tmpData), user.ActiveOrg.Name, user.ActiveOrg.Id)
	type returnStruct struct {
		Success     bool               `json:"success"`
		KeysExisted []DatastoreKeyMini `json:"keys_existed"`
	}

	/*
		// For testing deduplication
		if debug {
			found := []string{}
			for _, existing := range existingInfo {
				if ArrayContains(found, existing.Key) {
					log.Printf("[DEBUG] Key %s already found in existing info", existing.Key)
					continue
				}

				found = append(found, existing.Key)
			}
		}
	*/

	returnData := returnStruct{
		Success:     true,
		KeysExisted: existingInfo,
	}

	// For single-key updates
	returnStatus := 200
	if len(existingInfo) == 1 { 
		if existingInfo[0].Changed == false { 
			returnStatus = 400
			returnData.Success = false
		}
	}

	b, err := json.Marshal(returnData)
	if err != nil {
		log.Printf("[ERROR] Failed to marshal return data in set datastore key. Setting to JUST success true. This should NEVER happen. Details: %s", err)
		b = []byte(`{"success": true}`)
	}

	resp.WriteHeader(returnStatus)
	resp.Write(b)
}

func HandleListCacheKeys(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, usererr := HandleApiAuthentication(resp, request)
	if usererr != nil {
		log.Printf("[AUDIT] Api authentication failed in list datastore keys: %s. Allowing continue in case category is public", usererr)
		//resp.WriteHeader(401)
		//resp.Write([]byte(`{"success": false, "reason": "Failed authentication"}`))
		//return
	} else {
		if user.Role != "admin" && !user.SupportAccess {
			log.Printf("[AUDIT] User %s (%s) tried to list cache keys without admin role", user.Username, user.Id)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Admin required"}`))
			return
		}
	}

	//for key, value := range data.Apps {
	var orgId string
	category := ""
	location := strings.Split(request.URL.String(), "/")
	if location[1] == "api" {
		if len(location) <= 4 {
			//log.Printf("Path too short: %d", len(location))
		} else {
			if location[4] == "category" && len(location) > 5 {
				category = location[5]
				if strings.Contains(category, "?") {
					category = strings.Split(category, "?")[0]
				}
			} else {
				orgId = location[4]
			}
		}
	}

	// Overwriting, as we don't want it to work that way
	// Should use Org-Id header instead
	orgId = user.ActiveOrg.Id
	categoryList, categoryOk := request.URL.Query()["category"]
	if categoryOk && len(categoryList) > 0 {
		//category = categoryList[0]
		category = categoryList[0]
	}

	orgQuery, orgOk := request.URL.Query()["org_id"]
	if orgOk && len(orgQuery) > 0 {
		orgId = orgQuery[0]
	}

	if usererr != nil {
		if len(category) == 0 || category == "default" {
			log.Printf("[WARNING] No category provided in request. Returning 400.")
			resp.WriteHeader(400)
			resp.Write([]byte(`{"success": false, "reason": "No category provided"}`))
			return
		}

		// NEED to check the org etc
		if len(orgId) == 0 {
			log.Printf("[WARNING] No org ID provided in request. Returning 400.")
			resp.WriteHeader(400)
			resp.Write([]byte(`{"success": false, "reason": "No org ID provided"}`))
			return
		}
	}

	// Requires being admin
	if strings.ToLower(category) == "protected" {
		if user.Role != "admin" {
			resp.WriteHeader(403)
			resp.Write([]byte(`{"success": false, "reason": "Admin required to access protected category"}`))
			return
		}
	}

	ctx := GetContext(request)
	org, err := GetOrg(ctx, orgId)
	if err != nil {
		log.Printf("[INFO] Organization '%s' doesn't exist: %s", orgId, err)
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	maxAmount := 100
	top, topOk := request.URL.Query()["top"]
	if topOk && len(top) > 0 {
		val, err := strconv.Atoi(top[0])
		if err == nil {
			maxAmount = val
		}
	}

	cursor := ""
	cursorList, cursorOk := request.URL.Query()["cursor"]
	if cursorOk && len(cursorList) > 0 {
		cursor = cursorList[0]
	}

	keys := []CacheKeyData{}
	newCursor := ""
	isSuccess := true
	if keyList, keyOk := request.URL.Query()["key"]; keyOk && len(keyList) > 0 {
		key := keyList[0]

		cacheId := fmt.Sprintf("%s_%s", user.ActiveOrg.Id, key)
		if len(category) > 0 {
			cacheId = fmt.Sprintf("%s_%s_%s", user.ActiveOrg.Id, key, category)
		}

		cacheItem, err := GetDatastoreKey(ctx, cacheId, category)
		if err != nil {
			isSuccess = false
		}

		keys = []CacheKeyData{
			*cacheItem,
		}
	} else if searchList, searchOk := request.URL.Query()["search"]; searchOk && len(searchList) > 0 && searchList[0] != "" {
		// Prefix search within a category (e.g. DataGrid "starts with").
		// Require a real category so the scan stays bounded - never an org-wide scan.
		if len(category) == 0 || category == "default" {
			log.Printf("[WARNING] Prefix search attempted without a category. Returning 400.")
			resp.WriteHeader(400)
			resp.Write([]byte(`{"success": false, "reason": "A category is required to search keys"}`))
			return
		}

		keys, newCursor, err = GetCacheKeysByPrefix(ctx, org.Id, category, searchList[0], maxAmount, cursor)
		if err != nil {
			isSuccess = false
		}
	} else {
		keys, newCursor, err = GetAllCacheKeys(ctx, org.Id, category, maxAmount, cursor)
		if err != nil {
			isSuccess = false
		}
	}

	// This is NOT required unless automation/other config is set.
	foundCategories := []string{}
	categoryConfig := &DatastoreCategoryUpdate{}
	if len(category) > 0 && category != "default" {
		foundCategories = append(foundCategories, category)
		categoryConfig, err = GetDatastoreCategoryConfig(ctx, org.Id, category)
		if err != nil {
			//if debug {
			//	log.Printf("[WARNING] Failed to get category config for org %s: %s", org.Id, err)
			//}
		}
	} else {
		allCategories, err := GetDatastoreCategories(ctx, org.Id)
		if err == nil {
			for _, cat := range allCategories {
				if len(cat.Category) <= 1 || cat.Category == "default" {
					continue
				}

				foundCategories = append(foundCategories, cat.Category)
			}
		}

		for _, key := range keys {
			if len(key.Category) <= 1 || key.Category == "default" {
				continue
			}

			if ArrayContains(foundCategories, key.Category) {
				continue
			}

			foundCategories = append(foundCategories, key.Category)
		}
	}

	if orgId != user.ActiveOrg.Id {
		if !categoryConfig.Settings.Public {
			sourceExecution, sourceExecutionOk := request.URL.Query()["execution_id"]
			sourceAuth, sourceAuthOk := request.URL.Query()["authorization"]
			if !sourceAuthOk || !sourceExecutionOk {
				log.Printf("[AUDIT] User %s (%s) tried to list cache keys for org %s without access", user.Username, user.Id, orgId)
				resp.WriteHeader(401)
				resp.Write([]byte(`{"success": false, "reason": "This category is no longer public."}`))
				return
			}

			foundExec, err := GetWorkflowExecution(ctx, sourceExecution[0])
			if err != nil {
				log.Printf("[WARNING] Failed getting exec during cache set: %s", err)
				resp.WriteHeader(500)
				resp.Write([]byte(`{"success": false, "reason": "No permission to get execution (2)"}`))
				return
			}

			if sourceAuth[0] != foundExec.Authorization {
				log.Printf("[INFO] Execution auth %s and %s don't match", foundExec.Authorization, sourceAuth[0])
				resp.WriteHeader(403)
				resp.Write([]byte(`{"success": false, "reason": "Failed authentication (3)"}`))
				return
			}

			if len(foundExec.ExecutionOrg) == 0 {
				log.Printf("[WARNING] Execution %s doesn't have an org set", foundExec.ExecutionId)
				resp.WriteHeader(403)
				resp.Write([]byte(`{"success": false, "reason": "Failed authentication (4)"}`))
				return
			}
		}

		// Cleanup just in case
		categoryConfig = &DatastoreCategoryUpdate{}
		for keyIndex, _ := range keys {
			keys[keyIndex].WorkflowId = ""
			keys[keyIndex].ExecutionId = ""
			keys[keyIndex].PublicAuthorization = ""
			keys[keyIndex].SuborgDistribution = []string{}
		}
	}

	// Sort categories
	sort.SliceStable(foundCategories, func(i, j int) bool {
		return foundCategories[i] < foundCategories[j]
	})

	newReturn := CacheReturn{
		Success:     isSuccess,
		Keys:        keys,
		Cursor:      newCursor,
		Amount:      len(keys),
		TotalAmount: -1,

		Category: category,
		Config:   *categoryConfig,

		Categories: foundCategories,
	}

	outputTypeList, outputTypeOk := request.URL.Query()["type"]
	if outputTypeOk && len(outputTypeList) > 0 {
		outputType := outputTypeList[0]

		if outputType == "ndjson" || outputType == "csv" || outputType == "raw" {
			outputString := ""
			for _, key := range newReturn.Keys {
				if len(key.Value) == 0 {
					continue
				}

				newValue := strings.ReplaceAll(strings.ReplaceAll(key.Value, "\\n", "\n"), "\\r", "\r")
				newValue = strings.ReplaceAll(strings.ReplaceAll(newValue, "\n", "\\n"), "\r", "\\r")

				outputString += newValue + "\n"
			}

			// This forces browsers to download for some reason?
			//resp.Header().Set("Content-Type", "application/x-ndjson")
			resp.WriteHeader(200)
			resp.Write([]byte(outputString))
			return

		} else if outputType == "values" || outputType == "json" {
			newOutput := []string{}
			for _, key := range newReturn.Keys {
				if len(key.Value) == 0 {
					continue
				}

				newOutput = append(newOutput, key.Value)
			}

			marshalledOutput, err := json.MarshalIndent(newOutput, "", "  ")
			if err != nil {
				log.Printf("[WARNING] Failed to marshal cache values for org %s: %s", org.Id, err)
				resp.WriteHeader(500)
				resp.Write([]byte(`{"success": false, "reason": "Something went wrong in cache value json management. Please refresh."}`))
				return
			}

			resp.Header().Set("Content-Type", "application/json")
			resp.WriteHeader(200)
			resp.Write(marshalledOutput)
			return

		} else if outputType == "keys" {
			fullString := ""
			for _, key := range newReturn.Keys {
				fullString += fmt.Sprintf("%s\n", key.Key)
			}

			resp.Write([]byte(fullString))

			// Somehow this creates superflous request?
			//resp.WriteHeader(200)
			return

		} else if outputType == "meta" {
			marshalledOutput, err := json.MarshalIndent(newReturn.Keys, "", "  ")
			if err != nil {
				log.Printf("[WARNING] Failed to marshal cache keys for org %s: %s", org.Id, err)
				resp.WriteHeader(500)
				resp.Write([]byte(`{"success": false, "reason": "Something went wrong in cache key json management. Please refresh."}`))
				return
			}

			resp.Header().Set("Content-Type", "application/json")
			resp.WriteHeader(200)
			resp.Write(marshalledOutput)
			return
		}
	}

	categoryCount, err := GetCacheKeyCount(ctx, orgId, category)
	if err != nil {
		log.Printf("[WARNING] Failed to get cache key count for org %s: %s", org.Id, err)
	} else {
		newReturn.TotalAmount = categoryCount
	}

	b, err := json.Marshal(newReturn)
	if err != nil {
		log.Printf("[WARNING] Failed to marshal cache keys for org %s: %s", org.Id, err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false, "reason": "Something went wrong in cache key json management. Please refresh."}`))
		return
	}

	if err != nil {
		log.Printf("[INFO] Failed getting cache key list for org %s: %s", org.Id, err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	resp.WriteHeader(200)
	resp.Write(b)
}

func HandleCacheConfig(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[DEBUG] Api authentication failed in cache config: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed authentication"}`))
		return
	}

	if user.ActiveOrg.Role != "admin" {
		log.Printf("[AUDIT] User %s (%s) tried to list cache keys without admin role", user.Username, user.Id)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Only admins can distribute cache to sub-orgs"}`))
		return
	}

	var orgId string
	location := strings.Split(request.URL.String(), "/")
	if location[1] == "api" {
		if len(location) <= 4 {
			log.Printf("Path too short: %d", len(location))
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		orgId = location[4]
	}

	if len(orgId) == 0 {
		log.Printf("[ERROR] Missing org id in cache config")
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Missing org id"}`))
		return
	}

	type cacheConfig struct {
		Key            string   `json:"key"`
		Action         string   `json:"action"`
		Category       string   `json:"category"`
		SelectedSuborg []string `json:"selected_suborgs"`
	}

	var config cacheConfig
	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Printf("Error with body read: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	err = json.Unmarshal(body, &config)
	if err != nil {
		log.Printf("[WARNING] Failed unmarshalling in cache config: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	ctx := GetContext(request)
	if config.Category == "default" {
		config.Category = ""
	}

	cacheId := fmt.Sprintf("%s_%s", orgId, config.Key)
	cache, err := GetDatastoreKey(ctx, cacheId, config.Category)
	if err != nil {
		log.Printf("[WARNING] Failed getting cache key '%s' for org %s (config)", config.Key, orgId)
		resp.WriteHeader(400)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed to get key. Does it exist?", "extra": "%s"}`, cache.Key)))
		return
	}

	if config.Action == "suborg_distribute" {

		if len(config.SelectedSuborg) == 0 {
			cache.SuborgDistribution = []string{}
		} else {
			cache.SuborgDistribution = config.SelectedSuborg
		}

		err = SetDatastoreKey(ctx, *cache)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache key '%s' for org %s (config)", config.Key, orgId)
			resp.WriteHeader(400)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed to set key. Does it exist?", "extra": "%s"}`, cache.Key)))
			return
		}
	}

	log.Printf("[INFO] Successfully updated cache key '%s' for org %s", config.Key, orgId)

	resp.WriteHeader(200)
	resp.Write([]byte(`{"success": true, "reason" : "Cache updated successfully!"}`))
}

func HandleDeleteCacheKey(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[DEBUG] Api authentication failed in delete cache key: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed authentication"}`))
		return
	}

	//for key, value := range data.Apps {
	var orgId string
	var cacheKey string
	location := strings.Split(request.URL.String(), "/")
	if location[1] == "api" {
		if len(location) <= 4 {
			log.Printf("Path too short: %d", len(location))
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		orgId = location[4]
		cacheKey = location[6]
	}

	if len(cacheKey) == 0 || len(orgId) == 0 {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Missing org id or cache key"}`))
		return
	}

	ctx := GetContext(request)
	if orgId != user.ActiveOrg.Id {
		log.Printf("[INFO] OrgId '%s' and %s don't match (delete cache key)", orgId, user.ActiveOrg.Id)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Organization ID's don't match"}`))
		return
	}

	cacheKey, err = url.QueryUnescape(strings.Trim(cacheKey, " "))
	if err != nil {
		log.Printf("[WARNING] Failed to unescape cache key %s: %s", cacheKey, err)
		cacheKey = strings.Trim(cacheKey, " ")
	}

	//cacheKey = strings.Replace(cacheKey, "%20", " ", -1)
	cacheKey = strings.Trim(cacheKey, " ")
	cacheId := fmt.Sprintf("%s_%s", orgId, cacheKey)

	cacheData, err := GetDatastoreKey(ctx, cacheId, "")
	if err != nil || cacheData.Key == "" {
		log.Printf("[WARNING] Failed to GET datastore key '%s' for org %s (delete)", cacheId, orgId)
		resp.WriteHeader(400)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed to get key. Does it exist?", "extra": "%s"}`, cacheData.Key)))
		return
	}

	if cacheData.OrgId != user.ActiveOrg.Id {
		log.Printf("[INFO] OrgId '%s' and '%s' don't match", cacheData.OrgId, user.ActiveOrg.Id)
		resp.WriteHeader(403)
		resp.Write([]byte(`{"success": false, "reason": "Organization ID's don't match"}`))
		return
	}

	entity := "org_cache"

	DeleteKey(ctx, entity, cacheId)
	if len(cacheData.WorkflowId) > 0 {
		escapedKey := url.QueryEscape(cacheKey)

		DeleteKey(ctx, entity, fmt.Sprintf("%s_%s_%s", orgId, cacheData.WorkflowId, cacheData.Key))
		DeleteKey(ctx, entity, fmt.Sprintf("%s_%s_%s", orgId, cacheData.WorkflowId, escapedKey))

		DeleteKey(ctx, entity, fmt.Sprintf("%s_%s", cacheData.WorkflowId, cacheData.Key))

		DeleteKey(ctx, entity, fmt.Sprintf("%s_%s", cacheData.WorkflowId, escapedKey))
	}

	DeleteCache(ctx, cacheKey)
	DeleteCache(ctx, fmt.Sprintf("datastore_category_%s", user.ActiveOrg.Id))
	DeleteCache(ctx, fmt.Sprintf("%s_%s", entity, cacheKey))
	DeleteCache(ctx, fmt.Sprintf("%s_%s", entity, orgId))

	DeleteCache(ctx, fmt.Sprintf("%s_%s", orgId, cacheData.Key))
	DeleteCache(ctx, fmt.Sprintf("%s_%s_%s", orgId, cacheData.Key, cacheData.Category))

	DeleteCache(ctx, fmt.Sprintf("%s__%s_%s_50", entity, orgId, cacheData.Category))
	DeleteCache(ctx, fmt.Sprintf("%s__%s_%s_100", entity, orgId, cacheData.Category))
	DeleteCache(ctx, fmt.Sprintf("%s__%s_%s_1000", entity, orgId, cacheData.Category))

	if debug { 
		log.Printf("[DEBUG] Successfully Deleted key '%s' for org %s", cacheKey, orgId)
	}

	resp.WriteHeader(200)
	resp.Write([]byte(`{"success": true}`))
}

func HandleDeleteCacheKeyPost(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed reading body"}`))
		return
	}

	//for key, value := range data.Apps {
	var fileId string
	location := strings.Split(request.URL.String(), "/")
	if location[1] == "api" {
		if len(location) <= 4 {
			log.Printf("Path too short: %d", len(location))
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		fileId = location[4]
	}

	var tmpData CacheKeyData
	err = json.Unmarshal(body, &tmpData)
	if err != nil {
		log.Printf("[WARNING] Failed unmarshalling in DELETE cache value: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if tmpData.OrgId != fileId {
		log.Printf("[INFO] OrgId %s and %s don't match", tmpData.OrgId, fileId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Organization ID's don't match"}`))
		return
	}

	ctx := GetContext(request)
	org, err := GetOrg(ctx, tmpData.OrgId)
	if err != nil {
		log.Printf("[INFO] Organization doesn't exist: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	selectedOrg := tmpData.OrgId
	if len(tmpData.ExecutionId) > 0 {
		workflowExecution, err := GetWorkflowExecution(ctx, tmpData.ExecutionId)
		if err != nil {
			log.Printf("[INFO] Failed getting the execution: %s", err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "No permission to get execution"}`))
			return
		}

		// Allows for execution auth AND user auth
		if workflowExecution.Authorization != tmpData.Authorization {
			// Get the user?
			user, err := HandleApiAuthentication(resp, request)
			if err != nil {
				log.Printf("[INFO] Execution auth %s and %s don't match", workflowExecution.Authorization, tmpData.Authorization)
				resp.WriteHeader(401)
				resp.Write([]byte(`{"success": false, "reason": "Failed authentication"}`))
				return
			} else {
				if user.ActiveOrg.Id != org.Id {
					log.Printf("[INFO] Execution auth %s and %s don't match (2)", workflowExecution.Authorization, tmpData.Authorization)
					resp.WriteHeader(401)
					resp.Write([]byte(`{"success": false, "reason": "Failed authentication"}`))
					return
				}
			}
		}

		if workflowExecution.Status != "EXECUTING" {
			log.Printf("[INFO] Workflow %s isn't executing (delete cache key)", workflowExecution.ExecutionId)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Workflow isn't executing (2)"}`))
			return
		}

		if workflowExecution.ExecutionOrg != org.Id {
			log.Printf("[INFO] Org %s wasn't used to execute %s", org.Id, workflowExecution.ExecutionId)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Bad organization specified"}`))
			return
		}
	} else {
		// Fail over to user if exec isn't there

		user, err := HandleApiAuthentication(resp, request)
		if err != nil {
			log.Printf("[INFO] Missing auth when deleting key %s for org %s", tmpData.Key, tmpData.OrgId)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Failed authentication"}`))
			return
		}

		if user.ActiveOrg.Id != org.Id {
			org, err = GetOrg(ctx, user.ActiveOrg.Id)
			if err != nil {
				log.Printf("[INFO] Organization doesn't exist in cache delete: %s", err)
				resp.WriteHeader(401)
				resp.Write([]byte(`{"success": false}`))
				return
			}
		}

		selectedOrg = user.ActiveOrg.Id
	}

	tmpData.Key = strings.Trim(tmpData.Key, " ")
	cacheId := fmt.Sprintf("%s_%s", selectedOrg, tmpData.Key)
	cacheData, err := GetDatastoreKey(ctx, cacheId, tmpData.Category)
	if err != nil || len(cacheData.Key) == 0 {
		//log.Printf("[WARNING] Failed to DELETE cache key '%s' for org %s (delete) in category '%s'. Does it exist?", tmpData.Key, tmpData.OrgId, tmpData.Category)

		resp.WriteHeader(400)
		result := ResultChecker{
			Success: false,
			Reason:  "Failed to get key. Does it exist? Correct category?",
			Extra:   fmt.Sprintf("Attempted to delete key '%s'", tmpData.Key),
		}

		if len(tmpData.Category) > 0 {
			result.Extra = fmt.Sprintf("Attempted to delete key '%s' in category '%s'", tmpData.Key, tmpData.Category)
		}

		marshalled, err := json.Marshal(result)
		if err != nil {
			resp.Write([]byte(`{"success": false, "reason": "Failed to get key. Does it exist?"}`))
			return
		}

		resp.Write(marshalled)
		return
	}

	if len(tmpData.Category) > 0 {
		cacheId = fmt.Sprintf("%s_%s", cacheId, tmpData.Category)
	}

	cacheId = url.QueryEscape(cacheId)
	if len(cacheId) > 127 {
		cacheId = cacheId[:127]
	}

	if debug {
		log.Printf("[DEBUG] Attempting to delete cache key '%s' for org %s. Error: %#v. Cache ID: %s", tmpData.Key, tmpData.OrgId, err, string(cacheId))
	}

	entity := "org_cache"
	err = DeleteKey(ctx, entity, cacheId)
	if err != nil {
		//log.Printf("[WARNING] Failed to DELETE cache key '%s' (2) for org %s (delete) (2)", cacheId, tmpData.OrgId)
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false, "reason": "Failed to delete key"}`))
		return
	}

	if len(cacheData.WorkflowId) > 0 {
		escapedKey := url.QueryEscape(tmpData.Key)

		DeleteKey(ctx, entity, fmt.Sprintf("%s_%s_%s", org.Id, cacheData.WorkflowId, cacheData.Key))
		DeleteKey(ctx, entity, fmt.Sprintf("%s_%s_%s", org.Id, cacheData.WorkflowId, escapedKey))

		DeleteKey(ctx, entity, fmt.Sprintf("%s_%s", cacheData.WorkflowId, cacheData.Key))
		DeleteKey(ctx, entity, fmt.Sprintf("%s_%s", cacheData.WorkflowId, escapedKey))
	}

	DeleteCache(ctx, tmpData.Key)
	DeleteCache(ctx, fmt.Sprintf("%s_%s", entity, tmpData.Key))
	DeleteCache(ctx, fmt.Sprintf("%s_%s", entity, org.Id))
	DeleteCache(ctx, fmt.Sprintf("%s_%s", entity, cacheId))
	DeleteCache(ctx, fmt.Sprintf("%s_%s", entity, url.QueryEscape(cacheId)))

	normalizedCategory := strings.ReplaceAll(strings.ToLower(tmpData.Category), " ", "_")
	if normalizedCategory == "default" {
		normalizedCategory = ""
	}
	DeleteCache(ctx, fmt.Sprintf("%s__%s_", entity, org.Id))
	DeleteCache(ctx, fmt.Sprintf("%s__%s", entity, org.Id))
	DeleteCache(ctx, fmt.Sprintf("%s__%s_%s", entity, org.Id, normalizedCategory))
	DeleteCache(ctx, fmt.Sprintf("%s__%s_%s_50", entity, org.Id, normalizedCategory))
	DeleteCache(ctx, fmt.Sprintf("%s__%s_%s_100", entity, org.Id, normalizedCategory))
	DeleteCache(ctx, fmt.Sprintf("%s__%s_%s_1000", entity, org.Id, normalizedCategory))

	result := ResultChecker{
		Success: true,
		Reason:  fmt.Sprintf("Key '%s' deleted", tmpData.Key),
	}

	if debug { 
		log.Printf("[DEBUG] Successfully Deleted key '%s' for org %s in category '%s'", tmpData.Key, tmpData.OrgId, tmpData.Category)
	}

	// Marshal
	resp.WriteHeader(200)
	jsonResult, err := json.Marshal(result)
	if err != nil {
		log.Printf("[WARNING] Failed to marshal result: %s", err)
		resp.Write([]byte(`{"success": true}`))
		return
	}

	resp.Write([]byte(jsonResult))
}

func HandleSetCacheKey(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, usererr := HandleApiAuthentication(resp, request)

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Printf("[WARNING] Failed reading body in set cache: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed reading body"}`))
		return
	}

	//for key, value := range data.Apps {
	var fileId string
	location := strings.Split(request.URL.String(), "/")
	if location[1] == "api" {
		if len(location) <= 4 {
			log.Printf("Path too short: %d", len(location))
			resp.WriteHeader(400)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		fileId = location[4]
	}

	// Check if body contains "key": <number> and replace it, as it should be a string
	var tmpData CacheKeyDataMini
	err = json.Unmarshal(body, &tmpData)
	if err != nil {
		log.Printf("[WARNING] Failed unmarshalling in setvalue (2): %s", err)
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	ctx := GetContext(request)
	if len(tmpData.OrgId) == 0 {
		//log.Printf("[INFO] No org id specified. User org: %#v", user.ActiveOrg)
		tmpData.OrgId = user.ActiveOrg.Id
	}

	org, err := GetOrg(ctx, tmpData.OrgId)
	if err != nil {
		log.Printf("[WARNING] Organization doesn't exist: %s", err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	workflowExecution, err := GetWorkflowExecution(ctx, tmpData.ExecutionId)
	if err != nil {
		if len(tmpData.ExecutionId) > 0 {
			log.Printf("[WARNING] Failed getting exec during cache set: %s", err)
			resp.WriteHeader(500)
			resp.Write([]byte(`{"success": false, "reason": "No permission to get execution"}`))
			return
		}

		workflowExecution.Authorization = uuid.NewV4().String()
	}

	if workflowExecution.Authorization != tmpData.Authorization || len(tmpData.Authorization) == 0 || len(workflowExecution.Authorization) == 0 {

		// Get the user?
		if usererr != nil {
			log.Printf("[INFO] Execution auth %s and %s don't match", workflowExecution.Authorization, tmpData.Authorization)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Failed authentication"}`))
			return
		} else {
			if user.ActiveOrg.Id != org.Id {
				log.Printf("[INFO] Execution auth %s and %s don't match (2)", workflowExecution.Authorization, tmpData.Authorization)
				resp.WriteHeader(401)
				resp.Write([]byte(`{"success": false, "reason": "Failed authentication"}`))
				return
			}

			tmpData.OrgId = user.ActiveOrg.Id
		}
	} else {
		if workflowExecution.Status != "EXECUTING" {
			log.Printf("[INFO] Workflow '%s' isn't executing (update cache key)", workflowExecution.ExecutionId)
			resp.WriteHeader(400)
			resp.Write([]byte(`{"success": false, "reason": "Workflow isn't executing (4)"}`))
			return
		}

		if workflowExecution.ExecutionOrg != org.Id {
			log.Printf("[INFO] Org '%s' wasn't used to execute %s", org.Id, workflowExecution.ExecutionId)
			resp.WriteHeader(403)
			resp.Write([]byte(`{"success": false, "reason": "Bad organization specified"}`))
			return
		}
	}

	if tmpData.OrgId != fileId {
		log.Printf("[INFO] OrgId '%s' and '%s' don't match (set cache)", tmpData.OrgId, fileId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Organization ID's don't match"}`))
		return
	}

	if len(tmpData.Value) == 0 {
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false, "reason": "Value can't be empty"}`))
		return
	}

	if strings.ToLower(tmpData.Category) == "default" {
		tmpData.Category = ""
	}

	tmpData.Key = strings.Trim(tmpData.Key, " ")
	// Check if cache already existed and if distributed
	cacheId := fmt.Sprintf("%s_%s", tmpData.OrgId, tmpData.Key)
	cacheData, err := GetDatastoreKey(ctx, cacheId, tmpData.Category)
	if err == nil {
		tmpData.SuborgDistribution = cacheData.SuborgDistribution
	}

	// This is just to ensure that input data doesn't get directly set in the database
	parsedKey := CacheKeyData{
		Category:           tmpData.Category,
		Key:                tmpData.Key,
		Value:              tmpData.Value,
		ExecutionId:        tmpData.ExecutionId,
		Authorization:      tmpData.Authorization,
		SuborgDistribution: tmpData.SuborgDistribution,
		Tags:               tmpData.Tags,

		IgnoreSecurityRules: tmpData.IgnoreSecurityRules, // Makes sure we don't stop manual requests even if security rules exist. Basically a rule.
		OrgId:               user.ActiveOrg.Id,
		UpdatedBy:           user.Username,
	}

	if len(user.ActiveOrg.Id) == 0 {
		parsedKey.OrgId = tmpData.OrgId
	}

	existed, err := SetDatastoreKeyBulk(ctx, []CacheKeyData{parsedKey})
	if err != nil {
		log.Printf("[ERROR] Failed to set cache key '%s' for org %s", tmpData.Key, tmpData.OrgId)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false, "reason": "Failed to set data. Please try again, or contact support@shuffler.io"}`))
		return
	}

	if len(existed) == 0 {
		//log.Printf("[INFO] Successfully set key '%s' for org '%s' (%s). Category: %s", tmpData.Key, org.Name, tmpData.OrgId, tmpData.Category)
	} else {
		//log.Printf("[INFO] Successfully set key '%s' for org '%s' (%s). New key: %#v. Category: %s", tmpData.Key, org.Name, tmpData.OrgId, !existed[0].Existed, tmpData.Category)
	}

	type returnStruct struct {
		Success     bool               `json:"success"`
		KeysExisted []DatastoreKeyMini `json:"keys_existed"`
	}

	returnData := returnStruct{
		Success:     true,
		KeysExisted: existed,
	}

	b, err := json.Marshal(returnData)
	if err != nil {
		b = []byte(`{"success": true}`)
	}

	resp.WriteHeader(200)
	resp.Write(b)
}

func handleRunDatastoreAutomation(ctx context.Context, cacheData CacheKeyData, automation DatastoreAutomation) error {
	if len(cacheData.OrgId) == 0 {
		return errors.New("CacheKeyData.OrgId is required for handleRunAutomation")
	}

	if len(cacheData.Category) == 0 {
		return errors.New("CacheKeyData.Category is required for handleRunAutomation")
	}
    
	if ctx == nil {
		ctx = context.Background()
	}

	parsedName := strings.ReplaceAll(strings.ToLower(automation.Name), " ", "_")

	// These are ran pre-execution
	if parsedName == "security_rules" {
		return nil
	}

	// Unmarshal cacheData.Value to parsedOutput
	parsedOutput := map[string]interface{}{}
	if err := json.Unmarshal([]byte(cacheData.Value), &parsedOutput); err != nil {
		//log.Printf("[ERROR] Failed to unmarshal cacheData.Value: %s", err)
		parsedOutput = map[string]interface{}{}
		parsedOutput["value"] = cacheData.Value
	}

	if parsedOutput == nil {
		parsedOutput = map[string]interface{}{}
	}

	parsedOutput["shuffle_datastore"] = map[string]interface{}{
		"action":              "update",
		"key":                 cacheData.Key,
		"category":            cacheData.Category,
		"org_id":              cacheData.OrgId,
		"timestamp":           cacheData.Edited,
		"workflow_id":         cacheData.WorkflowId,
		"suborg_distribution": cacheData.SuborgDistribution,
		"tags":                cacheData.Tags,
	}

	marshalledBody, err := json.Marshal(parsedOutput)
	if err != nil {
		log.Printf("[ERROR] Failed to marshal parsedOutput. Key %s, Category: %s, org: %s, err: %s", cacheData.Key, cacheData.Category, cacheData.OrgId, err)
		return err
	}

	backendUrl := "https://shuffler.io"
	if len(os.Getenv("BASE_URL")) > 0 {
		backendUrl = os.Getenv("BASE_URL")
	}

	if len(os.Getenv("SHUFFLE_CLOUDRUN_URL")) > 0 && strings.Contains(os.Getenv("SHUFFLE_CLOUDRUN_URL"), "http") {
		backendUrl = os.Getenv("SHUFFLE_CLOUDRUN_URL")
	}

	org, err := GetOrg(ctx, cacheData.OrgId)
	if err != nil {
		return err
	}

	foundApikey := ""
	for _, user := range org.Users {
		foundUser, err := GetUser(ctx, user.Id)
		if err != nil {
			continue
		}

		if len(foundUser.Role) == 0 || foundUser.Role == "org-reader" {
			continue
		}

		if len(foundUser.ApiKey) > 0 {
			foundApikey = foundUser.ApiKey
			break
		}
	}

	if parsedName == "run_ai_agent" {
		if len(automation.Options) == 0 {
			log.Printf("[ERROR] AI agent: No options provided for run_ai_agent automation for key %s in category %s", cacheData.Key, cacheData.Category)
			return errors.New("No options provided for run_ai_agent automation")
		}

		log.Printf("[INFO] AI agent: Handling 'run_ai_agent' automation for key '%s' in category '%s'", cacheData.Key, cacheData.Category)
		if len(foundApikey) == 0 {
			log.Printf("[ERROR] No admin user with API key found for org %s", cacheData.OrgId)
			return errors.New("No admin user with API key found")
		}

		// Already handled check
		for optionKey, option := range automation.Options {
			// 'remove' icon in the UI does this
			if option.Disabled {
				continue
			}

			if len(option.Value) < 10 {
				//log.Printf("[DEBUG] Actions info too short: %s - skipping", option.Key)
				continue
			}

			agentTagName := fmt.Sprintf("agent-%s", option.Key)
			if ArrayContains(cacheData.Tags, agentTagName) {
				continue
			}

			// Check if previous has finished/timed out
			// This allows next to run. Default agent cache timeout is 30 seconds~
			if optionKey > 0 {
				oldKey := automation.Options[optionKey-1]
				oldCacheName := fmt.Sprintf("%s_%s_%s_%s", cacheData.Key, cacheData.Category, cacheData.OrgId, oldKey.Key)
				_, err := GetCache(ctx, oldCacheName)
				if err == nil {
					if debug { 
						log.Printf("[DEBUG] PREV agent cache hit for %s - skipping for now", oldCacheName)
					}

					continue
				}
			}

			// As a fallback in case of slow datastore update
			// Prevents super quick reruns
			cacheName := fmt.Sprintf("%s_%s_%s_%s", cacheData.Key, cacheData.Category, cacheData.OrgId, option.Key)
			_, err := GetCache(ctx, cacheName)
			if err == nil {
				//log.Printf("[DEBUG] Cache hit for %s - skipping to avoid re-running agent", cacheName)
				continue
			}

			// 30 seconds
			SetCache(ctx, cacheName, []byte("1"), 60000, true)
			if !strings.Contains(option.Key, "action") {
				log.Printf("[WARNING] Agent option key %s does not contain 'action' - skipping to avoid confusion. This may cause the agent to not run if no other options are present.", option.Key)
				continue
			}

			// Makes sure we don't re-run the same twice
			cacheData.Tags = append(cacheData.Tags, agentTagName)
			err = SetDatastoreKeyMeta(ctx, cacheData)
			if err != nil {
				log.Printf("[ERROR] Failed to set cache key after running AI agent: %s", err)
			}

			requiredApps := []string{"shuffle-datastore"}
			for _, req := range requiredApps {

				if !ArrayContains(option.Apps, req) {
					option.Apps = append(option.Apps, req)
				}
			}

			allowedApps := strings.Join(option.Apps, ",")
			/*
			parsedParams := []map[string]string{
				map[string]string{
					"name":  "app_name",
					"value": allowedApps,
				},
				map[string]string{
					"name":  "action",
					"value": "API",
				},
			}

			// option.Value += fmt.Sprintf("\n%s", cacheData.Value)
			parsedParams = append(parsedParams, map[string]string{
				"name":  "input",
				"value": fmt.Sprintf("TASK: %s\n\nKey: %s\nCategory: %s\n\nRAW DATA:\n%s", option.Value, cacheData.Key, cacheData.Category, cacheData.Value),
			})

			//agentUrl := fmt.Sprintf("%s/api/v1/apps/agent_starter/run", backendUrl)
			agentStartRequest := AgentStartRequest{
				//ID          string              `json:"id"`
				Name:        "agent",
				AppName:     "AI Agent",
				AppID:       "shuffle_agent",
				AppVersion:  "1.0.0",
				//Environment: "cloud",
				Parameters:  parsedParams,
			}
			*/

			agentUrl := fmt.Sprintf("%s/api/v1/agent", backendUrl)
			agentStartRequest := MCPRequest{
				Method: "tools/call",
				Params: MCPRequestParams{
					ToolName: allowedApps,
					Input: MCPRequestInput{
						Text: fmt.Sprintf("TASK: %s\n\nKey: %s\nCategory: %s\n\nRAW DATA:\n%s", option.Value, cacheData.Key, cacheData.Category, cacheData.Value),
					},
				},
			}

			newParsedBody, err := json.Marshal(agentStartRequest)
			if err != nil {
				log.Printf("[ERROR] Failed to marshal body for ai agent execution: %s", err)
				return err
			}

			client := GetExternalClient(agentUrl)
			req, err := http.NewRequest(
				"POST",
				agentUrl,
				bytes.NewBuffer(newParsedBody),
			)

			if err != nil {
				log.Printf("[ERROR] Failed to create request for enrichment workflow execution: %s", err)
				return err
			}

			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", foundApikey))
			req.Header.Set("Org-Id", cacheData.OrgId)
			req.Header.Set("X-Internal-Caller", "handleRunDatastoreAutomation")

			go client.Do(req)

			/*
			resp, err := 
			if err != nil {
				log.Printf("[ERROR] Failed to run ai agent execution request: %s", err)
				return err
			}

			defer resp.Body.Close()
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				log.Printf("[ERROR] Failed to read response body from AI AGENT execution request: %s", err)
				return err
			}

			if debug {
				log.Printf("[DEBUG] RESP FOR RUNNING AI AGENT (%d): %s", resp.StatusCode, string(body))
			}
			*/

			break
		}

	} else if parsedName == "enrich" {
		// Prevent recursion
		cacheKey := fmt.Sprintf("enrich_wait_%s_%s_%s", cacheData.OrgId, cacheData.Category, cacheData.Key)


		// Validates if the data is the same. Need a proper data diff
		//md5sum := Md5sum([]byte(cacheData.Value))
		//log.Printf("VALUE (%s):\n\n%s\n\n", md5sum, cacheData.Value)

		data, err := GetCache(ctx, cacheKey)
		if err == nil && data != nil {
			//cacheData := []byte(data.([]uint8))
			//if string(cacheData) == md5sum {
			//	return nil
			//}

			return nil
		}

		if debug { 
			log.Printf("[DEBUG] Running enrich automation for key %s in category %s", cacheData.Key, cacheData.Category)
		}

		//SetCache(ctx, cacheKey, []byte("1"), 1)
		var timeout int32 = 15000 
		if project.Environment != "cloud" {
			timeout = 60000 
		}

		SetCache(ctx, cacheKey, []byte("1"), timeout, true)
		if cacheData.Enrichments != nil && len(cacheData.Enrichments) > 0 {
		}

		// Send the data into shuffle_tools => parse_ioc?
		// Or generate a workflow that runs for it? :thinking:

		// Example process:
		// 1. Ingest IOC (hash/IP/domain/alert) => inject into datastore category
		// 2. Query reputation + passive DNS + WHOIS + SSL CT.
		// 3. Run lookup in historic sightings (SIEM, MISP).
		// 4. If file hash: submit to sandbox + static YARA.
		// 5. Map results to ATT&CK techniques and assign a risk score.
		// 6. Push enriched alert to SIEM/EDR/SOAR for automated playbook or analyst triage.
		// 7. If high confidence, add to blocklists / trigger containment / share via STIX/TAXII or MISP.

		// Getting started:
		// 1. Check for enrichments key. Stop if it exists.
		/*
			types := []iocParser.IndicatorType{
				iocParser.IPV4,
				iocParser.URL_LINK,
				iocParser.Domain,
				iocParser.Email,
			}
			foundIocs := iocParser.Parse(string(marshalledBody), types)
			log.Printf("RESP: %#v", foundIocs)
			if len(foundIocs) == 0 {
				log.Printf("[DEBUG] No IOCs found to enrich.")
				return nil
			}

			log.Printf("[DEBUG] Found %d IOCs to enrich.", len(foundIocs))
			for _, foundIoc := range foundIocs {
				log.Printf("[DEBUG] Found IOC: %#v", foundIoc)
			}
		*/

		if len(foundApikey) == 0 {
			log.Printf("[ERROR] No admin user with API key found for org %s", cacheData.OrgId)
			return errors.New("No admin user with API key found")
		}

		// Uses the same as the API /api/v*/workflows/generate  
		seedString := fmt.Sprintf("%s_Enable Threat feeds_webhook", cacheData.OrgId)

		hash := sha1.New()
		hash.Write([]byte(seedString))
		hashBytes := hash.Sum(nil)

		uuidBytes := make([]byte, 16)
		copy(uuidBytes, hashBytes)
		relevantWorkflowId := uuid.Must(uuid.FromBytes(uuidBytes)).String()

		// FIXME: If workflow doesn't exist - generate it 
		fullUrl := fmt.Sprintf("%s/api/v1/workflows/%s/execute", backendUrl, relevantWorkflowId)
		if debug { 
			log.Printf("[DEBUG] Running enrich automation workflow %s for key %s in category %s", relevantWorkflowId, cacheData.Key, cacheData.Category)
		}

		executionRequest := ExecutionRequest{
			ExecutionArgument: string(marshalledBody),
			ExecutionSource:   fmt.Sprintf("datastore|%s|%s", cacheData.Category, cacheData.Key),
		}

		newParsedBody, err := json.Marshal(executionRequest)
		if err != nil {
			log.Printf("[ERROR] Failed to marshal body for enrichment workflow execution: %s", err)
			return err
		}

		client := GetExternalClient(fullUrl)
		req, err := http.NewRequest(
			"POST",
			fullUrl,
			bytes.NewBuffer(newParsedBody),
		)

		if err != nil {
			log.Printf("[ERROR] Failed to create request for enrichment workflow execution: %s", err)
			return err
		}

		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", foundApikey))
		req.Header.Add("Org-Id", cacheData.OrgId)

		resp, err := client.Do(req)
		if err != nil {
			log.Printf("[ERROR] Failed to send enrichment workflow execution request: %s", err)
			return err
		}

		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Printf("[ERROR] Failed to read response body from enrichment workflow execution request: %s", err)
			return err
		}

		if resp.StatusCode != 200 { 
			log.Printf("[ERROR] Enrichment workflow execution request failed with status code %d. Body: %s", resp.StatusCode, string(body))
		}

		if debug { 
			log.Printf("[DEBUG] RESP FOR RUNNING ENRICHMENT (%d): %s", resp.StatusCode, string(body))
		}

	} else if parsedName == "run_workflow" {
		if len(automation.Options) == 0 {
			log.Printf("[ERROR] No options provided for 'run_workflow' automation for key %s in category %s", cacheData.Key, cacheData.Category)
			return errors.New("No options provided for 'run_workflow' automation")
		}

		for _, option := range automation.Options {
			if option.Key != "workflow_id" {
				continue
			}

			if len(option.Value) == 0 {
				continue
			}

			cacheData.WorkflowId = option.Value
			workflowIds := strings.Split(option.Value, ",")


			formattedBodyStruct := ExecutionRequest{
				ExecutionSource:   fmt.Sprintf("datastore_%s_%s", cacheData.Category, cacheData.Key),
				ExecutionArgument: string(marshalledBody),
			}

			marshalledFormattedBody, err := json.Marshal(formattedBodyStruct)
			if err != nil {
				log.Printf("[ERROR] Failed in marshalling data in 'run_workflow' datastore automation for workflow %s")
			} else {
				marshalledBody = marshalledFormattedBody
			}

			handled := []string{}
			for _, workflowId := range workflowIds {
				workflowId = strings.TrimSpace(workflowId)
				if ArrayContains(handled, workflowId) {
					continue
				}

				handled = append(handled, workflowId)

				go handleDatastoreAutomationRequest(ctx, marshalledBody, cacheData, automation, fmt.Sprintf("/api/v1/workflows/%s/execute", workflowId), "run_workflow")
			}

			break
		}

	} else if parsedName == "send_webhook" {
		if len(automation.Options) == 0 {
			log.Printf("[ERROR] No options provided for 'run_workflow' automation for key %s in category %s", cacheData.Key, cacheData.Category)
			return errors.New("No options provided for 'run_workflow' automation")
		}

		return handleDatastoreAutomationRequest(ctx, marshalledBody, cacheData, automation, "/api/v1/apps/HTTP/run", "webhook")

		// Send the webhook using the HTTP app with a POST request

	} else {
		return fmt.Errorf("Unknown automation name %s", automation.Name)
	}

	return nil
}
