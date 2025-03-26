package shuffle

import (
	"fmt"
	"log"
	"time"
	"sort"
	"strings"
	"strconv"

	"os"

	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/satori/go.uuid"
)

var PredictableDataTypes = []string{
    "app_executions",
    "workflow_executions",
    "workflow_executions_finished",
    "workflow_executions_failed",
    "app_executions_failed",
	"app_executions_cloud",
    "subflow_executions",
    "org_sync_actions",
    "workflow_executions_cloud",
    "workflow_executions_onprem",
    "api_usage",
    "ai_executions",
}

func HandleGetWidget(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in get widget: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	_ = user

	var dashboard string
	var widget string
	location := strings.Split(request.URL.String(), "/")
	if location[1] == "api" {
		if len(location) <= 6 {
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		dashboard = location[4]
		widget = location[6]
	}

	//log.Printf("Should get widget %s in dashboard %s", widget, dashboard)
	id := uuid.NewV4().String()

	// Returning some static info for now
	returnData := Widget{
		Success:   true,
		Id:        id,
		Title:     widget,
		Dashboard: dashboard,
		Data: []WidgetPoint{
			WidgetPoint{
				Key: widget,
				Data: []WidgetPointData{
					WidgetPointData{
						Key:  "11/21/2019",
						Data: 9,
						MetaData: WidgetMeta{
							Color: "#f86a3e",
						},
					},
					WidgetPointData{
						Key:  "11/22/2019",
						Data: 4,
					},
					WidgetPointData{
						Key:  "11/24/2019",
						Data: 12,
					},
				},
			},
			WidgetPoint{
				Key: "Intel",
				Data: []WidgetPointData{
					WidgetPointData{
						Key:  "11/22/2019",
						Data: 5,
						MetaData: WidgetMeta{
							Color: "cyan",
						},
					},
					WidgetPointData{
						Key:  "11/23/2019",
						Data: 8,
					},
					WidgetPointData{
						Key:  "11/24/2019",
						Data: 14,
					},
				},
			},
		},
	}

	newjson, err := json.Marshal(returnData)
	if err != nil {
		log.Printf("[ERROR] Failed marshal in get widget: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed unpacking data"}`)))
		return
	}

	resp.WriteHeader(200)
	resp.Write(newjson)
}

// Starts a new webhook
func HandleNewWidget(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in set new hook: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if user.Role == "org-reader" {
		log.Printf("[WARNING] Org-reader doesn't have access to make new widgets: %s (%s)", user.Username, user.Id)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Read only user"}`))
		return
	}

	type requestData struct {
		Id             string `json:"id"`
		Name           string `json:"name"`
		Type           string `json:"type"`
		Start          string `json:"start"`
		Auth           string `json:"auth"`
		Workflow       string `json:"workflow"`
		Environment    string `json:"environment"`
		Description    string `json:"description"`
		CustomResponse string `json:"custom_response"`
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Printf("[WARNING] Body data error in webhook set: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	_ = body

	/*
		ctx := GetContext(request)
		var requestdata requestData
		err = json.Unmarshal([]byte(body), &requestdata)
		if err != nil {
			log.Printf("[WARNING] Failed unmarshaling inputdata for webhook: %s", err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		newId := requestdata.Id
		if len(newId) != 36 {
			log.Printf("[WARNING] Bad webhook ID: %s", newId)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Invalid Webhook ID: bad formatting"}`))
			return
		}

		if requestdata.Id == "" || requestdata.Name == "" {
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Required fields id and name can't be empty"}`))
			return

		}

		validTypes := []string{
			"webhook",
		}

		isTypeValid := false
		for _, thistype := range validTypes {
			if requestdata.Type == thistype {
				isTypeValid = true
				break
			}
		}

		if !(isTypeValid) {
			log.Printf("Type %s is not valid. Try any of these: %s", requestdata.Type, strings.Join(validTypes, ", "))
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		// Let remote endpoint handle access checks (shuffler.io)
		baseUrl := "https://shuffler.io"
		if len(os.Getenv("SHUFFLE_GCEPROJECT")) > 0 && len(os.Getenv("SHUFFLE_GCEPROJECT_LOCATION")) > 0 {
			baseUrl = fmt.Sprintf("https://%s.%s.r.appspot.com", os.Getenv("SHUFFLE_GCEPROJECT"), os.Getenv("SHUFFLE_GCEPROJECT_LOCATION"))
		}

		currentUrl := fmt.Sprintf("%s/api/v1/hooks/webhook_%s", baseUrl, newId)
		startNode := requestdata.Start
		if requestdata.Environment == "cloud" && project.Environment != "cloud" {
			// https://shuffler.io/v1/hooks/webhook_80184973-3e82-4852-842e-0290f7f34d7c
			log.Printf("[INFO] Should START a cloud webhook for url %s for startnode %s", currentUrl, startNode)
			org, err := GetOrg(ctx, user.ActiveOrg.Id)
			if err != nil {
				log.Printf("Failed finding org %s: %s", org.Id, err)
				return
			}

			action := CloudSyncJob{
				Type:          "webhook",
				Action:        "start",
				OrgId:         org.Id,
				PrimaryItemId: newId,
				SecondaryItem: startNode,
				ThirdItem:     requestdata.Workflow,
				FourthItem:    requestdata.Auth,
			}

			err = executeCloudAction(action, org.SyncConfig.Apikey)
			if err != nil {
				log.Printf("[WARNING] Failed cloud action START webhook execution: %s", err)
				resp.WriteHeader(401)
				resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "%s"}`, err)))
				return
			} else {
				log.Printf("[INFO] Successfully set up cloud action schedule")
			}
		}

		hook := Hook{
			Id:        newId,
			Start:     startNode,
			Workflows: []string{requestdata.Workflow},
			Info: Info{
				Name:        requestdata.Name,
				Description: requestdata.Description,
				Url:         fmt.Sprintf("%s/api/v1/hooks/webhook_%s", baseUrl, newId),
			},
			Type:   "webhook",
			Owner:  user.Username,
			Status: "uninitialized",
			Actions: []HookAction{
				HookAction{
					Type:  "workflow",
					Name:  requestdata.Name,
					Id:    requestdata.Workflow,
					Field: "",
				},
			},
			Running:        false,
			OrgId:          user.ActiveOrg.Id,
			Environment:    requestdata.Environment,
			Auth:           requestdata.Auth,
			CustomResponse: requestdata.CustomResponse,
		}

		hook.Status = "running"
		hook.Running = true
		err = SetHook(ctx, hook)
		if err != nil {
			log.Printf("[WARNING] Failed setting hook: %s", err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}
	*/

	newId := "tmp"
	log.Printf("[INFO] Set up a new widget %s", newId)
	resp.WriteHeader(200)
	resp.Write([]byte(`{"success": true}`))
}

func GetSpecificStats(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	var orgId string
	var statsKey string
	location := strings.Split(request.URL.String(), "/")
	if location[1] == "api" {
		if len(location) <= 4 {
			log.Printf("Path too short: %d", len(location))
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		statsKey = location[4]
		if len(location) > 6 {
			orgId = location[4]
			statsKey = location[6]
		}
	}

	// Remove ? from orgId or statsKey
	orgId = strings.Split(orgId, "?")[0]
	statsKey = strings.Split(statsKey, "?")[0]

	if len(statsKey) <= 1 {
		log.Printf("[WARNING] Invalid stats key: %s", statsKey)
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false, "reason": "Invalid stats key"}`))
		return
	}

	statsKey = strings.ToLower(strings.ReplaceAll(statsKey, " ", "_"))

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in get stats: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	orgId = user.ActiveOrg.Id
	ctx := GetContext(request)
	info, err := GetOrgStatistics(ctx, orgId)
	if err != nil {
		log.Printf("[WARNING] Failed getting stats in specific stats for org %s: %s", orgId, err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed getting stats for your org. Maybe not initialized yet?"}`))
		return
	}

	// Default
	statDays := 30
	// Check for if the query parameter exists
	if len(request.URL.Query().Get("days")) > 0 {
		amountQuery := request.URL.Query().Get("days")
		statDays, err = strconv.Atoi(amountQuery)
		if err != nil {
			log.Printf("[WARNING] Failed parsing days query parameter: %s", err)
		} else {
			if statDays > 365 {
				statDays = 365
			}
		}
	}

	log.Printf("[INFO] Should get stats for key %s for the last %d days", statsKey, statDays)

	totalEntires := 0
	totalValue := 0 
	statEntries := []AdditionalUseConfig{}
	info.DailyStatistics = append(info.DailyStatistics, DailyStatistics{
		Date: time.Now(),
		Additions: info.Additions,
	})

	allStats := []string{}
	for _, daily := range info.DailyStatistics {
		// Check if the date is more than statDays ago
		shouldAppend := true
		if daily.Date.Before(time.Now().AddDate(0, 0, -statDays)) {
			shouldAppend = false 
		}

		for _, addition := range daily.Additions {
			newKey := strings.ToLower(strings.ReplaceAll(addition.Key, " ", "_"))
			if shouldAppend && newKey == statsKey {
				totalEntires++
				totalValue += int(addition.Value)

				addition.Key = statsKey
				addition.Date = daily.Date
				statEntries = append(statEntries, addition)
			}

			if !ArrayContains(allStats, newKey) {
				allStats = append(allStats, newKey)
			}
		}
	}

	// Deduplicate and merge same days
	mergedEntries := []AdditionalUseConfig{}
	for _, entry := range statEntries {
		found := false
		for mergedEntryIndex, mergedEntry := range mergedEntries {
			if mergedEntry.Date.Day() == entry.Date.Day() && mergedEntry.Date.Month() == entry.Date.Month() && mergedEntry.Date.Year() == entry.Date.Year() {
				mergedEntries[mergedEntryIndex].Value += entry.Value
				found = true
				break
			}
		}

		if !found {
			mergedEntries = append(mergedEntries, entry)
		}
	}

	statEntries = mergedEntries

	// Check if entries exist for the last X statDays
	// Backfill any missing ones
	if len(statEntries) < statDays {
		// Find the missing days
		missingDays := []time.Time{}
		for i := 0; i < statDays; i++ {
			missingDays = append(missingDays, time.Now().AddDate(0, 0, -i))
		}

		// Find the missing entries
		appended := 0
		foundAmount := 0
		toAppend := []AdditionalUseConfig{}
		for _, missingDay := range missingDays {
			found := false
			for _, entry := range statEntries {
				if entry.Date.Day() == missingDay.Day() && entry.Date.Month() == missingDay.Month() && entry.Date.Year() == missingDay.Year() {
					foundAmount += 1
					found = true
					break
				}
			}

			if !found {
				appended += 1
				toAppend = append(toAppend, AdditionalUseConfig{
					Key:   statsKey,
					Value: 0,
					Date:  missingDay,
				})
			}
		}

		statEntries = append(statEntries, toAppend...)
	}

	// Sort statentries by date
	sort.Slice(statEntries, func(i, j int) bool {
		return statEntries[i].Date.Before(statEntries[j].Date)
	})

	marshalledEntries, err := json.Marshal(statEntries)
	if err != nil {
		log.Printf("[ERROR] Failed marshal in get org stats: %s", err)
		resp.WriteHeader(500)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed unpacking data for org stats"}`)))
		return
	}

	availableStats, err := json.Marshal(allStats)
	if err != nil {
		log.Printf("[ERROR] Failed marshal in get org stats: %s", err)
		resp.WriteHeader(500)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed unpacking data for org stats"}`)))
		return
	}

	successful := totalValue != 0

	resp.WriteHeader(200)
	resp.Write([]byte(fmt.Sprintf(`{"success": %v, "key": "%s", "total": %d, "available_keys": %s, "entries": %s}`, successful, strings.ReplaceAll(statsKey, "\"", ""), totalValue, string(availableStats), string(marshalledEntries))))
}

func HandleGetStatistics(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	var orgId string
	var statsKey string
	location := strings.Split(request.URL.String(), "/")
	if location[1] == "api" {
		// Just falling back 
		if len(location) <= 4 {
		} else {
			orgId = location[4]
		}
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in get stats: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if len(orgId) == 0 {
		orgId = user.ActiveOrg.Id
	}

	ctx := GetContext(request)
	org, err := GetOrg(ctx, orgId)
	if err != nil {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed getting org stats"}`))
		return
	}

	userFound := false
	for _, inneruser := range org.Users {
		if inneruser.Id == user.Id {
			userFound = true

			break
		}
	}

	if user.SupportAccess {
		log.Printf("[AUDIT] User %s (%s) is getting org stats for %s (%s) with support access", user.Username, user.Id, org.Name, orgId)
		userFound = true
	}

	if !userFound {
		log.Printf("[WARNING] User %s isn't a part of org %s (get)", user.Id, org.Id)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "User doesn't have access to org"}`))
		return

	}

	// before we get stats, force dump all increments to db
	// this is just for memcached right now
	memcached := os.Getenv("SHUFFLE_MEMCACHED")
	if len(memcached) > 0 {
		var keys []string

		keysInterface, err := GetCache(ctx, "stat_cache_keys_" + orgId)
		if err != nil {
			
		} else {
			keyBytes, ok := keysInterface.([]byte)
			if !ok {
				log.Printf("[WARNING] Failed converting keyInterface -> keyBytes cache keys for org %s", orgId)
				resp.WriteHeader(401)
				resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed converting keyInterface -> keyBytes cache keys for org %s"}`, orgId)))
				return
			}

			err = json.Unmarshal(keyBytes, &keys)
			if err != nil {
				log.Printf("[WARNING] Failed unmarshaling cache keys for org %s: %s", orgId, err)
				keys = []string{}
			}
		}

		for _, dataType := range PredictableDataTypes {
			key := fmt.Sprintf("cache_%s_%s", orgId, dataType)
			if !ArrayContains(keys, key) {
				// log.Printf("[DEBUG] Adding %s to stats", key)
				keys = append(keys, key)
			} else {
				// log.Printf("[DEBUG] NOT Adding %s to stats because they are apparently in %+v", keys)	
			}
		}

		for _, key := range keys {
			value, err := GetCache(ctx, key)
			if err != nil {
				log.Printf("[WARNING] Failed getting cache value for key %s: %s", key, err)
			} else {
				valueBytes, ok := value.([]byte)
				if !ok {
					log.Printf("[WARNING] Failed converting value -> valueBytes cache value for key %s", key)
					continue
				}

				// Increment the value
				if !(len(valueBytes) > 1) {
					// log.Printf("[WARNING] Invalid value for key %s: %s", key, value)
					continue
				}

				var incrementInCache IncrementInCache
				err = json.Unmarshal(valueBytes, &incrementInCache)
				if err != nil {
					log.Printf("[WARNING] Failed unmarshaling increment in cache for key %s: %s", key, err)
					continue
				}

				if incrementInCache.Amount == 0 {
					// log.Printf("[INFO] No need to dump cache value for key %s", key)
					continue
				}

				// make the value "dataType" everything after the second _
				if len(strings.Split(key, "_")) < 3 {
					log.Printf("[WARNING] Invalid key for cache value: %s", key)
					continue
				}

				dataType := strings.Join(strings.Split(key, "_")[2:], "_")

				err = IncrementCacheDump(ctx, orgId, dataType, int(incrementInCache.Amount))
				if err != nil {
					log.Printf("[WARNING] Failed dumping cache value for key %s: %s and datatype %s", key, err, dataType)
				} else {
					// log.Printf("[INFO] Dumped cache value for key %s and datatypes %s", key, dataType)
					// now, set it back to 0
					// known bug: many times, the cache just deletes
					// rather than becoming 0
					incrementInCache.Amount = 0
					incrementInCache.CreatedAt = time.Now().Unix()

					newjson, err := json.Marshal(incrementInCache)
					if err != nil {
						log.Printf("[ERROR] Failed marshal in get org stats: %s", err)
						resp.WriteHeader(401)
						resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed unpacking data for org stats"}`)))
						return
					}

					err = SetCache(ctx, key, newjson, 86400*30)
					if err != nil {
						log.Printf("[WARNING] Failed setting cache value for key %s: %s", key, err)
						resp.WriteHeader(401)
						resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed setting cache value for key %s"}`, key)))
						return
					}
				}
			}
		}
	}

	info, err := GetOrgStatistics(ctx, orgId)
	if err != nil {
		log.Printf("[WARNING] Failed getting stats for org %s: %s", orgId, err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed getting stats for your org. Maybe not initialized yet?"}`))
		return
	}

	if len(statsKey) > 0  {
		log.Printf("[INFO] Should get stats for key %s", statsKey)
	}

	if len(info.DailyStatistics) > 0 {
		// Sort the array
		sort.Slice(info.DailyStatistics, func(i, j int) bool {
			return info.DailyStatistics[i].Date.Before(info.DailyStatistics[j].Date)
		})

		// Get a max of the last 365 days
		if len(info.DailyStatistics) > 365 {
			info.DailyStatistics = info.DailyStatistics[len(info.DailyStatistics)-60:]
		}
	}

	newjson, err := json.Marshal(info)
	if err != nil {
		log.Printf("[ERROR] Failed marshal in get org stats: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed unpacking data for org stats"}`)))
		return
	}

	resp.WriteHeader(200)
	resp.Write(newjson)
}

func HandleAppendStatistics(resp http.ResponseWriter, request *http.Request) {
	// Send in a thing to increment
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in add stats: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if user.Role == "org-reader" {
		log.Printf("[WARNING] Org-reader doesn't have access to add stats: %s (%s)", user.Username, user.Id)
		resp.WriteHeader(403)
		resp.Write([]byte(`{"success": false, "reason": "Read only user"}`))
		return
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Printf("[WARNING] Failed reading body in add stats: %s", err)
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false, "reason": "Failed reading body"}`))
		return
	}

	inputData := AdditionalUseConfig{}
	err = json.Unmarshal(body, &inputData)
	if err != nil {
		log.Printf("[WARNING] Failed unmarshaling inputdata for add stats: %s", err)
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false, "reason": "Failed unpacking data"}`))
		return
	}

	if len(inputData.Key) < 3 || len(inputData.Key) > 50 {
		log.Printf("[WARNING] Invalid input data for add stats: %s", inputData.Key)
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false, "reason": "'key' has to be a minimum of 3 characters and a maximum of 50"}`))
		return
	}

	if inputData.Value <= 0 {
		inputData.Value = 1
	}

	if inputData.Value > 100 {
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false, "reason": "'value' to increment can be a maximum of 100"}`))
		return
	}

	if !strings.HasPrefix(inputData.Key, "custom_") {
		inputData.Key = fmt.Sprintf("custom_%s", inputData.Key)
	}

	ctx := GetContext(request)
	go IncrementCache(ctx, user.ActiveOrg.Id, inputData.Key, int(inputData.Value))
	resp.WriteHeader(200)
	resp.Write([]byte(fmt.Sprintf(`{"success": true, "reason": "Cache incremented by %d"}`, inputData.Value)))
}
