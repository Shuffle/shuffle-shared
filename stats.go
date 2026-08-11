package shuffle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"encoding/json"
	"io/ioutil"
	"math/rand"
	"net/http"

	gomemcache "github.com/bradfitz/gomemcache/memcache"
	uuid "github.com/satori/go.uuid"
)

// FIXME: There is some issue when going past 0x9 (>0xA) with how
// cache is being counted locally
// var dbInterval = 0x20
var dbInterval = 0x9

// var dbInterval = 0x4
var PredictableDataTypes = []string{
	"app_executions",
	"childorg_app_executions",
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
	"agent_executions",
	"agent_executions_successful",
	"agent_executions_failed",
	"agent_tokens",
	"agent_input_tokens",
	"agent_output_tokens",
	"agent_cached_tokens",
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

	if debug {
		log.Printf("[DEBUG] Should get stats for key %s for the last %d days", statsKey, statDays)
	}

	totalEntires := 0
	totalValue := 0
	statEntries := []AdditionalUseConfig{}
	info.DailyStatistics = append(info.DailyStatistics, DailyStatistics{
		Date:      time.Now(),
		Additions: info.Additions,
	})

	allStats := []string{}

	getTypedValue := func(d DailyStatistics, key string) int64 {
		switch key {
		case "app_executions":
			return d.AppExecutions
		case "childorg_app_executions":
			return d.ChildAppExecutions
		case "app_executions_failed":
			return d.AppExecutionsFailed
		case "subflow_executions":
			return d.SubflowExecutions
		case "workflow_executions":
			return d.WorkflowExecutions
		case "workflow_executions_finished":
			return d.WorkflowExecutionsFinished
		case "workflow_executions_failed":
			return d.WorkflowExecutionsFailed
		case "org_sync_actions":
			return d.OrgSyncActions
		case "workflow_executions_cloud":
			return d.CloudExecutions
		case "workflow_executions_onprem":
			return d.OnpremExecutions
		case "api_usage":
			return d.ApiUsage
		case "ai_executions":
			return d.AIUsage
		case "agent_executions":
			return d.AgentExecutions
		case "agent_executions_successful":
			return d.AgentExecutionsSuccessful
		case "agent_executions_failed":
			return d.AgentExecutionsFailed
		case "agent_tokens":
			return d.AgentTokens
		case "agent_input_tokens":
			return d.AgentInputTokens
		case "agent_output_tokens":
			return d.AgentOutputTokens
		case "agent_cached_tokens":
			return d.AgentCachedTokens
		default:
			return -1
		}
	}

	isPredictable := ArrayContains(PredictableDataTypes, statsKey)

	for _, daily := range info.DailyStatistics {
		// Check if the date is more than statDays ago
		shouldAppend := true
		if daily.Date.Before(time.Now().AddDate(0, 0, -statDays)) {
			shouldAppend = false
		}

		if isPredictable {
			if shouldAppend {
				value := getTypedValue(daily, statsKey)
				if value >= 0 {
					totalEntires++
					totalValue += int(value)
					statEntries = append(statEntries, AdditionalUseConfig{
						Key:   statsKey,
						Value: value,
						Date:  daily.Date,
					})
				}
			}

			// Track available keys too
			for _, k := range PredictableDataTypes {
				if !ArrayContains(allStats, k) {
					allStats = append(allStats, k)
				}
			}
			continue
		}

		// Custom additions path (original behavior)
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

	// If predictable key, also include today's in-memory daily counters (not yet rolled into DailyStatistics)
	if isPredictable {
		today := time.Now()
		var todayValue int64 = 0
		switch statsKey {
		case "app_executions":
			todayValue = info.DailyAppExecutions
		case "childorg_app_executions":
			todayValue = info.DailyChildAppExecutions
		case "app_executions_failed":
			todayValue = info.DailyAppExecutionsFailed
		case "subflow_executions":
			todayValue = info.DailySubflowExecutions
		case "workflow_executions":
			todayValue = info.DailyWorkflowExecutions
		case "workflow_executions_finished":
			todayValue = info.DailyWorkflowExecutionsFinished
		case "workflow_executions_failed":
			todayValue = info.DailyWorkflowExecutionsFailed
		case "org_sync_actions":
			todayValue = info.DailyOrgSyncActions
		case "workflow_executions_cloud":
			todayValue = info.DailyCloudExecutions
		case "workflow_executions_onprem":
			todayValue = info.DailyOnpremExecutions
		case "api_usage":
			todayValue = info.DailyApiUsage
		case "ai_executions":
			todayValue = info.DailyAIUsage
		}

		// Only append if within window
		if !today.Before(time.Now().AddDate(0, 0, -statDays)) {
			statEntries = append(statEntries, AdditionalUseConfig{
				Key:   statsKey,
				Value: todayValue,
				Date:  today,
			})
			totalEntires++
			totalValue += int(todayValue)
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
	// Backfill any missing ones so that the number is correct
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

	// Append cache for right now as it may not be in the DB yet
	for statEntryIndex, statEntry := range statEntries {
		if statEntry.Date.Day() == time.Now().Day() && statEntry.Date.Month() == time.Now().Month() && statEntry.Date.Year() == time.Now().Year() {
			for _, addition := range info.Additions {
				if addition.Key != statsKey {
					continue
				}

				key := fmt.Sprintf("cache_%s_%s", orgId, addition.Key)
				cacheItem, err := GetCache(ctx, key)
				if err == nil {
					parsedItem := []byte(cacheItem.([]uint8))
					increment, err := strconv.Atoi(string(parsedItem))
					if err == nil {
						statEntries[statEntryIndex].Value += int64(increment)
						totalValue += int(increment)
					}
				}

				break
			}
		}
	}

	// Sort statentries by date
	sort.Slice(statEntries, func(i, j int) bool {
		return statEntries[i].Date.Before(statEntries[j].Date)
	})

	// For debugging stats that don't show up by injecting them
	/*
		if debug && totalValue == 0 {
			log.Printf("[DEBUG] Found %d entries for '%s' with 0 in data. Force-adding data to first entry.", len(statEntries), statsKey)
			chosenIndex := rand.Intn(len(statEntries))
			statEntries[chosenIndex].Value = int64(rand.Intn(10) + 1)
		}
	*/

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

	//successful := totalValue != 0
	successful := true

	resp.WriteHeader(200)
	resp.Write([]byte(fmt.Sprintf(`{"success": %v, "key": "%s", "total": %d, "available_keys": %s, "entries": %s}`, successful, strings.ReplaceAll(statsKey, "\"", ""), totalValue, string(availableStats), string(marshalledEntries))))
}

func mergeMultiRegionResults(crossRegionResults []MultiRegionStatsEntry, info *ExecutionInfo, parentDailyMap map[string]int) {
	log.Printf("[INFO] HandleGetStatistics: received cross-region stats for %d child orgs from multi-region-stats endpoint", len(crossRegionResults))

	for _, entry := range crossRegionResults {
		for _, childDay := range entry.DailyStatistics {
			dateKey := childDay.Date.UTC().Format("2006-01-02")
			alreadyAppliedCorrection := childDay.AgentInputTokens*250/1_000_000 +
				childDay.AgentOutputTokens*1500/1_000_000 +
				childDay.DailySMSUsage*3 +
				childDay.DailyEmailUsage*2
			rawChildAppExecutions := childDay.AppExecutions - alreadyAppliedCorrection
			if rawChildAppExecutions < 0 {
				rawChildAppExecutions = 0
			}

			if idx, exists := parentDailyMap[dateKey]; exists {
				info.DailyStatistics[idx].ChildAppExecutions += rawChildAppExecutions
				info.DailyStatistics[idx].DailyChildOrgAiUsage += childDay.AIUsage
				info.DailyStatistics[idx].DailyChildOrgAgentExecutions += childDay.AgentExecutions
				info.DailyStatistics[idx].DailyChildOrgAgentTokens += childDay.AgentTokens
				info.DailyStatistics[idx].DailyChildOrgAgentInputTokens += childDay.AgentInputTokens
				info.DailyStatistics[idx].DailyChildOrgAgentOutputTokens += childDay.AgentOutputTokens
				info.DailyStatistics[idx].DailyChildOrgSMSUsage += childDay.DailySMSUsage
				info.DailyStatistics[idx].DailyChildOrgEmailUsage += childDay.DailyEmailUsage
			} else {
				// No matching parent day — create a new entry carrying only the child org counters
				newDay := DailyStatistics{
					Date:                           childDay.Date,
					ChildAppExecutions:             rawChildAppExecutions,
					DailyChildOrgAiUsage:           childDay.AIUsage,
					DailyChildOrgAgentExecutions:   childDay.AgentExecutions,
					DailyChildOrgAgentTokens:       childDay.AgentTokens,
					DailyChildOrgAgentInputTokens:  childDay.AgentInputTokens,
					DailyChildOrgAgentOutputTokens: childDay.AgentOutputTokens,
					DailyChildOrgSMSUsage:          childDay.DailySMSUsage,
					DailyChildOrgEmailUsage:        childDay.DailyEmailUsage,
				}
				parentDailyMap[dateKey] = len(info.DailyStatistics)
				info.DailyStatistics = append(info.DailyStatistics, newDay)
			}
		}
	}
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

	org := &Org{}
	ctx := GetContext(request)
	if orgId == "public" {
		if user.SupportAccess {
			log.Printf("[AUDIT] User %s (%s) is getting org stats for PUBLIC org %s with support access", user.Username, user.Id, orgId)
		}

	} else {
		org, err = GetOrg(ctx, orgId)
		if err != nil {
			resp.WriteHeader(403)
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
			resp.WriteHeader(403)
			resp.Write([]byte(`{"success": false, "reason": "User doesn't have access to org"}`))
			return

		}
	}

	// FIXME: Removed the current stats grabber as it made no sense
	// to dump it to cache. The point was JUST to grab it in realtime.
	info, err := GetOrgStatistics(ctx, orgId)
	if err != nil {
		log.Printf("[WARNING] Failed getting stats for org %s: %s", orgId, err)
		//resp.WriteHeader(400)
		//resp.Write([]byte(`{"success": false, "reason": "Failed getting stats for your org. Maybe not initialized yet?"}`))
		//return
		info.OrgId = orgId
		info.OrgName = org.Name
	}

	// Sideload GCS overflow stats (entries >60 days old archived from Datastore), cached 30 min.
	if project.Environment == "cloud" && len(orgFileBucket) > 0 {
		var gcsStats []DailyStatistics
		gcsCacheKey := fmt.Sprintf("gcs_stats_%s", orgId)

		if cached, cacheErr := GetCache(ctx, gcsCacheKey); cacheErr == nil {
			_ = json.Unmarshal([]byte(cached.([]uint8)), &gcsStats)
		} else {
			bucketPath := fmt.Sprintf("org_statistics/%s/stats.json", orgId)
			obj := project.StorageClient.Bucket(orgFileBucket).Object(bucketPath)
			if gcsReader, gcsErr := obj.NewReader(ctx); gcsErr == nil {
				gcsBytes, readErr := ioutil.ReadAll(gcsReader)
				gcsReader.Close()
				if readErr == nil && len(gcsBytes) > 0 {
					if unmarshalErr := json.Unmarshal(gcsBytes, &gcsStats); unmarshalErr == nil {
						_ = SetCache(ctx, gcsCacheKey, gcsBytes, 30)
					}
				}
			}
		}

		if len(gcsStats) > 0 {
			log.Printf("[DEBUG] HandleGetStatistics: merging %d GCS overflow entries for org %s", len(gcsStats), orgId)
			// Deduplicate by date; Datastore entries win on conflict.
			dateMapCap := len(gcsStats)
			if len(info.DailyStatistics) > dateMapCap {
				dateMapCap = len(info.DailyStatistics)
			}
			dateMap := make(map[string]DailyStatistics, dateMapCap)
			for _, d := range gcsStats {
				dateMap[d.Date.UTC().Format("2006-01-02")] = d
			}
			for _, d := range info.DailyStatistics {
				dateMap[d.Date.UTC().Format("2006-01-02")] = d
			}
			merged := make([]DailyStatistics, 0, len(dateMap))
			for _, d := range dateMap {
				merged = append(merged, d)
			}
			info.DailyStatistics = merged
		}
	}

	// Sideload app runs, workflow runs and subflow runs (just in case)
	// This makes numbers accurate even when less than  dbDumpInterval
	key := fmt.Sprintf("cache_%s_app_executions", orgId)
	cacheItem, err := GetCache(ctx, key)
	if err == nil {
		parsedItem := []byte(cacheItem.([]uint8))
		increment, err := strconv.Atoi(string(parsedItem))
		if err == nil {
			info.TotalAppExecutions += int64(increment)
			info.MonthlyAppExecutions += int64(increment)
			info.WeeklyAppExecutions += int64(increment)
			info.DailyAppExecutions += int64(increment)
			info.HourlyAppExecutions += int64(increment)
		}
	}

	key = fmt.Sprintf("cache_%s_childorg_app_executions", orgId)
	cacheItem, err = GetCache(ctx, key)
	if err == nil {
		parsedItem := []byte(cacheItem.([]uint8))
		increment, err := strconv.Atoi(string(parsedItem))
		if err == nil {
			info.TotalChildAppExecutions += int64(increment)
			info.MonthlyChildAppExecutions += int64(increment)
			info.WeeklyChildAppExecutions += int64(increment)
			info.DailyChildAppExecutions += int64(increment)
			info.HourlyChildAppExecutions += int64(increment)
		}
	}

	key = fmt.Sprintf("cache_%s_workflow_executions", orgId)
	cacheItem, err = GetCache(ctx, key)
	if err == nil {
		parsedItem := []byte(cacheItem.([]uint8))
		increment, err := strconv.Atoi(string(parsedItem))
		if err == nil {
			info.TotalWorkflowExecutions += int64(increment)
			info.MonthlyWorkflowExecutions += int64(increment)
			info.WeeklyWorkflowExecutions += int64(increment)
			info.DailyWorkflowExecutions += int64(increment)
			info.HourlyWorkflowExecutions += int64(increment)
		}
	}

	key = fmt.Sprintf("cache_%s_subflow_executions", orgId)
	cacheItem, err = GetCache(ctx, key)
	if err == nil {
		parsedItem := []byte(cacheItem.([]uint8))
		increment, err := strconv.Atoi(string(parsedItem))
		if err == nil {
			info.TotalSubflowExecutions += int64(increment)
			info.MonthlySubflowExecutions += int64(increment)
			info.WeeklySubflowExecutions += int64(increment)
			info.DailySubflowExecutions += int64(increment)
			info.HourlySubflowExecutions += int64(increment)
		}
	}

	key = fmt.Sprintf("cache_%s_send_mail", orgId)
	cacheItem, err = GetCache(ctx, key)
	if err == nil {
		parsedItem := []byte(cacheItem.([]uint8))
		increment, err := strconv.Atoi(string(parsedItem))
		if err == nil {
			info.TotalEmailUsage += int64(increment)
			info.MonthlyEmailUsage += int64(increment)
			info.DailyEmailUsage += int64(increment)
		}
	}

	key = fmt.Sprintf("cache_%s_childorg_send_mail", orgId)
	cacheItem, err = GetCache(ctx, key)
	if err == nil {
		parsedItem := []byte(cacheItem.([]uint8))
		increment, err := strconv.Atoi(string(parsedItem))
		if err == nil {
			info.TotalChildOrgEmailUsage += int64(increment)
			info.MonthlyChildOrgEmailUsage += int64(increment)
			info.DailyChildOrgEmailUsage += int64(increment)
		}
	}

	key = fmt.Sprintf("cache_%s_send_sms", orgId)
	cacheItem, err = GetCache(ctx, key)
	if err == nil {
		parsedItem := []byte(cacheItem.([]uint8))
		increment, err := strconv.Atoi(string(parsedItem))
		if err == nil {
			info.TotalSMSUsage += int64(increment)
			info.MonthlySMSUsage += int64(increment)
			info.DailySMSUsage += int64(increment)
		}
	}

	key = fmt.Sprintf("cache_%s_childorg_send_sms", orgId)
	cacheItem, err = GetCache(ctx, key)
	if err == nil {
		parsedItem := []byte(cacheItem.([]uint8))
		increment, err := strconv.Atoi(string(parsedItem))
		if err == nil {
			info.TotalChildOrgSMSUsage += int64(increment)
			info.MonthlyChildOrgSMSUsage += int64(increment)
			info.DailyChildOrgSMSUsage += int64(increment)
		}
	}

	for additionCnt, addition := range info.Additions {

		key := fmt.Sprintf("cache_%s_%s", orgId, addition.Key)
		cacheItem, err = GetCache(ctx, key)
		if err == nil {
			parsedItem := []byte(cacheItem.([]uint8))
			increment, err := strconv.Atoi(string(parsedItem))
			if err == nil {
				info.Additions[additionCnt].Value += int64(increment)
			}
		}

		// In case a lot of use
		if additionCnt > 10 {
			break
		}
	}

	_ = statsKey
	//if len(statsKey) > 0 {
	//	log.Printf("[INFO] Should get stats for key %s", statsKey)
	//}

	if len(info.DailyStatistics) > 0 {
		// Sort the array
		sort.Slice(info.DailyStatistics, func(i, j int) bool {
			return info.DailyStatistics[i].Date.Before(info.DailyStatistics[j].Date)
		})

		// Get a max of the last 365 days
		if len(info.DailyStatistics) > 365 {
			info.DailyStatistics = info.DailyStatistics[len(info.DailyStatistics)-365:]
		}
	}

	parentOrgLocations := []Locations{}
	parentEnvs, err := GetEnvironments(ctx, org.Id)
	if err == nil {
		for _, env := range parentEnvs {
			if strings.ToLower(env.Name) == "cloud" {
				continue
			}
			status := "active"
			if env.Archived {
				status = "disabled"
			}
			parentOrgLocations = append(parentOrgLocations, Locations{
				OrgId:     org.Id,
				OrgName:   org.Name,
				Name:      env.Name,
				Id:        env.Id,
				CreatedAt: time.Unix(env.Created, 0).Format(time.RFC3339),
				Status:    status,
			})
		}
	}

	if len(parentOrgLocations) > 0 {
		info.Locations = append(parentOrgLocations, info.Locations...)
	}

	skipMultiRegion := false
	if skipList, ok := request.URL.Query()["skip_multi_region"]; ok && len(skipList) > 0 && skipList[0] == "true" {
		skipMultiRegion = true
	}

	if len(org.CreatorOrg) > 0 {
		skipMultiRegion = true
	}

	if len(org.ChildOrgs) > 0 && !skipMultiRegion {
		// Build a date-keyed map of parent daily stats for fast lookups when merging cross-region child data
		parentDailyMap := make(map[string]int, len(info.DailyStatistics))
		for i, d := range info.DailyStatistics {
			parentDailyMap[d.Date.UTC().Format("2006-01-02")] = i
		}

		// mu protects all shared writes: info.Tenants, info.Locations, info.DailyStatistics, parentDailyMap
		var mu sync.Mutex
		var wg sync.WaitGroup

		// Semaphore: buffered channel of size 5 limits concurrent goroutines to 5 at a time
		sem := make(chan struct{}, 5)

		parentRegionUrl := strings.TrimRight(org.RegionUrl, "/")
		hasCrossRegionChildren := false

		for _, childOrgMini := range org.ChildOrgs {
			wg.Add(1)
			sem <- struct{}{} // acquire a slot; blocks if 5 goroutines are already running

			go func(childOrgMini OrgMini) {
				defer wg.Done()
				defer func() { <-sem }() // release the slot when this goroutine finishes

				childOrgFull, err := GetOrg(ctx, childOrgMini.Id)
				if err != nil {
					log.Printf("[WARNING] HandleGetStatistics: failed fetching child org %s: %s", childOrgMini.Id, err)
					return
				}

				// --- Collect Tenant and Location data (write behind mutex) ---
				newTenant := Tenants{
					Name:      childOrgFull.Name,
					Id:        childOrgFull.Id,
					CreatedAt: time.Unix(childOrgFull.Created, 0),
					Status:    "active",
				}

				var newLocs []Locations
				childEnvs, err := GetEnvironments(ctx, childOrgFull.Id)
				if err == nil {
					for _, env := range childEnvs {
						if len(env.SuborgDistribution) > 0 {
							continue
						}
						if strings.ToLower(env.Name) == "cloud" {
							continue
						}
						status := "active"
						if env.Archived {
							status = "disabled"
						}
						newLocs = append(newLocs, Locations{
							OrgId:     childOrgFull.Id,
							OrgName:   childOrgFull.Name,
							Name:      env.Name,
							Id:        env.Id,
							CreatedAt: time.Unix(env.Created, 0).Format(time.RFC3339),
							Status:    status,
						})
					}
				}

				childRegionUrl := strings.TrimRight(childOrgFull.RegionUrl, "/")
				if project.Environment == "cloud" &&
					len(childRegionUrl) > 0 &&
					strings.Contains(childRegionUrl, "http") &&
					childRegionUrl != parentRegionUrl {
					mu.Lock()
					hasCrossRegionChildren = true
					info.Tenants = append(info.Tenants, newTenant)
					info.Locations = append(info.Locations, newLocs...)
					mu.Unlock()
					return
				}

				mu.Lock()
				info.Tenants = append(info.Tenants, newTenant)
				info.Locations = append(info.Locations, newLocs...)
				mu.Unlock()
			}(childOrgMini)
		}

		wg.Wait()

		if project.Environment == "cloud" && hasCrossRegionChildren && !skipMultiRegion {
			multiRegionCacheKey := fmt.Sprintf("multi_region_stats_%s", org.Id)

			if cachedBody, cacheErr := GetCache(ctx, multiRegionCacheKey); cacheErr == nil {
				cachedBytes := []byte(cachedBody.([]uint8))
				var cachedResults []MultiRegionStatsEntry
				if jsonErr := json.Unmarshal(cachedBytes, &cachedResults); jsonErr == nil {
					log.Printf("[INFO] HandleGetStatistics: serving multi-region stats from cache for org %s", orgId)
					mergeMultiRegionResults(cachedResults, info, parentDailyMap)
				} else {
					log.Printf("[WARNING] HandleGetStatistics: failed unmarshalling cached multi-region-stats, will refetch: %s", jsonErr)
				}
			} else {
				multiRegionUrl := fmt.Sprintf("https://shuffler.io/api/v1/orgs/%s/multi-region-stats", orgId)
				multiReq, multiErr := http.NewRequest("GET", multiRegionUrl, nil)
				if multiErr != nil {
					log.Printf("[WARNING] HandleGetStatistics: failed building multi-region-stats request: %s", multiErr)
				} else {
					multiReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", user.ApiKey))
					multiReq.Header.Set("Org-Id", orgId)

					multiClient := &http.Client{Timeout: 60 * time.Second}
					multiResp, multiDoErr := multiClient.Do(multiReq)
					if multiDoErr != nil {
						log.Printf("[WARNING] HandleGetStatistics: multi-region-stats request failed: %s", multiDoErr)
					} else {
						defer multiResp.Body.Close()
						if multiResp.StatusCode == 200 {
							multiBody, multiReadErr := ioutil.ReadAll(multiResp.Body)
							if multiReadErr != nil {
								log.Printf("[WARNING] HandleGetStatistics: failed reading multi-region-stats body: %s", multiReadErr)
							} else {
								var crossRegionResults []MultiRegionStatsEntry
								if jsonErr := json.Unmarshal(multiBody, &crossRegionResults); jsonErr != nil {
									log.Printf("[WARNING] HandleGetStatistics: failed unmarshalling multi-region-stats: %s", jsonErr)
								} else {
									// Store raw response bytes in cache for 1 hour (3600 seconds)
									_ = SetCache(ctx, multiRegionCacheKey, multiBody, 3600)
									mergeMultiRegionResults(crossRegionResults, info, parentDailyMap)
								}
							}
						} else {
							log.Printf("[WARNING] HandleGetStatistics: multi-region-stats returned status %d", multiResp.StatusCode)
						}
					}
				}
			}
		}
	}

	if org.SyncFeatures.AnnualAppRunsGrouping.Active {
		var startDate, endDate time.Time
		annualSubscriptionExists := false
		for _, subscription := range org.Subscriptions {
			if (strings.Contains(strings.ToLower(subscription.Name), "business") || strings.Contains(strings.ToLower(subscription.Name), "enterprise")) && (strings.Contains(strings.ToLower(subscription.Recurrence), "annual")) && subscription.Active {
				annualSubscriptionExists = true
				startDate = time.Unix(subscription.Startdate, 0)
				endDate = time.Unix(subscription.Enddate, 0)
				break
			}
		}

		if annualSubscriptionExists && len(info.DailyStatistics) > 0 {

			annualSubscriptionAppRuns := int64(0)
			annualSubscriptionChildAppRuns := int64(0)
			for i := range info.DailyStatistics {
				if info.DailyStatistics[i].Date.Unix() >= startDate.Unix() && info.DailyStatistics[i].Date.Unix() <= endDate.Unix() {
					annualSubscriptionAppRuns += info.DailyStatistics[i].AppExecutions
					annualSubscriptionChildAppRuns += info.DailyStatistics[i].ChildAppExecutions
				}
			}
			info.AnnualAppExecutions = annualSubscriptionAppRuns
			info.AnnualChildAppExecutions = annualSubscriptionChildAppRuns
		}
	}

	stats := GetCorrectedStats(info)

	newjson, err := json.Marshal(stats)
	if err != nil {
		log.Printf("[ERROR] Failed marshal in get org stats: %s", err)
		resp.WriteHeader(500)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed unpacking data for org stats"}`)))
		return
	}

	resp.WriteHeader(200)
	resp.Write(newjson)
}

// Make sure that we are not calling SetOrgStatistics function after calling this function. This will increase the app runs count in db on every call to this function.
func GetCorrectedStats(info *ExecutionInfo) *ExecutionInfo {

	// 1 Million Input Tokens = 250 app runs
	// 1 Million Output Tokens = 1500 app runs
	// 1 SMS = 3 app runs
	// 1 Email = 2 app runs

	// Loop through the daily statistics and add the app runs from tokens, SMS and email on top of existing counts
	for i := range info.DailyStatistics {
		info.DailyStatistics[i].AppExecutions += info.DailyStatistics[i].AgentInputTokens*250/1_000_000 + info.DailyStatistics[i].AgentOutputTokens*1500/1_000_000 + info.DailyStatistics[i].DailySMSUsage*3 + info.DailyStatistics[i].DailyEmailUsage*2
		info.DailyStatistics[i].ChildAppExecutions += info.DailyStatistics[i].ChildOrgAgentInputTokens*250/1_000_000 + info.DailyStatistics[i].ChildOrgAgentOutputTokens*1500/1_000_000 + info.DailyStatistics[i].DailyChildOrgSMSUsage*3 + info.DailyStatistics[i].DailyChildOrgEmailUsage*2
	}

	// Add the monthly app runs from SMS, Email, Input Tokens and Output Tokens on top of existing counts
	info.MonthlyAppExecutions += info.MonthlySMSUsage*3 + info.MonthlyEmailUsage*2 + info.MonthlyAgentInputTokens*250/1_000_000 + info.MonthlyAgentOutputTokens*1500/1_000_000
	info.MonthlyChildAppExecutions += info.MonthlyChildOrgSMSUsage*3 + info.MonthlyChildOrgEmailUsage*2 + info.MonthlyChildOrgAgentInputTokens*250/1_000_000 + info.MonthlyChildOrgAgentOutputTokens*1500/1_000_000

	info.DailyAppExecutions += info.DailyAgentInputTokens*250/1_000_000 + info.DailyAgentOutputTokens*1500/1_000_000 + info.DailySMSUsage*3 + info.DailyEmailUsage*2
	info.DailyChildAppExecutions += info.DailyChildOrgAgentInputTokens*250/1_000_000 + info.DailyChildOrgAgentOutputTokens*1500/1_000_000 + info.DailyChildOrgSMSUsage*3 + info.DailyChildOrgEmailUsage*2

	info.TotalAppExecutions += info.TotalAgentInputTokens*250/1_000_000 + info.TotalAgentOutputTokens*1500/1_000_000 + info.TotalSMSUsage*3 + info.TotalEmailUsage*2
	info.TotalChildAppExecutions += info.TotalChildOrgAgentInputTokens*250/1_000_000 + info.TotalChildOrgAgentOutputTokens*1500/1_000_000 + info.TotalChildOrgSMSUsage*3 + info.TotalChildOrgEmailUsage*2

	if len(info.DailyStatistics) > 0 {
		annualInputTokens := int64(0)
		annualChildInputTokens := int64(0)
		annualOutputTokens := int64(0)
		annualChildOutputTokens := int64(0)
		annualSMSUsage := int64(0)
		annualChildSMSUsage := int64(0)
		annualEmailUsage := int64(0)
		annualChildEmailUsage := int64(0)
		for i := range info.DailyStatistics {
			annualInputTokens += info.DailyStatistics[i].AgentInputTokens
			annualChildInputTokens += info.DailyStatistics[i].ChildOrgAgentInputTokens
			annualOutputTokens += info.DailyStatistics[i].AgentOutputTokens
			annualChildOutputTokens += info.DailyStatistics[i].ChildOrgAgentOutputTokens
			annualSMSUsage += info.DailyStatistics[i].DailySMSUsage
			annualChildSMSUsage += info.DailyStatistics[i].DailyChildOrgSMSUsage
			annualEmailUsage += info.DailyStatistics[i].DailyEmailUsage
			annualChildEmailUsage += info.DailyStatistics[i].DailyChildOrgEmailUsage
		}
		info.AnnualAppExecutions += annualInputTokens*250/1_000_000 + annualOutputTokens*1500/1_000_000 + annualSMSUsage*3 + annualEmailUsage*2
		info.AnnualChildAppExecutions += annualChildInputTokens*250/1_000_000 + annualChildOutputTokens*1500/1_000_000 + annualChildSMSUsage*3 + annualChildEmailUsage*2
	}

	return info
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

// Rudementary caching system. WILL go wrong at times without sharding.
// It's only good for the user in cloud, hence wont bother for a while
// Optional input is the amount to increment
func IncrementCache(ctx context.Context, orgId, dataType string, amount ...int) {
	// Check if environment is worker and skip
	if project.Environment == "worker" {
		//log.Printf("[DEBUG] Skipping cache increment for worker with datatype %s", dataType)
		return
	}

	if len(orgId) != 36 && orgId != "public" && orgId != "INTERNAL" {
		log.Printf("[ERROR] Increment Stats with bad OrgId '%s' for type '%s'", orgId, dataType)
		return
	}

	dataType = strings.ToLower(strings.Replace(dataType, " ", "_", -1))
	incrementAmount := 1
	if len(amount) > 0 {
		if amount[0] > 0 {
			incrementAmount = amount[0]
		}
	}

	// Dump to disk every 0x19
	// 1. Get the existing value
	// 2. Update it
	dbDumpInterval := uint8(dbInterval)
	key := fmt.Sprintf("cache_%s_%s", orgId, dataType)
	if len(memcached) > 0 {
		appendForQuickDump := false
		if !ArrayContains(PredictableDataTypes, dataType) {
			appendForQuickDump = true
		}

		if appendForQuickDump {
			// check if the cache already key is indexed in memcache
			keyItems, err := mc.Get("stat_cache_keys_" + orgId)
			if err == gomemcache.ErrCacheMiss {
				keyItem := []string{key}
				data, err := json.Marshal(keyItem)
				if err != nil {
					log.Printf("[ERROR] Failed marshalling increment item for cache: %s", err)
				} else {
					// dump it to memcache
					item := &gomemcache.Item{
						Key:        "stat_cache_keys_" + orgId,
						Value:      data,
						Expiration: 86400 * 30,
					}

					if err := mc.Set(item); err != nil {
						log.Printf("[ERROR] Failed setting increment cache for key %s: %s", orgId, err)
					} else {
						// log.Printf("[DEBUG] Set cache index key for (1) %s", orgId)
					}
				}
			} else if err != nil {
				log.Printf("[ERROR] Failed getting increment cache for key %s: %s", orgId, err)
			} else {
				dumpedItems := []string{}
				err = json.Unmarshal(keyItems.Value, &dumpedItems)
				if err != nil {
					log.Printf("[ERROR] Failed unmarshalling item in cache: %s", err)
				} else {
					if !ArrayContains(dumpedItems, key) {
						dumpedItems = append(dumpedItems, key)
						data, err := json.Marshal(dumpedItems)
						if err != nil {
							log.Printf("[ERROR] Failed marshalling increment item for cache: %s", err)
						} else {
							// dump it to memcache
							item := &gomemcache.Item{
								Key:        "stat_cache_keys_" + orgId,
								Value:      data,
								Expiration: 86400 * 30,
							}

							if err := mc.Set(item); err != nil {
								log.Printf("[ERROR] Failed setting increment cache for key %s: %s", orgId, err)
							} else {
								// log.Printf("[DEBUG] Set cache index key for (1) %s", orgId)
							}
						}
					}
				}
			}
		}

		item, err := mc.Get(key)
		if err == gomemcache.ErrCacheMiss {
			incrementItem := IncrementInCache{
				Amount:    uint64(incrementAmount),
				CreatedAt: time.Now().Unix(),
			}

			data, err := json.Marshal(incrementItem)
			if err != nil {
				log.Printf("[ERROR] Failed marshalling increment item for cache: %s", err)
				return
			}

			item := &gomemcache.Item{
				Key:        key,
				Value:      data,
				Expiration: 86400 * 30,
			}

			if err := mc.Set(item); err != nil {
				log.Printf("[ERROR] Failed setting increment cache for key %s: %s", orgId, err)
			}

		} else if err != nil {
			log.Printf("[ERROR] Failed increment memcache err: %s", err)
		} else {
			if item == nil || item.Value == nil {
				incrementItem := IncrementInCache{
					Amount:    uint64(incrementAmount),
					CreatedAt: time.Now().Unix(),
				}

				data, err := json.Marshal(incrementItem)
				if err != nil {
					log.Printf("[DEBUG] Failed marshalling increment item for cache: %s", err)
					return
				}

				item = &gomemcache.Item{
					Key:        key,
					Value:      data,
					Expiration: 86400 * 30,
				}

				// log.Printf("[ERROR] Value in DB is nil for cache %s.", dataType)
			}

			if len(item.Value) == 1 {
				// case to use if the cache that was present before
				// the new changes that introduced the struct to the increment system.
				// log.Printf("[DEBUG] This is from the older system. num: %+v", item.Value)

				// num := uint64(item.Value[0])
				// num += uint64(incrementAmount)

				// log.Printf("[DEBUG] new num: %d", num)

				// there is some bug here. i would much rather lose the data here.
				num := uint64(incrementAmount)

				incrementItem := IncrementInCache{
					Amount:    num,
					CreatedAt: time.Now().Unix(),
				}

				data, err := json.Marshal(incrementItem)
				if err != nil {
					log.Printf("[ERROR] Failed marshalling increment item for cache: %s", err)
					return
				}

				item := &gomemcache.Item{
					Key:        key,
					Value:      data,
					Expiration: 86400 * 30,
				}

				if err := mc.Set(item); err != nil {
					log.Printf("[ERROR] Failed setting increment cache for key %s: %s", orgId, err)
					return
				}
			} else if len(item.Value) > 0 {
				var incrementedItemInCache IncrementInCache

				err := json.Unmarshal(item.Value, &incrementedItemInCache)
				if err != nil {
					log.Printf("[ERROR] Failed unmarshalling item in cache: %s", err)
					return
				}

				num := incrementedItemInCache.Amount
				// num += byte(incrementAmount)
				num += uint64(incrementAmount)
				//num += []byte{2}

				incrementedItemInCache.Amount = num

				// log.Printf("[DEBUG] time.Now().Unix() (%d) - incrementedItemInCache.CreatedAt (%d) = %d", time.Now().Unix(), incrementedItemInCache.CreatedAt, time.Now().Unix()-incrementedItemInCache.CreatedAt)

				// if num >= dbDumpInterval {
				// if the cache was created more than a day ago

				// make it a random number between
				// (10-60 seconds)
				randomSeconds := (rand.Intn(50) + 10) * 5 // to make the number longer

				if time.Now().Unix()-incrementedItemInCache.CreatedAt > int64(randomSeconds) && incrementedItemInCache.Amount > uint64(dbInterval) {
					// Memcache dump first to keep the counter going for other executions
					oldNum := num
					num = 0

					incrementedItemInCache.Amount = num
					incrementedItemInCache.CreatedAt = time.Now().Unix()

					// log.Printf("[DEBUG] Dumping cache item with key %s which was created at %s is was %d", key, incrementedItemInCache.CreatedAt, oldNum)

					data, err := json.Marshal(incrementedItemInCache)
					if err != nil {
						log.Printf("[ERROR] Failed marshalling increment item for cache: %s", err)
						return
					}

					// an issue here is that it isn't necessary that num is dbDumpInterval
					err = IncrementCacheDump(ctx, orgId, dataType, int(oldNum))
					if err != nil {
						log.Printf("[ERROR] Failed dumping cache for key (1) %s: %s", key, err)
						if strings.Contains(fmt.Sprintf("%s", err), "concurrent transaction") {
							// log.Printf("[ERROR] Concurrent transaction in cache dump: %s. Storing in cache (%s) instead with new amount: %d", err, key, oldNum)
							incrementedItemInCache.Amount = oldNum

							data, err := json.Marshal(incrementedItemInCache)
							if err != nil {
								log.Printf("[ERROR] Failed marshalling increment item for cache: %s", err)
							}

							item := &gomemcache.Item{
								Key:        key,
								Value:      data,
								Expiration: 86400 * 30,
							}

							if err := mc.Set(item); err != nil {
								log.Printf("[ERROR] Failed setting inner memcache for key %s: %s", orgId, err)
							}
						} else {
							log.Printf("[ERROR] Failed dumping cache for key %s: %s", key, err)
						}
					} else {
						item := &gomemcache.Item{
							Key:        key,
							Value:      data,
							Expiration: 86400 * 30,
						}
						if err := mc.Set(item); err != nil {
							log.Printf("[ERROR] Failed setting inner memcache for key %s: %s", orgId, err)
						}
					}

				} else {
					//log.Printf("NOT Dumping!")
					// this case got apparently overwritten unnecessarily 3 times out of 20.
					// data gets more lost here due to cache overwrites.

					// add a random sleep of a few miliseconds here
					randomSleep := rand.Intn(50) + 10
					time.Sleep(time.Duration(randomSleep) * time.Millisecond)

					// read again and check if it's already not dumped
					item, err := mc.Get(key)
					if err != nil {
						log.Printf("[ERROR] Failed getting cache item for key %s: %s", key, err)
						return
					}

					incrementedItemInCache = IncrementInCache{}
					err = json.Unmarshal(item.Value, &incrementedItemInCache)
					if err != nil {
						log.Printf("[ERROR] Failed unmarshalling item in cache: %s", err)
						incrementedItemInCache.Amount = num
						incrementedItemInCache.CreatedAt = time.Now().Unix()
					}

					// this means there will be an overwrite!
					if incrementedItemInCache.Amount == num {
						// better to update the cache again instead of losing the data
						incrementedItemInCache.Amount += uint64(incrementAmount)
					} else if num > incrementedItemInCache.Amount {
						// we bow to the higher number we have
						incrementedItemInCache.Amount = num
					} else if incrementedItemInCache.Amount > num {
						// this means, a bunch of stats were added in the meantime
						// bow to the higher number and just increment again
						incrementedItemInCache.Amount += uint64(incrementAmount)
					}

					// log.Printf("[DEBUG] Cache item with key %s which was created at %d is now %d", key, incrementedItemInCache.CreatedAt, incrementedItemInCache.Amount)
					// log.Printf("[DEBUG] Cache item with key %s which was created at %d is now %d. While num we updated was %d", key, incrementedItemInCache.CreatedAt, incrementedItemInCache.Amount, num)

					data, err := json.Marshal(incrementedItemInCache)
					if err != nil {
						log.Printf("[ERROR] Failed marshalling increment item for cache: %s", err)
					}

					item = &gomemcache.Item{
						Key:        key,
						Value:      data,
						Expiration: 86400 * 30,
					}

					if err := mc.Set(item); err != nil {
						log.Printf("[ERROR] Failed setting inner memcache for key %s: %s", orgId, err)
					}
				}
			} else {
				// let's keep this here for now
				// log.Printf("[ERROR] Length of value in cache key %s is less than 1: %d", key, len(item.Value))
			}
		}

	} else {
		// Get the cache, but use requestCache instead of memcache
		foundItem := 1
		item, err := GetCache(ctx, key)
		if err != nil {
			if incrementAmount > int(dbDumpInterval) {
				foundItem = incrementAmount
			} else {
				//toIncrement := []byte(fmt.Sprintf("%d", incrementAmount))
				//toIncrement := []byte(string(incrementAmount))
				foundItem = incrementAmount
			}

			//log.Printf("[DEBUG] Increment cache miss for %s", key)
		} else {
			// make item into a number
			if item == nil {
				log.Printf("[ERROR] Value in DB is nil for cache %s. Setting to 1", dataType)
			} else {
				// Parse out int from []uint8 with marshal
				// String (ASCII): 0x31 -> 1
				// int: 0x1 -> 1

				//foundData := []byte(item.(int))
				foundData := item.([]uint8)
				foundItem, err = strconv.Atoi(string(foundData))
				if err != nil {
					log.Printf("[ERROR] Stat tracking fail: Failed converting item to int: %s. Datatype: %s", err, dataType)
					foundItem = incrementAmount
					//foundItem = foundData
				} else {
					foundItem += incrementAmount
				}
			}
		}

		if foundItem >= int(dbDumpInterval) {
			// Memcache dump first to keep the counter going for other executions
			go SetCache(context.Background(), key, []byte(fmt.Sprintf("%x", 0)), 86400)
			IncrementCacheDump(ctx, orgId, dataType, foundItem)

			//log.Printf("[DEBUG] Dumping cache for %s with amount %d", key, foundItem)
		} else {
			// Set cache
			//setCacheValue := []byte(strconv.FormatInt(int64(foundItem), 16))
			//setCacheValue := []byte(fmt.Sprintf("%d", foundItem))

			// FIXME: Something is wrong here past 0x9 :O
			setCacheValue := []byte(fmt.Sprintf("%x", foundItem))
			err = SetCache(ctx, key, setCacheValue, 86400)
			if err != nil {
				log.Printf("[ERROR] Failed setting increment cache for key %s: %s", orgId, err)
			}
		}

		return
	}
}

// 1. Check list if there is a record for yesterday
// 2. If there isn't, set it and clear out the daily records
// Also: can we dump a list of apps that run? Maybe a list of them?
func handleDailyCacheUpdate(executionInfo *ExecutionInfo) *ExecutionInfo {
	currentDate := time.Now().Format("2006-01-02")

	// check if today's date exists in daily stats, if not (new day), append it and reset daily values
	if len(executionInfo.DailyStatistics) == 0 || executionInfo.DailyStatistics[len(executionInfo.DailyStatistics)-1].Date.Format("2006-01-02") != currentDate {
		executionInfo.DailyStatistics = append(executionInfo.DailyStatistics, DailyStatistics{
			Date: time.Now(),
		})

		// Reset daily and hourly/weekly fields so they start fresh
		executionInfo.HourlyAppExecutions = 0
		executionInfo.HourlyChildAppExecutions = 0
		executionInfo.HourlyAppExecutionsFailed = 0
		executionInfo.HourlySubflowExecutions = 0
		executionInfo.HourlyWorkflowExecutions = 0
		executionInfo.HourlyWorkflowExecutionsFinished = 0
		executionInfo.HourlyChildWorkflowExecutions = 0
		executionInfo.HourlyWorkflowExecutionsFailed = 0
		executionInfo.HourlyOrgSyncActions = 0
		executionInfo.HourlyCloudExecutions = 0
		executionInfo.HourlyOnpremExecutions = 0

		executionInfo.DailyAppExecutions = 0
		executionInfo.DailyChildAppExecutions = 0
		executionInfo.DailyAppExecutionsFailed = 0
		executionInfo.DailySubflowExecutions = 0
		executionInfo.DailyWorkflowExecutions = 0
		executionInfo.DailyWorkflowExecutionsFinished = 0
		executionInfo.DailyChildWorkflowExecutions = 0
		executionInfo.DailyWorkflowExecutionsFailed = 0
		executionInfo.DailyOrgSyncActions = 0
		executionInfo.DailyCloudExecutions = 0
		executionInfo.DailyOnpremExecutions = 0
		executionInfo.DailyApiUsage = 0
		executionInfo.DailyAIUsage = 0
		executionInfo.DailyAgentExecutions = 0
		executionInfo.DailyAgentTokens = 0
		executionInfo.DailyAgentInputTokens = 0
		executionInfo.DailyAgentOutputTokens = 0
		executionInfo.DailyChildOrgAiUsage = 0
		executionInfo.DailyChildOrgAgentExecutions = 0
		executionInfo.DailyChildOrgAgentTokens = 0
		executionInfo.DailyChildOrgAgentInputTokens = 0
		executionInfo.DailyChildOrgAgentOutputTokens = 0
		executionInfo.DailySMSUsage = 0
		executionInfo.DailyChildOrgSMSUsage = 0
		executionInfo.DailyEmailUsage = 0
		executionInfo.DailyChildOrgEmailUsage = 0
		executionInfo.DailyAgentExecutionsSuccessful = 0
		executionInfo.DailyAgentExecutionsFailed = 0
		executionInfo.DailyAgentCachedTokens = 0
		executionInfo.DailyAgentMaxLoopsHit = 0
		executionInfo.DailyChildOrgAgentExecutionsSuccessful = 0
		executionInfo.DailyChildOrgAgentExecutionsFailed = 0
		executionInfo.DailyChildOrgAgentCachedTokens = 0
		executionInfo.DailyChildOrgAgentMaxLoopsHit = 0

		executionInfo.WeeklyAppExecutions = 0
		executionInfo.WeeklyChildAppExecutions = 0
		executionInfo.WeeklyAppExecutionsFailed = 0
		executionInfo.WeeklySubflowExecutions = 0
		executionInfo.WeeklyWorkflowExecutions = 0
		executionInfo.WeeklyWorkflowExecutionsFinished = 0
		executionInfo.WeeklyWorkflowExecutionsFailed = 0
		executionInfo.WeeklyOrgSyncActions = 0
		executionInfo.WeeklyCloudExecutions = 0
		executionInfo.WeeklyOnpremExecutions = 0
		executionInfo.WeeklyChildWorkflowExecutions = 0

		for additionIndex := range executionInfo.Additions {
			executionInfo.Additions[additionIndex].Value = 0
			executionInfo.Additions[additionIndex].DailyValue = 0
		}
	} else {
		// Update today's stats on each increment
		lastIdx := len(executionInfo.DailyStatistics) - 1
		executionInfo.DailyStatistics[lastIdx].AppExecutions = executionInfo.DailyAppExecutions
		executionInfo.DailyStatistics[lastIdx].ChildAppExecutions = executionInfo.DailyChildAppExecutions
		executionInfo.DailyStatistics[lastIdx].AppExecutionsFailed = executionInfo.DailyAppExecutionsFailed
		executionInfo.DailyStatistics[lastIdx].SubflowExecutions = executionInfo.DailySubflowExecutions
		executionInfo.DailyStatistics[lastIdx].WorkflowExecutions = executionInfo.DailyWorkflowExecutions
		executionInfo.DailyStatistics[lastIdx].WorkflowExecutionsFinished = executionInfo.DailyWorkflowExecutionsFinished
		executionInfo.DailyStatistics[lastIdx].WorkflowExecutionsFailed = executionInfo.DailyWorkflowExecutionsFailed
		executionInfo.DailyStatistics[lastIdx].OrgSyncActions = executionInfo.DailyOrgSyncActions
		executionInfo.DailyStatistics[lastIdx].CloudExecutions = executionInfo.DailyCloudExecutions
		executionInfo.DailyStatistics[lastIdx].OnpremExecutions = executionInfo.DailyOnpremExecutions
		executionInfo.DailyStatistics[lastIdx].AIUsage = executionInfo.DailyAIUsage
		executionInfo.DailyStatistics[lastIdx].ApiUsage = executionInfo.DailyApiUsage
		executionInfo.DailyStatistics[lastIdx].Additions = executionInfo.Additions
		executionInfo.DailyStatistics[lastIdx].AgentExecutions = executionInfo.DailyAgentExecutions
		executionInfo.DailyStatistics[lastIdx].AgentTokens = executionInfo.DailyAgentTokens
		executionInfo.DailyStatistics[lastIdx].AgentInputTokens = executionInfo.DailyAgentInputTokens
		executionInfo.DailyStatistics[lastIdx].ChildOrgAgentInputTokens = executionInfo.DailyChildOrgAgentInputTokens
		executionInfo.DailyStatistics[lastIdx].AgentOutputTokens = executionInfo.DailyAgentOutputTokens
		executionInfo.DailyStatistics[lastIdx].ChildOrgAgentOutputTokens = executionInfo.DailyChildOrgAgentOutputTokens
		executionInfo.DailyStatistics[lastIdx].ChildOrgAiUsage = executionInfo.DailyChildOrgAiUsage
		executionInfo.DailyStatistics[lastIdx].ChildOrgAgentExecutions = executionInfo.DailyChildOrgAgentExecutions
		executionInfo.DailyStatistics[lastIdx].ChildOrgAgentTokens = executionInfo.DailyChildOrgAgentTokens
		executionInfo.DailyStatistics[lastIdx].DailySMSUsage = executionInfo.DailySMSUsage
		executionInfo.DailyStatistics[lastIdx].DailyChildOrgSMSUsage = executionInfo.DailyChildOrgSMSUsage
		executionInfo.DailyStatistics[lastIdx].DailyEmailUsage = executionInfo.DailyEmailUsage
		executionInfo.DailyStatistics[lastIdx].DailyChildOrgEmailUsage = executionInfo.DailyChildOrgEmailUsage

		executionInfo.DailyStatistics[lastIdx].AgentExecutionsSuccessful = executionInfo.DailyAgentExecutionsSuccessful
		executionInfo.DailyStatistics[lastIdx].AgentExecutionsFailed = executionInfo.DailyAgentExecutionsFailed
		executionInfo.DailyStatistics[lastIdx].AgentCachedTokens = executionInfo.DailyAgentCachedTokens
		executionInfo.DailyStatistics[lastIdx].AgentMaxLoopsHit = executionInfo.DailyAgentMaxLoopsHit

		executionInfo.DailyStatistics[lastIdx].ChildOrgAgentExecutionsSuccessful = executionInfo.DailyChildOrgAgentExecutionsSuccessful
		executionInfo.DailyStatistics[lastIdx].ChildOrgAgentExecutionsFailed = executionInfo.DailyChildOrgAgentExecutionsFailed
		executionInfo.DailyStatistics[lastIdx].ChildOrgAgentCachedTokens = executionInfo.DailyChildOrgAgentCachedTokens
		executionInfo.DailyStatistics[lastIdx].ChildOrgAgentMaxLoopsHit = executionInfo.DailyChildOrgAgentMaxLoopsHit

	}

	now := time.Now()
	currentMonth := int(now.Month())
	if executionInfo.LastMonthlyResetMonth != currentMonth {
		log.Printf("[DEBUG] Resetting monthly stats for org %s on %s", executionInfo.OrgId, now.Format("2006-01-02"))

		executionInfo.MonthlyAppExecutions = 0
		executionInfo.MonthlyChildAppExecutions = 0
		executionInfo.MonthlyAppExecutionsFailed = 0
		executionInfo.MonthlySubflowExecutions = 0
		executionInfo.MonthlyWorkflowExecutions = 0
		executionInfo.MonthlyWorkflowExecutionsFinished = 0
		executionInfo.MonthlyChildWorkflowExecutions = 0
		executionInfo.MonthlyWorkflowExecutionsFailed = 0
		executionInfo.MonthlyOrgSyncActions = 0
		executionInfo.MonthlyCloudExecutions = 0
		executionInfo.MonthlyOnpremExecutions = 0
		executionInfo.MonthlyApiUsage = 0
		executionInfo.MonthlyAIUsage = 0
		executionInfo.MonthlyAgentExecutions = 0
		executionInfo.MonthlyAgentExecutionsSuccessful = 0
		executionInfo.MonthlyAgentExecutionsFailed = 0
		executionInfo.MonthlyAgentMaxLoopsHit = 0
		executionInfo.MonthlyAgentTokens = 0
		executionInfo.MonthlyAgentInputTokens = 0
		executionInfo.MonthlyAgentOutputTokens = 0
		executionInfo.MonthlyAgentCachedTokens = 0
		executionInfo.MonthlyChildOrgAiUsage = 0
		executionInfo.MonthlyChildOrgAgentExecutions = 0
		executionInfo.MonthlyChildOrgAgentTokens = 0
		executionInfo.MonthlyChildOrgAgentInputTokens = 0
		executionInfo.MonthlyChildOrgAgentOutputTokens = 0
		executionInfo.MonthlySMSUsage = 0
		executionInfo.MonthlyChildOrgSMSUsage = 0
		executionInfo.MonthlyEmailUsage = 0
		executionInfo.MonthlyChildOrgEmailUsage = 0
		executionInfo.MonthlyAgentMaxLoopsHit = 0
		executionInfo.MonthlyChildOrgAgentExecutionsSuccessful = 0
		executionInfo.MonthlyChildOrgAgentExecutionsFailed = 0
		executionInfo.MonthlyChildOrgAgentCachedTokens = 0
		executionInfo.MonthlyChildOrgAgentMaxLoopsHit = 0
		executionInfo.LastMonthlyResetMonth = currentMonth
		executionInfo.LastUsageAlertThreshold = 0
		executionInfo.MonthlyAIUsageAlertSent = false

		// Reset all usage alerts to unsent
		for index := range executionInfo.UsageAlerts {
			executionInfo.UsageAlerts[index].Email_send = false
		}
	}

	return executionInfo
}

func generateAlertCacheKey(orgId string, threshold interface{}, emailList []string) string {
	sortedEmails := make([]string, len(emailList))
	copy(sortedEmails, emailList)
	sort.Strings(sortedEmails)

	emailsStr := strings.Join(sortedEmails, ",")
	thresholdStr := fmt.Sprintf("%v", threshold)

	key := fmt.Sprintf("alert_cache_%s_%s_%s", orgId, thresholdStr, emailsStr)

	key = strings.ReplaceAll(key, "@", "_at_")
	key = strings.ReplaceAll(key, ".", "_dot_")
	key = strings.ReplaceAll(key, " ", "_")

	// Memcache keys have a 250-character limit. Hash anything that exceeds it.
	if len(key) > 200 {
		hash := sha256.Sum256([]byte(key))
		key = "alert_cache_" + hex.EncodeToString(hash[:])
	}

	return key
}

func checkAndSetAlertCache(ctx context.Context, cacheKey string) bool {
	_, err := GetCache(ctx, cacheKey)
	if err == nil {
		return false
	}

	now := time.Now()
	endOfMonth := time.Date(now.Year(), now.Month()+1, 1, 0, 0, 0, 0, now.Location())
	remainingMinutes := int32(endOfMonth.Sub(now).Minutes())
	if remainingMinutes < 60 {
		remainingMinutes = 60
	}

	err = SetCache(ctx, cacheKey, []byte("sent"), remainingMinutes)
	if err != nil {
		log.Printf("[WARNING] Failed setting alert cache for key %s: %s", cacheKey, err)
	}

	return true
}

func CheckOnpremUsageAlerts(ctx context.Context, org *Org, onpremMonthlyTotal int64) error {
	if !isOnpremAlertEligible(org) {
		return nil
	}

	onpremLimit := org.SyncFeatures.OnpremAppExecutions.Limit
	if onpremLimit <= 0 {
		return nil
	}

	onpremPercentage := float64(onpremMonthlyTotal) / float64(onpremLimit) * 100

	allAdmins := []string{}
	for _, user := range org.Users {
		if user.Role == "admin" {
			allAdmins = append(allAdmins, user.Username)
		}
	}

	if !ArrayContains(allAdmins, "chris@shuffler.io") {
		allAdmins = append(allAdmins, "chris@shuffler.io")
	}

	if !ArrayContains(allAdmins, "jay@shuffler.io") {
		allAdmins = append(allAdmins, "jay@shuffler.io")
	}

	changed := false
	for index, alert := range org.Billing.OnpremAlertThreshold {
		if alert.Email_send || onpremPercentage < float64(alert.Percentage) {
			continue
		}

		cacheKey := generateAlertCacheKey(org.Id, fmt.Sprintf("onprem_%d", alert.Percentage), allAdmins)
		if !checkAndSetAlertCache(ctx, cacheKey) {
			continue
		}

		usagePercentageStr := fmt.Sprintf("%d%% of your on-premise app runs limit", alert.Percentage)
		Subject := fmt.Sprintf("[Shuffle]: You've reached %s for your tenant %s", usagePercentageStr, org.Name)
		substitutions := map[string]interface{}{
			"app_runs_usage":            onpremMonthlyTotal,
			"app_runs_limit":            onpremLimit,
			"subject_string":            usagePercentageStr,
			"org_name":                  org.Name,
			"org_id":                    org.Id,
			"admin_email":               org.Name,
			"app_runs_usage_percentage": int64(onpremPercentage),
		}

		err := sendMailSendgridV2(
			[]string{"support@shuffler.io"},
			Subject,
			substitutions,
			false,
			"d-3678d48b2b7144feb4b0b4cff7045016",
			allAdmins,
		)
		if err != nil {
			log.Printf("[ERROR] Failed sending onprem usage alert mail for org %s: %s", org.Id, err)
			continue
		}

		org.Billing.OnpremAlertThreshold[index].Email_send = true
		changed = true
	}

	if changed {
		return SetOrg(ctx, *org, org.Id)
	}

	return nil
}

func HandleIncrement(dataType string, orgStatistics *ExecutionInfo, increment uint) *ExecutionInfo {

	appendCustom := false

	if dataType == "childorg_app_executions" {
		orgStatistics.TotalChildAppExecutions += int64(increment)
		orgStatistics.MonthlyChildAppExecutions += int64(increment)
		orgStatistics.WeeklyChildAppExecutions += int64(increment)
		orgStatistics.DailyChildAppExecutions += int64(increment)
		orgStatistics.HourlyChildAppExecutions += int64(increment)

	} else if dataType == "app_executions" {
		orgStatistics.TotalAppExecutions += int64(increment)
		orgStatistics.MonthlyAppExecutions += int64(increment)
		orgStatistics.WeeklyAppExecutions += int64(increment)
		orgStatistics.DailyAppExecutions += int64(increment)
		orgStatistics.HourlyAppExecutions += int64(increment)

	} else if dataType == "workflow_executions" {
		orgStatistics.TotalWorkflowExecutions += int64(increment)
		orgStatistics.MonthlyWorkflowExecutions += int64(increment)
		orgStatistics.WeeklyWorkflowExecutions += int64(increment)
		orgStatistics.DailyWorkflowExecutions += int64(increment)
		orgStatistics.HourlyWorkflowExecutions += int64(increment)

	} else if dataType == "childorg_workflow_executions" {
		orgStatistics.TotalChildWorkflowExecutions += int64(increment)
		orgStatistics.MonthlyChildWorkflowExecutions += int64(increment)
		orgStatistics.WeeklyChildWorkflowExecutions += int64(increment)
		orgStatistics.DailyChildWorkflowExecutions += int64(increment)
		orgStatistics.HourlyChildWorkflowExecutions += int64(increment)
	} else if dataType == "workflow_executions_finished" {
		orgStatistics.TotalWorkflowExecutionsFinished += int64(increment)
		orgStatistics.MonthlyWorkflowExecutionsFinished += int64(increment)
		orgStatistics.WeeklyWorkflowExecutionsFinished += int64(increment)
		orgStatistics.DailyWorkflowExecutionsFinished += int64(increment)
		orgStatistics.HourlyWorkflowExecutionsFinished += int64(increment)

	} else if dataType == "workflow_executions_failed" {
		orgStatistics.TotalWorkflowExecutionsFailed += int64(increment)
		orgStatistics.MonthlyWorkflowExecutionsFailed += int64(increment)
		orgStatistics.WeeklyWorkflowExecutionsFailed += int64(increment)
		orgStatistics.DailyWorkflowExecutionsFailed += int64(increment)
		orgStatistics.HourlyWorkflowExecutionsFailed += int64(increment)

	} else if dataType == "app_executions_failed" {
		orgStatistics.TotalAppExecutionsFailed += int64(increment)
		orgStatistics.MonthlyAppExecutionsFailed += int64(increment)
		orgStatistics.WeeklyAppExecutionsFailed += int64(increment)
		orgStatistics.DailyAppExecutionsFailed += int64(increment)
		orgStatistics.HourlyAppExecutionsFailed += int64(increment)

	} else if dataType == "subflow_executions" {
		orgStatistics.TotalSubflowExecutions += int64(increment)
		orgStatistics.MonthlySubflowExecutions += int64(increment)
		orgStatistics.WeeklySubflowExecutions += int64(increment)
		orgStatistics.DailySubflowExecutions += int64(increment)
		orgStatistics.HourlySubflowExecutions += int64(increment)

	} else if dataType == "org_sync_actions" {
		orgStatistics.TotalOrgSyncActions += int64(increment)
		orgStatistics.MonthlyOrgSyncActions += int64(increment)
		orgStatistics.WeeklyOrgSyncActions += int64(increment)
		orgStatistics.DailyOrgSyncActions += int64(increment)
		orgStatistics.HourlyOrgSyncActions += int64(increment)

	} else if dataType == "workflow_executions_cloud" {
		orgStatistics.TotalCloudExecutions += int64(increment)
		orgStatistics.MonthlyCloudExecutions += int64(increment)
		orgStatistics.WeeklyCloudExecutions += int64(increment)
		orgStatistics.DailyCloudExecutions += int64(increment)
		orgStatistics.HourlyCloudExecutions += int64(increment)

	} else if dataType == "workflow_executions_onprem" {
		orgStatistics.TotalOnpremExecutions += int64(increment)
		orgStatistics.MonthlyOnpremExecutions += int64(increment)
		orgStatistics.WeeklyOnpremExecutions += int64(increment)
		orgStatistics.DailyOnpremExecutions += int64(increment)
		orgStatistics.HourlyOnpremExecutions += int64(increment)
	} else if dataType == "api_usage" {
		orgStatistics.TotalApiUsage += int64(increment)
		orgStatistics.MonthlyApiUsage += int64(increment)
		orgStatistics.DailyApiUsage += int64(increment)
	} else if dataType == "ai_executions" {
		orgStatistics.TotalAIUsage += int64(increment)
		orgStatistics.MonthlyAIUsage += int64(increment)
		orgStatistics.DailyAIUsage += int64(increment)
	} else if dataType == "agent_executions" {
		orgStatistics.TotalAgentExecutions += int64(increment)
		orgStatistics.MonthlyAgentExecutions += int64(increment)
		orgStatistics.DailyAgentExecutions += int64(increment)
	} else if dataType == "agent_executions_successful" {
		orgStatistics.TotalAgentExecutionsSuccessful += int64(increment)
		orgStatistics.MonthlyAgentExecutionsSuccessful += int64(increment)
		orgStatistics.DailyAgentExecutionsSuccessful += int64(increment)
	} else if dataType == "agent_executions_failed" {
		orgStatistics.TotalAgentExecutionsFailed += int64(increment)
		orgStatistics.MonthlyAgentExecutionsFailed += int64(increment)
		orgStatistics.DailyAgentExecutionsFailed += int64(increment)
	} else if dataType == "agent_max_loops_hit" {
		orgStatistics.TotalAgentMaxLoopsHit += int64(increment)
		orgStatistics.MonthlyAgentMaxLoopsHit += int64(increment)
		orgStatistics.DailyAgentMaxLoopsHit += int64(increment)
	} else if dataType == "child_org_agent_max_loops_hit" {
		orgStatistics.TotalChildOrgAgentMaxLoopsHit += int64(increment)
		orgStatistics.MonthlyChildOrgAgentMaxLoopsHit += int64(increment)
		orgStatistics.DailyChildOrgAgentMaxLoopsHit += int64(increment)
	} else if dataType == "agent_tokens" {
		orgStatistics.TotalAgentTokens += int64(increment)
		orgStatistics.MonthlyAgentTokens += int64(increment)
		orgStatistics.DailyAgentTokens += int64(increment)
	} else if dataType == "childorg_agent_tokens" {
		orgStatistics.TotalChildOrgAgentTokens += int64(increment)
		orgStatistics.MonthlyChildOrgAgentTokens += int64(increment)
		orgStatistics.DailyChildOrgAgentTokens += int64(increment)
	} else if dataType == "agent_input_tokens" {
		orgStatistics.TotalAgentInputTokens += int64(increment)
		orgStatistics.MonthlyAgentInputTokens += int64(increment)
		orgStatistics.DailyAgentInputTokens += int64(increment)
	} else if dataType == "childorg_agent_input_tokens" {
		orgStatistics.TotalChildOrgAgentInputTokens += int64(increment)
		orgStatistics.MonthlyChildOrgAgentInputTokens += int64(increment)
		orgStatistics.DailyChildOrgAgentInputTokens += int64(increment)
	} else if dataType == "agent_output_tokens" {
		orgStatistics.TotalAgentOutputTokens += int64(increment)
		orgStatistics.MonthlyAgentOutputTokens += int64(increment)
		orgStatistics.DailyAgentOutputTokens += int64(increment)
	} else if dataType == "agent_cached_tokens" {
		orgStatistics.TotalAgentCachedTokens += int64(increment)
		orgStatistics.MonthlyAgentCachedTokens += int64(increment)
		orgStatistics.DailyAgentCachedTokens += int64(increment)
	} else if dataType == "child_org_agent_executions" {
		orgStatistics.TotalChildOrgAgentExecutions += int64(increment)
		orgStatistics.MonthlyChildOrgAgentExecutions += int64(increment)
		orgStatistics.DailyChildOrgAgentExecutions += int64(increment)
	} else if dataType == "child_org_agent_executions_successful" {
		orgStatistics.TotalChildOrgAgentExecutionsSuccessful += int64(increment)
		orgStatistics.MonthlyChildOrgAgentExecutionsSuccessful += int64(increment)
		orgStatistics.DailyChildOrgAgentExecutionsSuccessful += int64(increment)
	} else if dataType == "child_org_agent_executions_failed" {
		orgStatistics.TotalChildOrgAgentExecutionsFailed += int64(increment)
		orgStatistics.MonthlyChildOrgAgentExecutionsFailed += int64(increment)
		orgStatistics.DailyChildOrgAgentExecutionsFailed += int64(increment)
	} else if dataType == "child_org_agent_tokens" {
		orgStatistics.TotalChildOrgAgentTokens += int64(increment)
		orgStatistics.MonthlyChildOrgAgentTokens += int64(increment)
		orgStatistics.DailyChildOrgAgentTokens += int64(increment)
	} else if dataType == "child_org_agent_input_tokens" {
		orgStatistics.TotalChildOrgAgentInputTokens += int64(increment)
		orgStatistics.MonthlyChildOrgAgentInputTokens += int64(increment)
		orgStatistics.DailyChildOrgAgentInputTokens += int64(increment)
	} else if dataType == "child_org_agent_output_tokens" {
		orgStatistics.TotalChildOrgAgentOutputTokens += int64(increment)
		orgStatistics.MonthlyChildOrgAgentOutputTokens += int64(increment)
		orgStatistics.DailyChildOrgAgentOutputTokens += int64(increment)
	} else if dataType == "send_sms" {
		orgStatistics.TotalSMSUsage += int64(increment)
		orgStatistics.MonthlySMSUsage += int64(increment)
		orgStatistics.DailySMSUsage += int64(increment)
	} else if dataType == "childorg_send_sms" {
		orgStatistics.TotalChildOrgSMSUsage += int64(increment)
		orgStatistics.MonthlyChildOrgSMSUsage += int64(increment)
		orgStatistics.DailyChildOrgSMSUsage += int64(increment)
	} else if dataType == "send_mail" {
		orgStatistics.TotalEmailUsage += int64(increment)
		orgStatistics.MonthlyEmailUsage += int64(increment)
		orgStatistics.DailyEmailUsage += int64(increment)
	} else if dataType == "childorg_send_mail" {
		orgStatistics.TotalChildOrgEmailUsage += int64(increment)
		orgStatistics.MonthlyChildOrgEmailUsage += int64(increment)
		orgStatistics.DailyChildOrgEmailUsage += int64(increment)
	} else if dataType == "child_org_agent_executions" {
		orgStatistics.TotalChildOrgAgentExecutions += int64(increment)
		orgStatistics.MonthlyChildOrgAgentExecutions += int64(increment)
		orgStatistics.DailyChildOrgAgentExecutions += int64(increment)
	} else if dataType == "child_org_agent_executions_successful" {
		orgStatistics.TotalChildOrgAgentExecutionsSuccessful += int64(increment)
		orgStatistics.MonthlyChildOrgAgentExecutionsSuccessful += int64(increment)
		orgStatistics.DailyChildOrgAgentExecutionsSuccessful += int64(increment)
	} else if dataType == "child_org_agent_executions_failed" {
		orgStatistics.TotalChildOrgAgentExecutionsFailed += int64(increment)
		orgStatistics.MonthlyChildOrgAgentExecutionsFailed += int64(increment)
		orgStatistics.DailyChildOrgAgentExecutionsFailed += int64(increment)
	} else if dataType == "childorg_agent_cached_tokens" {
		orgStatistics.TotalChildOrgAgentCachedTokens += int64(increment)
		orgStatistics.MonthlyChildOrgAgentCachedTokens += int64(increment)
		orgStatistics.DailyChildOrgAgentCachedTokens += int64(increment)
	} else {
		//log.Printf("\n\n[ERROR] Unknown data type in stats increment for org %s: %s. Appending to custom list.\n\n", orgStatistics.OrgId, dataType)
		appendCustom = true
	}

	if strings.HasPrefix(dataType, "app_executions") && dataType != "app_executions" {
		appendCustom = true
	}

	if appendCustom {
		if debug {
			log.Printf("[DEBUG] Appending custom data type %s for org %s. Amount: %d", dataType, orgStatistics.OrgId, increment)
		}

		dataType = strings.ToLower(strings.Replace(dataType, " ", "_", -1))
		found := false
		for additionIndex, addition := range orgStatistics.Additions {
			if addition.Key != dataType {
				continue
			}

			found = true
			amount := int64(increment)

			orgStatistics.Additions[additionIndex].Value += amount
			//orgStatistics.Additions[additionIndex].DailyValue += amount

			break
		}

		if debug {
			log.Printf("[DEBUG] After processing custom data type %s for org %s. Amount: %d. Found: %v", dataType, orgStatistics.OrgId, increment, found)
		}

		if !found {
			orgStatistics.Additions = append(orgStatistics.Additions, AdditionalUseConfig{
				Key:   dataType,
				Value: int64(increment),
				//DailyValue: int64(increment),

				//Date: 0,
			})
		}
	}

	//send mail if the app runs more than the set threshold limit
	ctx := context.Background()
	orgId := orgStatistics.OrgId

	//Unmarshal the org details
	org, err := GetOrg(ctx, orgId)
	if err != nil {
		log.Printf("[ERROR] Failed getting org in increment: %s", err)
		return orgStatistics
	}

	//send mail if the app runs more than the set threshold limit
	emailSend := false
	if len(org.Id) == 0 {
		return orgStatistics
	}

	for _, alert := range org.Billing.AlertThreshold {
		found := false
		for _, statAlert := range orgStatistics.UsageAlerts {
			if statAlert.Percentage == alert.Percentage && statAlert.Count == alert.Count {
				found = true
				break
			}
		}

		if !found {
			orgStatistics.UsageAlerts = append(orgStatistics.UsageAlerts, AlertThreshold{
				Percentage: alert.Percentage,
				Count:      alert.Count,
				Email_send: alert.Email_send,
			})
		}
	}

	for index, AlertThreshold := range org.Billing.AlertThreshold {

		totalAppExecutions := orgStatistics.MonthlyAppExecutions + orgStatistics.MonthlyChildAppExecutions

		// Alert should be based on the current month usage, check if monthly reset happened if yes than only send alert
		monthlyResetMonth := time.Now().Month()
		shouldSendAlert := false
		if orgStatistics.LastMonthlyResetMonth == int(monthlyResetMonth) {
			shouldSendAlert = true
		}

		sendAlert := false
		for _, alerts := range orgStatistics.UsageAlerts {
			if alerts.Percentage == AlertThreshold.Percentage && alerts.Count == AlertThreshold.Count {
				sendAlert = alerts.Email_send
				break
			}
		}

		if int64(AlertThreshold.Count) < totalAppExecutions && !sendAlert && shouldSendAlert {

			allAdmins := []string{}
			for _, user := range org.Users {
				if user.Role == "admin" {
					allAdmins = append(allAdmins, user.Username)
				}
			}

			if !ArrayContains(allAdmins, "chris@shuffler.io") {
				allAdmins = append(allAdmins, "chris@shuffler.io")
			}

			if !ArrayContains(allAdmins, "jay@shuffler.io") {
				allAdmins = append(allAdmins, "jay@shuffler.io")
			}

			cacheKey := generateAlertCacheKey(orgId, AlertThreshold.Count, allAdmins)
			if !checkAndSetAlertCache(ctx, cacheKey) {
				continue
			}

			AppRunsPercentage := float64(totalAppExecutions) / float64(org.SyncFeatures.AppExecutions.Limit) * 100
			appRunsUsagePercentageStr := fmt.Sprintf("%d%% of your app runs limit", int64(AppRunsPercentage))
			Subject := fmt.Sprintf("[Shuffle]: You've reached %s for your tenant %s", appRunsUsagePercentageStr, org.Name)
			aiTokensUsage := orgStatistics.MonthlyAgentTokens + orgStatistics.MonthlyChildOrgAgentTokens
			aiTokensUsagePercentage := float64(aiTokensUsage) / float64(org.SyncFeatures.AgentTokens.Limit) * 100

			aiTokensLimit := org.SyncFeatures.AgentTokens.Limit
			if aiTokensLimit == 0 {
				aiTokensLimit = 10000000
			}
			substitutions := map[string]interface{}{
				"app_runs_usage":             totalAppExecutions,
				"app_runs_limit":             org.SyncFeatures.AppExecutions.Limit,
				"subject_string":             appRunsUsagePercentageStr,
				"ai_tokens_usage":            aiTokensUsage,
				"ai_tokens_limit":            aiTokensLimit,
				"org_name":                   org.Name,
				"org_id":                     org.Id,
				"admin_email":                org.Name,
				"app_runs_usage_percentage":  int64(AppRunsPercentage),
				"ai_tokens_usage_percentage": int64(aiTokensUsagePercentage),
			}

			err = sendMailSendgridV2(
				[]string{"support@shuffler.io"},
				Subject,
				substitutions,
				false,
				"d-3678d48b2b7144feb4b0b4cff7045016",
				allAdmins,
			)
			if err != nil {
				log.Printf("[ERROR] Failed sending alert mail in increment: %s", err)
			} else {
				emailSend = true
			}

			if emailSend {
				org.Billing.AlertThreshold[index].Email_send = true
				err = SetOrg(ctx, *org, orgId)
				if err != nil {
					log.Printf("[ERROR] Failed setting org in increment: %s", err)
					return orgStatistics
				}

				// update the the alert send in the statistics
				for index, alerts := range orgStatistics.UsageAlerts {
					if alerts.Percentage == AlertThreshold.Percentage && alerts.Count == AlertThreshold.Count {
						orgStatistics.UsageAlerts[index].Email_send = true
						break
					}
				}

				log.Printf("[DEBUG] Successfully sent alert mail for org %s", orgId)
			}
		}
	}

	// hard limit aleart
	if org.Billing.AppRunsHardLimit > 0 && orgStatistics.MonthlyAppExecutions > org.Billing.AppRunsHardLimit {
		// send alert to all admin in the orgs
		admins := []string{}

		for _, user := range org.Users {
			if user.Role == "admin" {
				admins = append(admins, user.Username)
			}
		}

		cacheKey := generateAlertCacheKey(orgId, "hard_limit", admins)
		if !checkAndSetAlertCache(ctx, cacheKey) {
			log.Printf("[DEBUG] Skipping duplicate hard limit alert for org %s - alert sent within last minute", orgId)
		} else {
			subject := fmt.Sprintf("App Runs Hard Limit Exceeded for Org %s (%s)", org.Name, org.Id)
			message := fmt.Sprintf(
				`Dear Team,

				Your organization <strong>%s</strong> (ID: %s) has exceeded the monthly app runs hard limit of <strong>%d</strong> runs.

				<strong>Current usage:</strong> %d app runs.
				
				As a result, all workflows have been temporarily blocked until the start of the next billing cycle.
				To increase your organization's hard limit, please visit the admin panel of the parent organization.
				If you have any questions, feel free to reach out to us at <a href="mailto:support@shuffler.io">support@shuffler.io</a>.
				
				Note: This is an automated message sent by Shuffle to notify you about the exceeded app runs hard limit.

				Best regards, 
				The Shuffler Team`,
				org.Name, org.Id, org.Billing.AppRunsHardLimit, orgStatistics.MonthlyAppExecutions,
			)

			err = sendMailSendgrid(admins, subject, message, false, []string{})
			if err != nil {
				log.Printf("[ERROR] Failed sending alert email to admins of org %s (%s): %s", org.Name, org.Id, err)
			}
		}
	}

	if dataType == "app_executions" || dataType == "childorg_app_executions" {

		validationOrg := org
		validationOrgStatistics := orgStatistics

		if len(org.CreatorOrg) > 0 {
			validationOrg, err = GetOrg(ctx, org.CreatorOrg)
			if err != nil {
				log.Printf("[ERROR] Failed getting parent org in increment: %s", err)
				return validationOrgStatistics
			}

			validationOrgStatistics, err = GetOrgStatistics(ctx, org.CreatorOrg)
			if err != nil {
				log.Printf("[ERROR] Failed getting parent org statistics in increment: %s", err)
				return validationOrgStatistics
			}
		}

		totalExecutions := float64(validationOrgStatistics.MonthlyAppExecutions) + float64(validationOrgStatistics.MonthlyChildAppExecutions)
		limit := float64(validationOrg.SyncFeatures.AppExecutions.Limit)
		percentage := (totalExecutions / limit) * 100

		var currentThreshold int64
		if percentage >= 50 {
			currentThreshold = int64((int(percentage) / 50) * 50)
		}

		monthlyResetMonth := time.Now().Month()
		shouldSendAlert := false
		if orgStatistics.LastMonthlyResetMonth == int(monthlyResetMonth) {
			shouldSendAlert = true
		}

		if currentThreshold >= 50 && currentThreshold > validationOrgStatistics.LastUsageAlertThreshold && shouldSendAlert {

			allAdmins := []string{}
			firstAdmin := ""
			allShufflerEmails := true

			for _, user := range org.Users {
				if user.Role == "admin" {
					allAdmins = append(allAdmins, user.Username)

					if firstAdmin == "" && !strings.Contains(user.Username, "shuffler.io") {
						firstAdmin = user.Username
					}

					if !strings.Contains(user.Username, "shuffler.io") {
						allShufflerEmails = false
					}
				}
			}

			if allShufflerEmails && firstAdmin == "" && len(allAdmins) > 0 {
				firstAdmin = allAdmins[0]
			}

			alertAlreadySet := false
			// If 50% and 100% alert are already set by user, and alert is send for that threshold, then skip
			for _, AlertThreshold := range validationOrg.Billing.AlertThreshold {
				if AlertThreshold.Percentage == int(currentThreshold) && AlertThreshold.Email_send {
					alertAlreadySet = true
					break
				}
			}

			newEmailList := []string{}
			if alertAlreadySet && (currentThreshold == 100 || currentThreshold == 50) {
				newEmailList = allAdmins
			} else {
				newEmailList = []string{"chris@shuffler.io", "jay@shuffler.io"}
			}

			// send mail use different subject line as it will sent only to the team
			totalAppExecutions := validationOrgStatistics.MonthlyAppExecutions + validationOrgStatistics.MonthlyChildAppExecutions
			AppRunsPercentage := float64(totalAppExecutions) / float64(validationOrg.SyncFeatures.AppExecutions.Limit) * 100
			appRunsUsagePercentageStr := fmt.Sprintf("%d%% of your app runs limit", int64(AppRunsPercentage))
			Subject := fmt.Sprintf("[Shuffle]: You've reached %s for your account %s", appRunsUsagePercentageStr, firstAdmin)
			leadInfo := ""
			if validationOrg.LeadInfo.POV {
				leadInfo = "POC"
			}

			if validationOrg.LeadInfo.Customer {
				leadInfo = "Customer"
			}

			if validationOrg.LeadInfo.IntegrationPartner || validationOrg.LeadInfo.TechPartner || validationOrg.LeadInfo.DistributionPartner || validationOrg.LeadInfo.ServicePartner || validationOrg.LeadInfo.ChannelPartner {
				leadInfo = "Partner"
			}

			if len(leadInfo) > 0 && (currentThreshold > 100) {
				Subject = fmt.Sprintf("[Shuffle] %s: You've reached %s for your account %s", leadInfo, appRunsUsagePercentageStr, firstAdmin)
			}

			if len(leadInfo) == 0 && !ArrayContains(newEmailList, "jay@shuffler.io") {
				newEmailList = append(newEmailList, "jay@shuffler.io")
			}

			if len(leadInfo) == 0 && !ArrayContains(newEmailList, "chris@shuffler.io") {
				newEmailList = append(newEmailList, "chris@shuffler.io")
			}

			cacheKey := generateAlertCacheKey(validationOrg.Id, currentThreshold, newEmailList)
			if !checkAndSetAlertCache(ctx, cacheKey) {
				log.Printf("[DEBUG] Skipping duplicate percentage threshold alert for org %s, threshold %d%% - alert sent within last minute", validationOrg.Id, currentThreshold)
			} else {
				substitutions := map[string]interface{}{
					"app_runs_usage":            totalAppExecutions,
					"app_runs_limit":            validationOrg.SyncFeatures.AppExecutions.Limit,
					"subject_string":            appRunsUsagePercentageStr,
					"ai_tokens_usage":           validationOrgStatistics.MonthlyAgentTokens,
					"ai_tokens_limit":           validationOrg.SyncFeatures.AgentTokens.Limit,
					"org_name":                  validationOrg.Name,
					"org_id":                    validationOrg.Id,
					"admin_email":               firstAdmin,
					"app_runs_usage_percentage": int64(AppRunsPercentage),
				}

				if currentThreshold > 100 {
					substitutions["lead_info"] = leadInfo
				}

				err = sendMailSendgridV2(
					[]string{"support@shuffler.io"},
					Subject,
					substitutions,
					false,
					"d-3678d48b2b7144feb4b0b4cff7045016",
					newEmailList,
				)

				if err != nil {
					log.Printf("[ERROR] Failed sending alert mail for child org in increment (1): %s", err)
				} else {
					log.Printf("[DEBUG] Successfully sent alert mail for child org %s to parent org %s (1)", validationOrg.Name, validationOrg.Name)
				}
			}

			if (currentThreshold == 100 || currentThreshold == 50) && len(leadInfo) > 0 {
				secondEmailList := []string{"chris@shuffler.io", "jay@shuffler.io", "support@shuffler.io"}
				secondCacheKey := generateAlertCacheKey(validationOrg.Id, fmt.Sprintf("second_%d", currentThreshold), secondEmailList)
				if !checkAndSetAlertCache(ctx, secondCacheKey) {
					log.Printf("[DEBUG] Skipping duplicate second alert for org %s, threshold %d%% - alert sent within last minute", validationOrg.Id, currentThreshold)
				} else {
					if len(leadInfo) > 0 {
						Subject = fmt.Sprintf("[Shuffle] %s: You've reached %s for your account %s", leadInfo, appRunsUsagePercentageStr, firstAdmin)
					}

					substitutions := map[string]interface{}{
						"app_runs_usage":            totalAppExecutions,
						"app_runs_limit":            validationOrg.SyncFeatures.AppExecutions.Limit,
						"subject_string":            appRunsUsagePercentageStr,
						"ai_tokens_usage":           validationOrgStatistics.MonthlyAgentTokens,
						"ai_tokens_limit":           validationOrg.SyncFeatures.AgentTokens.Limit,
						"org_name":                  validationOrg.Name,
						"org_id":                    validationOrg.Id,
						"admin_email":               firstAdmin,
						"lead_info":                 leadInfo,
						"app_runs_usage_percentage": int64(AppRunsPercentage),
					}

					log.Printf("[DEBUG] Sending second alert mail for child org %s to parent org %s (2)", validationOrg.Name, validationOrg.Name)
					err = sendMailSendgridV2(
						[]string{"chris@shuffler.io", "jay@shuffler.io", "support@shuffler.io"},
						Subject,
						substitutions,
						false,
						"d-3678d48b2b7144feb4b0b4cff7045016",
						[]string{},
					)
					if err != nil {
						log.Printf("[ERROR] Failed sending alert mail for child org in increment (2): %s", err)
					} else {
						log.Printf("[DEBUG] Successfully sent alert mail for child org %s to parent org %s (2)", validationOrg.Name, validationOrg.Name)
					}
				}
			}

			orgStatistics.LastUsageAlertThreshold = currentThreshold
		}
	}

	return orgStatistics
}

func UpdateDetectionStats(ctx context.Context, cacheData CacheKeyData) {
	//log.Printf("\n\n\nDETECTION STAT UPDATE!!\n\n\n")
	if len(cacheData.Category) == 0 || cacheData.Category == "default" {
		return
	}

	if len(cacheData.OrgId) == 0 {
		return
	}

	// Handle Detection
	// We actually do this in 'shuffle-security_incidents' tho
	category := strings.ToLower(cacheData.Category)
	if category != "ticket" && category != "detection" && category != "incidents" {
		//if debug {
		//	log.Printf("[WARNING] Debug: Not a detection or ticket category, skipping detection stats update for category '%s'", category)
		//}

		return
	}

	// Should we verify the data here?
	// Look for whether "rule" is set.
	mappedContent := map[string]interface{}{}
	err := json.Unmarshal([]byte(cacheData.Value), &mappedContent)
	if err != nil {
		log.Printf("[WARNING] Failed unmarshalling detection content for stats update: %s", err)
	}

	if mappedContent["rule"] == nil {
		log.Printf("[WARNING] No rule found in detection content, skipping stats update")
		return
	}

	ruleName := fmt.Sprintf("%v", mappedContent["rule"])
	if len(ruleName) == 0 {
		log.Printf("[WARNING] No rule name found in detection content, skipping stats update")
		return
	}

	detectionStatname := fmt.Sprintf("detection_rule_%s", strings.TrimSpace(strings.ToLower(strings.ReplaceAll(ruleName, " ", "_"))))
	IncrementCache(ctx, cacheData.OrgId, detectionStatname, 1)
	if debug {
		log.Printf("[DEBUG] Incremented detection stat '%s' for org %s", detectionStatname, cacheData.OrgId)
	}

}
