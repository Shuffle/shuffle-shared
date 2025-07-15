package shuffle

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"time"

	"encoding/json"
	"io/ioutil"
	"math/rand"
	"net/http"

	"cloud.google.com/go/datastore"
	gomemcache "github.com/bradfitz/gomemcache/memcache"
	"github.com/satori/go.uuid"
)

// FIXME: There is some issue when going past 0x9 (>0xA) with how 
// cache is being counted locally
//var dbInterval = 0x20
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
		Date:      time.Now(),
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

	if len(statsKey) > 0 {
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
		resp.WriteHeader(500)
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

func IncrementCacheDump(ctx context.Context, orgId, dataType string, amount ...int) error {

	nameKey := "org_statistics"
	orgStatistics := &ExecutionInfo{}

	dbDumpInterval := uint(dbInterval)
	if len(amount) > 0 {
		if amount[0] > 0 {
			dbDumpInterval = uint(amount[0])
		}
	}

	// Get the org
	tmpOrgDetail, err := GetOrg(ctx, orgId)
	if err != nil {
		log.Printf("[ERROR] Failed getting org in increment: %s", err)
		return err
	}

	// Ensuring we at least have one.
	if len(tmpOrgDetail.ManagerOrgs) == 0 && len(tmpOrgDetail.CreatorOrg) > 0 {
		tmpOrgDetail.ManagerOrgs = append(tmpOrgDetail.ManagerOrgs, OrgMini{
			Id: tmpOrgDetail.CreatorOrg,
		})
	}

	// FIXME: Can look for childorg_app_executions here as well which
	// would make tracking app runs at scale recursively work
	// The problem is... recursion (:
	if len(tmpOrgDetail.ManagerOrgs) > 0 && (dataType == "app_executions" || dataType == "app_runs") {
		for _, managerOrg := range tmpOrgDetail.ManagerOrgs {
			if len(managerOrg.Id) == 36 {
				IncrementCache(ctx, managerOrg.Id, "childorg_app_executions", int(dbDumpInterval))
			}
		}
	}

	concurrentTxn := false
	errMsg := ""

	if project.DbType == "opensearch" {
		// Get it from opensearch (may be prone to more issues at scale (thousands/second) due to no transactional locking)

		id := strings.ToLower(orgId)
		res, err := project.Es.Get(strings.ToLower(GetESIndexPrefix(nameKey)), id)
		if err != nil {
			log.Printf("[WARNING] Error in org STATS get: %s", err)
			return err
		}

		defer res.Body.Close()
		respBody, bodyErr := ioutil.ReadAll(res.Body)
		if err != nil || bodyErr != nil || res.StatusCode >= 300 {
			log.Printf("[WARNING] Failed getting org STATS body: %s. Resp: %d. Body err: %s", err, res.StatusCode, bodyErr)

			// Init the org stats if it doesn't exist
			if res.StatusCode == 404 {
				orgStatistics.OrgId = orgId
				orgStatistics = HandleIncrement(dataType, orgStatistics, dbDumpInterval)
				orgStatistics = handleDailyCacheUpdate(orgStatistics)

				marshalledData, err := json.Marshal(orgStatistics)
				if err != nil {
					log.Printf("[ERROR] Failed marshalling org STATS body: %s", err)
				} else {
					err := indexEs(ctx, nameKey, id, marshalledData)
					if err != nil {
						log.Printf("[ERROR] Failed indexing org STATS body: %s", err)
					} else {
						log.Printf("[DEBUG] Indexed org STATS body for %s", orgId)
					}
				}
			}

			return err
		}

		orgStatsWrapper := &ExecutionInfoWrapper{}
		err = json.Unmarshal(respBody, &orgStatsWrapper)
		if err != nil {
			log.Printf("[ERROR] Failed unmarshalling org STATS body: %s", err)
			return err
		}

		orgStatistics = &orgStatsWrapper.Source
		if orgStatistics.OrgName == "" || orgStatistics.OrgName == orgStatistics.OrgId {
			org, err := GetOrg(ctx, orgId)
			if err == nil {
				orgStatistics.OrgName = org.Name
			}

			orgStatistics.OrgId = orgId
		}

		orgStatistics = HandleIncrement(dataType, orgStatistics, dbDumpInterval)
		orgStatistics = handleDailyCacheUpdate(orgStatistics)

		// Set the data back in the database
		marshalledData, err := json.Marshal(orgStatistics)
		if err != nil {
			log.Printf("[ERROR] Failed marshalling org STATS body (2): %s", err)
			return err
		}

		err = indexEs(ctx, nameKey, id, marshalledData)
		if err != nil {
			log.Printf("[ERROR] Failed indexing org STATS body (2): %s", err)
		}

		//log.Printf("[DEBUG] Incremented org stats for %s", orgId)
	} else {
		tx, err := project.Dbclient.NewTransaction(ctx)
		if err != nil {
			log.Printf("[WARNING] Error in cache dump: %s", err)
			return err
		}

		key := datastore.NameKey(nameKey, strings.ToLower(orgId), nil)
		if err := tx.Get(key, orgStatistics); err != nil {

			if strings.Contains(fmt.Sprintf("%s", err), "no such entity") {
				log.Printf("[DEBUG] Continuing by creating entity for org %s", orgId)
			} else {
				if !strings.Contains(fmt.Sprintf("%s", err), "cannot load field") {
					log.Printf("[ERROR] Failed getting stats in increment: %s", err)
					tx.Rollback()
					return err
				}
			}
		}

		if orgStatistics.OrgName == "" || orgStatistics.OrgName == orgStatistics.OrgId {
			org, err := GetOrg(ctx, orgId)
			if err == nil {
				orgStatistics.OrgName = org.Name
			}

			orgStatistics.OrgId = orgId
		}

		orgStatistics = HandleIncrement(dataType, orgStatistics, dbDumpInterval)
		orgStatistics = handleDailyCacheUpdate(orgStatistics)
		// Transaction control
		if _, err := tx.Put(key, orgStatistics); err != nil {
			log.Printf("[WARNING] Failed setting stats: %s", err)
			tx.Rollback()
			return err
		}

		if _, err = tx.Commit(); err != nil {
			log.Printf("[ERROR] Failed commiting stats: %s", err)
			if strings.Contains(fmt.Sprintf("%s", err), "concurrent transaction") {
				concurrentTxn = true
				errMsg = fmt.Sprintf("%s", err)
			}
		}
	}

	// Could use cache for everything, really
	if project.CacheDb {
		cacheKey := fmt.Sprintf("%s_%s", nameKey, orgId)
		data, err := json.Marshal(orgStatistics)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling in set org stats: %s", err)
			return err
		}

		err = SetCache(ctx, cacheKey, data, 30)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for org stats '%s': %s", cacheKey, err)
		}
	}

	if concurrentTxn {
		return errors.New(errMsg)
	}

	return nil
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

	if len(orgId) != 36 {
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
		//log.Printf("[DEBUG] Incrementing cache for %s with amount %d", key, incrementAmount)
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
			go SetCache(ctx, key, []byte(fmt.Sprintf("%x", 0)), 86400)
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
	timeYesterday := time.Now().AddDate(0, 0, -1)
	timeYesterdayFormatted := timeYesterday.Format("2006-12-02")

	for _, day := range executionInfo.DailyStatistics {

		// Check if the day.Date is the same as yesterday and return if it is
		if day.Date.Format("2006-12-02") == timeYesterdayFormatted {
			//log.Printf("[DEBUG] Daily stats already updated for %s. Data: %#v", day.Date, day)
			return executionInfo
		}
	}

	log.Printf("[DEBUG] Daily stats not updated for %s in org %s today. Only have %d stats so far - running update.", timeYesterday, executionInfo.OrgId, len(executionInfo.DailyStatistics))
	// If we get here, we need to update the daily stats
	newDay := DailyStatistics{
		Date:                       timeYesterday,
		AppExecutions:              executionInfo.DailyAppExecutions,
		ChildAppExecutions:         executionInfo.DailyChildAppExecutions,
		AppExecutionsFailed:        executionInfo.DailyAppExecutionsFailed,
		SubflowExecutions:          executionInfo.DailySubflowExecutions,
		WorkflowExecutions:         executionInfo.DailyWorkflowExecutions,
		WorkflowExecutionsFinished: executionInfo.DailyWorkflowExecutionsFinished,
		WorkflowExecutionsFailed:   executionInfo.DailyWorkflowExecutionsFailed,
		OrgSyncActions:             executionInfo.DailyOrgSyncActions,
		CloudExecutions:            executionInfo.DailyCloudExecutions,
		OnpremExecutions:           executionInfo.DailyOnpremExecutions,
		AIUsage:                    executionInfo.DailyAIUsage,

		ApiUsage: executionInfo.DailyApiUsage,

		Additions: executionInfo.Additions,
	}

	executionInfo.DailyStatistics = append(executionInfo.DailyStatistics, newDay)

	// Cleaning up old stuff we don't use for now
	executionInfo.HourlyAppExecutions = 0
	executionInfo.HourlyChildAppExecutions = 0
	executionInfo.HourlyAppExecutionsFailed = 0
	executionInfo.HourlySubflowExecutions = 0
	executionInfo.HourlyWorkflowExecutions = 0
	executionInfo.HourlyWorkflowExecutionsFinished = 0
	executionInfo.HourlyWorkflowExecutionsFailed = 0
	executionInfo.HourlyOrgSyncActions = 0
	executionInfo.HourlyCloudExecutions = 0
	executionInfo.HourlyOnpremExecutions = 0

	// Reset daily
	executionInfo.DailyAppExecutions = 0
	executionInfo.DailyChildAppExecutions = 0
	executionInfo.DailyAppExecutionsFailed = 0
	executionInfo.DailySubflowExecutions = 0
	executionInfo.DailyWorkflowExecutions = 0
	executionInfo.DailyWorkflowExecutionsFinished = 0
	executionInfo.DailyWorkflowExecutionsFailed = 0
	executionInfo.DailyOrgSyncActions = 0
	executionInfo.DailyCloudExecutions = 0
	executionInfo.DailyOnpremExecutions = 0
	executionInfo.DailyApiUsage = 0
	executionInfo.DailyAIUsage = 0

	// Weekly
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

	// Cleans up "random" stats as well
	for additionIndex, _ := range executionInfo.Additions {
		executionInfo.Additions[additionIndex].Value = 0
		executionInfo.Additions[additionIndex].DailyValue = 0
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
		executionInfo.MonthlyWorkflowExecutionsFailed = 0
		executionInfo.MonthlyOrgSyncActions = 0
		executionInfo.MonthlyCloudExecutions = 0
		executionInfo.MonthlyOnpremExecutions = 0
		executionInfo.MonthlyApiUsage = 0
		executionInfo.MonthlyAIUsage = 0
		executionInfo.LastMonthlyResetMonth = currentMonth
		executionInfo.LastUsageAlertThreshold = 0
	}

	return executionInfo
}

func HandleIncrement(dataType string, orgStatistics *ExecutionInfo, increment uint) *ExecutionInfo {

	appendCustom := false

	if dataType == "childorg_app_executions" {
		orgStatistics.TotalChildAppExecutions += int64(increment)
		orgStatistics.MonthlyChildAppExecutions += int64(increment)
		orgStatistics.WeeklyChildAppExecutions += int64(increment)
		orgStatistics.DailyChildAppExecutions += int64(increment)
		orgStatistics.HourlyChildAppExecutions += int64(increment)

	} else if dataType == "app_executions" || strings.HasPrefix(dataType, "app_executions") {
		orgStatistics.TotalAppExecutions += int64(increment)
		orgStatistics.MonthlyAppExecutions += int64(increment)
		orgStatistics.WeeklyAppExecutions += int64(increment)
		orgStatistics.DailyAppExecutions += int64(increment)
		orgStatistics.HourlyAppExecutions += int64(increment)

		if dataType != "app_executions" {
			appendCustom = true
		}

	} else if dataType == "workflow_executions" {
		orgStatistics.TotalWorkflowExecutions += int64(increment)
		orgStatistics.MonthlyWorkflowExecutions += int64(increment)
		orgStatistics.WeeklyWorkflowExecutions += int64(increment)
		orgStatistics.DailyWorkflowExecutions += int64(increment)
		orgStatistics.HourlyWorkflowExecutions += int64(increment)

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
	} else {
		//log.Printf("\n\n[ERROR] Unknown data type in stats increment for org %s: %s. Appending to custom list.\n\n", orgStatistics.OrgId, dataType)
		appendCustom = true
	}

	if appendCustom {
		//log.Printf("[DEBUG] Appending custom data type %s for org %s", dataType, orgStatistics.OrgId)
		dataType = strings.ToLower(strings.Replace(dataType, " ", "_", -1))

		found := false
		for additionIndex, addition := range orgStatistics.Additions {
			if addition.Key != dataType {
				continue
			}

			found = true
			amount := int64(increment)

			orgStatistics.Additions[additionIndex].Value += amount
			orgStatistics.Additions[additionIndex].DailyValue += amount

			break
		}

		if !found {
			orgStatistics.Additions = append(orgStatistics.Additions, AdditionalUseConfig{
				Key:        dataType,
				Value:      int64(increment),
				DailyValue: int64(increment),

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

	for index, AlertThreshold := range org.Billing.AlertThreshold {

		totalAppExecutions := orgStatistics.MonthlyAppExecutions + orgStatistics.MonthlyChildAppExecutions

		if int64(AlertThreshold.Count) < totalAppExecutions && AlertThreshold.Email_send == false {

			for _, user := range org.Users {
				if user.Role == "admin" {
					// var BccAddress []string
					// if int64(AlertThreshold.Count) >= 5000 || int64(AlertThreshold.Count) >= 10000 && AlertThreshold.Email_send == false {
					// 	BccAddress = []string{"support@shuffler.io", "jay@shuffler.io"}
					// }
					Subject := fmt.Sprintf("[Shuffle]: You've reached the app-runs threshold limit for your account %s", org.Name)
					// mailbody := Mailcheck{
					// 	Targets: []string{user.Username},
					// 	Subject: "You have reached the threshold limit of app executions",
					// 	Body:    fmt.Sprintf("You have reached the threshold limit of %v percent Or %v app executions run. Please login to shuffle and check it.", AlertThreshold.Percentage, AlertThreshold.Count),
					// }

					AppRunsPercentage := float64(totalAppExecutions) / float64(org.SyncFeatures.AppExecutions.Limit) * 100

					substitutions := map[string]interface{}{
						"app_runs_usage":            totalAppExecutions,
						"app_runs_limit":            org.SyncFeatures.AppExecutions.Limit,
						"app_runs_usage_percentage": int64(AppRunsPercentage),
						"org_name":                  org.Name,
						"org_id":                    org.Id,
					}

					err = sendMailSendgridV2(
						[]string{user.Username, "support@shuffler.io", "jay@shuffler.io"},
						Subject,
						substitutions,
						false,
						"d-3678d48b2b7144feb4b0b4cff7045016",
					)
					// err = sendMailSendgrid(mailbody.Targets, mailbody.Subject, mailbody.Body, false, BccAddress)
					if err != nil {
						log.Printf("[ERROR] Failed sending alert mail in increment: %s", err)
					} else {
						emailSend = true
					}
				}
			}

			if emailSend {
				org.Billing.AlertThreshold[index].Email_send = true
				err = SetOrg(ctx, *org, orgId)
				if err != nil {
					log.Printf("[ERROR] Failed setting org in increment: %s", err)
					return orgStatistics
				}
				log.Printf("[DEBUG] Successfully sent alert mail for org %s", orgId)
			}
		}
	}

	// hard limit aleart
	if org.Billing.AppRunsHardLimit > 0 && orgStatistics.MonthlyAppExecutions > org.Billing.AppRunsHardLimit {
		// send alert to all admin in the orgs
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

		admins := []string{}

		for _, user := range org.Users {
			if user.Role == "admin" {
				admins = append(admins, user.Username)
			}
		}

		err = sendMailSendgrid(admins, subject, message, false, []string{})
		if err != nil {
			log.Printf("[ERROR] Failed sending alert email to admins of org %s (%s): %s", org.Name, org.Id, err)
		}
	}

	if dataType == "app_executions" || dataType == "childorg_app_executions" {
		log.Printf("[INFO] Checking alert thresholds for org %s with data type %s", orgStatistics.OrgId, dataType)

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
		if percentage >= 100 {
			currentThreshold = int64(100 + ((int(percentage)-100)/50)*50)
		}

		if currentThreshold >= 100 && currentThreshold > validationOrgStatistics.LastUsageAlertThreshold {
			// send mail use different subject line as it will sent only to the team
			Subject := fmt.Sprintf("[Support] Exceeded app executions for org %s (%s)", validationOrg.Name, validationOrg.Id)

			totalAppExecutions := validationOrgStatistics.MonthlyAppExecutions + validationOrgStatistics.MonthlyChildAppExecutions
			AppRunsPercentage := float64(totalAppExecutions) / float64(validationOrg.SyncFeatures.AppExecutions.Limit) * 100

			substitutions := map[string]interface{}{
				"app_runs_usage":            totalAppExecutions,
				"app_runs_limit":            validationOrg.SyncFeatures.AppExecutions.Limit,
				"app_runs_usage_percentage": int64(AppRunsPercentage),
				"org_name":                  validationOrg.Name,
				"org_id":                    validationOrg.Id,
			}

			err = sendMailSendgridV2(
				[]string{"support@shuffler.io", "jay@shuffler.io"},
				Subject,
				substitutions,
				false,
				"d-3678d48b2b7144feb4b0b4cff7045016",
			)

			if err != nil {
				log.Printf("[ERROR] Failed sending alert mail for child org in increment: %s", err)
			} else {
				log.Printf("[DEBUG] Successfully sent alert mail for child org %s to parent org %s", validationOrg.Name, validationOrg.Name)
			}

			orgStatistics.LastUsageAlertThreshold = currentThreshold
		}
	}

	return orgStatistics
}
