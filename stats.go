package shuffle

import (
	"fmt"
	"log"
	"sort"
	"strings"

	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/satori/go.uuid"
)

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

	log.Printf("Should get widget %s in dashboard %s", widget, dashboard)
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

	log.Printf("RESP: %#v", info)

	resp.WriteHeader(200)
	resp.Write([]byte(fmt.Sprintf(`{"success": true, "key": "%s", "value": 2}`, statsKey)))
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
		if len(location) <= 4 {
			log.Printf("Path too short: %d", len(location))
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		orgId = location[4]

		if len(location) > 6 {
			statsKey = location[6]
		}
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in get stats: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
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
