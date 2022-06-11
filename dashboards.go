package shuffle

import (
	"fmt"
	"log"
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

	log.Printf("SHould get widget %s in dashboard %s", widget, dashboard)
	id := uuid.NewV4().String()

	// Returning some static info for now
	returnData := Widget{
		Success:   true,
		Id:        id,
		Title:     widget,
		Dashboard: dashboard,
		Data: []WidgetPoint{
			WidgetPoint{
				Key: "Wut",
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
		ctx := getContext(request)
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
