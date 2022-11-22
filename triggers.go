package shuffle

import (
	// "bytes"
	// "context"
	"errors"
	"fmt"
	// "gopkg.in/yaml.v3"
	// "io"
	"io/ioutil"
	"log"
	"net/http"
	// "net/url"
	"os"
	//"os/exec"
	// "regexp"
	// "strconv"
	"strings"
	// "time"

	// "encoding/base32"
	// "encoding/base64"
	// "encoding/binary"
	// "encoding/hex"
	"encoding/json"
	// "encoding/xml"

	// "crypto/aes"
	// "crypto/cipher"
	// "crypto/hmac"
	// "crypto/md5"
	// "crypto/rand"
	// "crypto/sha1"

	// "github.com/bradfitz/slice"
	// qrcode "github.com/skip2/go-qrcode"

	// "github.com/frikky/kin-openapi/openapi2"
	// "github.com/frikky/kin-openapi/openapi2conv"
	// "github.com/frikky/kin-openapi/openapi3"

	// "github.com/satori/go.uuid"
	// "google.golang.org/appengine"
)

func HandleGetHook(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in get hook: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	location := strings.Split(request.URL.String(), "/")

	var workflowId string
	if location[1] == "api" {
		if len(location) <= 4 {
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		workflowId = location[4]
	}

	if len(workflowId) != 36 {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "message": "ID not valid"}`))
		return
	}

	ctx := GetContext(request)
	hook, err := GetHook(ctx, workflowId)
	if err != nil {
		log.Printf("[WARNING] Failed getting hook %s (get hook): %s", workflowId, err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if user.Id != hook.Owner && user.Role != "scheduler" {
		log.Printf("Wrong user (%s) for hook %s", user.Username, hook.Id)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	b, err := json.Marshal(hook)
	if err != nil {
		log.Printf("Failed marshalling: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	resp.WriteHeader(200)
	resp.Write([]byte(b))
	return
}

// Starts a new webhook
func HandleNewHook(resp http.ResponseWriter, request *http.Request) {
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
		log.Printf("[WARNING] Org-reader doesn't have access to make new hook: %s (%s)", user.Username, user.Id)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Read only user"}`))
		return
	}

	type requestData struct {
		Type           string `json:"type"`
		Description    string `json:"description"`
		Id             string `json:"id"`
		Name           string `json:"name"`
		Workflow       string `json:"workflow"`
		Start          string `json:"start"`
		Environment    string `json:"environment"`
		Auth           string `json:"auth"`
		CustomResponse string `json:"custom_response"`
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Printf("[WARNING] Body data error in webhook set: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

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

	if len(os.Getenv("SHUFFLE_CLOUDRUN_URL")) > 0 {
		baseUrl = os.Getenv("SHUFFLE_CLOUDRUN_URL")
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

	log.Printf("[INFO] Set up a new hook with ID %s and environment %s", newId, hook.Environment)
	resp.WriteHeader(200)
	resp.Write([]byte(`{"success": true}`))
}

func HandleDeleteHook(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in delete hook: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if user.Role == "org-reader" {
		log.Printf("[WARNING] Org-reader doesn't have access to delete hook: %s (%s)", user.Username, user.Id)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Read only user"}`))
		return
	}

	location := strings.Split(request.URL.String(), "/")

	var fileId string
	if location[1] == "api" {
		if len(location) <= 4 {
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		fileId = location[4]
	}

	if len(fileId) != 36 {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Workflow ID when deleting hook is not valid"}`))
		return
	}

	ctx := GetContext(request)
	hook, err := GetHook(ctx, fileId)
	if err != nil {
		log.Printf("[WARNING] Failed getting hook %s (delete): %s", fileId, err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if user.Id != hook.Owner && user.ActiveOrg.Id != hook.OrgId {
		log.Printf("[WARNING] Wrong user (%s) for workflow %s", user.Username, hook.Id)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if len(hook.Workflows) > 0 {
		//err = increaseStatisticsField(ctx, "total_workflow_triggers", hook.Workflows[0], -1, user.ActiveOrg.Id)
		//if err != nil {
		//	log.Printf("Failed to increase total workflows: %s", err)
		//}
	}

	hook.Status = "stopped"
	err = SetHook(ctx, *hook)
	if err != nil {
		log.Printf("[WARNING] Failed setting hook: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if hook.Environment == "cloud" && project.Environment != "cloud" {
		log.Printf("[INFO] Should STOP cloud webhook https://shuffler.io/api/v1/hooks/webhook_%s", hook.Id)
		org, err := GetOrg(ctx, user.ActiveOrg.Id)
		if err != nil {
			log.Printf("Failed finding org %s: %s", org.Id, err)
			return
		}

		action := CloudSyncJob{
			Type:          "webhook",
			Action:        "stop",
			OrgId:         org.Id,
			PrimaryItemId: hook.Id,
		}

		if len(hook.Workflows) > 0 {
			action.SecondaryItem = hook.Workflows[0]
		}

		err = executeCloudAction(action, org.SyncConfig.Apikey)
		if err != nil {
			log.Printf("Failed cloud action STOP execution: %s", err)
			resp.WriteHeader(401)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "%s"}`, err)))
			return
		}
		// https://shuffler.io/v1/hooks/webhook_80184973-3e82-4852-842e-0290f7f34d7c
	}

	err = DeleteKey(ctx, "hooks", fileId)
	if err != nil {
		log.Printf("[WARNING] Error deleting hook %s for %s: %s", fileId, user.Username, err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed deleting the hook."}`))
		return
	}

	log.Printf("[INFO] Successfully deleted webhook %s", fileId)
	resp.WriteHeader(200)
	resp.Write([]byte(`{"success": true, "reason": "Stopped webhook"}`))
}

func HandleGetSchedules(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in get schedules: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if user.Role != "admin" {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Admin required"}`))
		return
	}

	ctx := GetContext(request)
	schedules, err := GetAllSchedules(ctx, user.ActiveOrg.Id)
	if err != nil {
		log.Printf("[WARNING] Failed getting schedules: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Couldn't get schedules"}`))
		return
	}

	newjson, err := json.Marshal(schedules)
	if err != nil {
		log.Printf("Failed unmarshal: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed unpacking environments"}`)))
		return
	}

	//log.Printf("Existing environments: %s", string(newjson))

	resp.WriteHeader(200)
	resp.Write(newjson)
}

func SendHookResult(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in send hook results: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}
	_ = user

	location := strings.Split(request.URL.String(), "/")

	var workflowId string
	if location[1] == "api" {
		if len(location) <= 4 {
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		workflowId = location[4]
	}

	if len(workflowId) != 32 {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "message": "ID not valid"}`))
		return
	}

	ctx := GetContext(request)
	hook, err := GetHook(ctx, workflowId)
	if err != nil {
		log.Printf("[WARNING] Failed getting hook %s (send): %s", workflowId, err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Printf("Body data error: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	log.Printf("SET the hook results for %s to %s", workflowId, body)
	// FIXME - set the hook result in the DB somehow as interface{}
	// FIXME - should the hook do the transform? Hmm

	b, err := json.Marshal(hook)
	if err != nil {
		log.Printf("Failed marshalling: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	resp.WriteHeader(200)
	resp.Write([]byte(b))
	return
}

// Checks authentication string for Webhooks
func CheckHookAuth(request *http.Request, auth string) error {
	if len(auth) == 0 {
		return nil
	}

	authSplit := strings.Split(auth, "\n")
	for _, line := range authSplit {
		lineSplit := strings.Split(line, "=")
		if strings.Contains(line, ":") {
			lineSplit = strings.Split(line, "=")
		}

		if len(lineSplit) == 2 {
			validationHeader := strings.ToLower(strings.TrimSpace(lineSplit[0]))
			found := false
			for key, value := range request.Header {
				if strings.ToLower(key) == validationHeader && len(value) > 0 {
					//log.Printf("FOUND KEY %#v. Value: %s", validationHeader, value)
					if value[0] == strings.TrimSpace(lineSplit[1]) {
						found = true
						break
					}
				}
			}

			if !found {
				return errors.New(fmt.Sprintf("Missing or bad header: %#v", validationHeader))
			}

			//log.Printf("Find header %#v", validationHeader)
			//itemHeader := request.Header[validationHeader]
			//log.Printf("LINE: %s. Header: %s", line, itemHeader)
		} else {
			log.Printf("[WARNING] Bad auth line: %s. NOT checking auth.", line)
		}
	}

	//return errors.New("Bad auth!")
	return nil
}