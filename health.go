package shuffle

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
)

type appConfig struct {
	Success bool   `json:"success"`
	OpenAPI string `json:"openapi"`
	App     string `json:"app"`
}

type genericResp struct {
	Success bool   `json:"success"`
	ID      string `json:"id"`
}

type executionResult struct {
	Success bool   `json:"success"`
	Result  string `json:"result"`
	ID      string `json:"id"`
}

func updateCache(workflowHealth WorkflowHealth) {
	cacheKey := fmt.Sprintf("ops-health-check")
	ctx := context.Background()

 	if project.CacheDb {
		platformHealthCheck := HealthCheck{}
		platformHealthCheck.Updated = time.Now().Unix()
		platformHealthCheck.Workflows = workflowHealth

		platformData, err := json.Marshal(platformHealthCheck)

		// Set cache
		err = SetCache(ctx, cacheKey, platformData, 15)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache ops health: %s", err)
		}		
	}
}

func base64StringToString(base64String string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(base64String)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

func RunOpsAppHealthCheck() (AppHealth, error) {
	log.Printf("[DEBUG] Running app health check")
	appHealth := AppHealth{
		Create:      false,
		Run:         false,
		Delete:      false,
		Read:        false,
		Validate:    false,
		AppId:       "",
		Result:      "",
		ExecutionID: "",
	}

	// 1. Get App
	baseURL := os.Getenv("SHUFFLE_CLOUDRUN_URL")
	// if len(baseURL) == 0 {
	baseURL = "https://shuffler.io"
	// }

	url := baseURL + "/api/v1/apps/edaa73d40238ee60874a853dc3ccaa6f/config"
	log.Printf("[DEBUG] Getting app with URL: %s", url)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Printf("[ERROR] Failed creating HTTP request: %s", err)
		return appHealth, err
	}

	// send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[ERROR] Failed sending HTTP request: %s", err)
		return appHealth, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Printf("[ERROR] Failed getting health check app: %s. The status code was: %d", err, resp.StatusCode)
		return appHealth, err
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[ERROR] Failed readin while getting HTTP response body: %s", err)
		return appHealth, err
	}

	// Unmarshal the JSON data into a Workflow instance
	app := appConfig{}
	err = json.Unmarshal([]byte(respBody), &app)
	if err != nil {
		log.Printf("[ERROR] Failed unmarshalling JSON data: %s", err)
		return appHealth, err
	}

	if app.Success == false {
		log.Printf("[ERROR] Reading returned false for app health check: %s", err)
		return appHealth, err
	}

	appHealth.Read = true

	// 2. Create App
	// 2.1 convert openapi base64 string to json
	openapiString, err := base64StringToString(app.OpenAPI)
	if err != nil {
		log.Printf("[ERROR] Failed converting openapi base64 to string in app health check: %s", err)
		return appHealth, err
	}

	// 2.2 call /api/v1/validate_openapi
	// with request body openapiString
	url = baseURL + "/api/v1/validate_openapi"

	req, err = http.NewRequest("POST", url, bytes.NewBuffer([]byte(openapiString)))
	if err != nil {
		log.Printf("[ERROR] Failed creating HTTP for app validate request: %s", err)
		return appHealth, err
	}

	// set the headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+os.Getenv("SHUFFLE_OPS_DASHBOARD_APIKEY"))

	// send the request
	client = &http.Client{}
	resp, err = client.Do(req)
	if err != nil {
		log.Printf("[ERROR] Failed sending the app validate HTTP request: %s", err)
		return appHealth, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Printf("[ERROR] Failed validating app in app health check: %s. The status code was: %d", err, resp.StatusCode)
		return appHealth, err
	}

	respBody, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[ERROR] Failed reading HTTP for app validate response body: %s", err)
		return appHealth, err
	}

	// Unmarshal the JSON data into a Workflow instance
	var validateResponse genericResp

	err = json.Unmarshal(respBody, &validateResponse)
	if err != nil {
		log.Printf("[ERROR] Failed unmarshalling JSON data: %s", err)
		return appHealth, err
	}

	if validateResponse.Success == false {
		log.Printf("[ERROR] Validating returned false for app health check: %s", err)
		return appHealth, err
	}

	id := validateResponse.ID
	appHealth.Validate = true

	log.Printf("[DEBUG] New app id: %s", id)

	// 2.3 call /api/v1/verify_openapi POST
	// with request body openapiString
	// replace edaa73d40238ee60874a853dc3ccaa6f with id from above
	newOpenapiString := strings.Replace(openapiString, "edaa73d40238ee60874a853dc3ccaa6f", id, -1)
	url = baseURL + "/api/v1/verify_openapi"

	log.Printf("[DEBUG] New openapi string: %s", newOpenapiString)

	req, err = http.NewRequest("POST", url, bytes.NewBuffer([]byte(newOpenapiString)))
	if err != nil {
		log.Printf("[ERROR] Failed creating app check HTTP for app verify request: %s", err)
		return appHealth, err
	}

	// set the headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+os.Getenv("SHUFFLE_OPS_DASHBOARD_APIKEY"))

	// send the request
	client = &http.Client{}
	resp, err = client.Do(req)
	if err != nil {
		log.Printf("[ERROR] Failed sending health check app verify HTTP request: %s", err)
		return appHealth, err
	}

	respBody, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[ERROR] Failed reading HTTP for app verify response body: %s", err)
		return appHealth, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Printf("[ERROR] Failed verifying app in app health check: %s.", err)
		log.Printf("[ERROR] The status code was: %d with response %s", resp.StatusCode, respBody)
		return appHealth, err
	}

	// Unmarshal the JSON data into a Workflow instance
	var validatedResp genericResp

	err = json.Unmarshal(respBody, &validatedResp)
	if err != nil {
		log.Printf("[ERROR] Failed unmarshalling JSON data: %s", err)
		return appHealth, err
	}

	// Verify that the app was created
	// Make a request to /api/v1/apps/<id>/config
	url = baseURL + "/api/v1/apps/" + id + "/config"

	log.Printf("[DEBUG] Getting app with URL: %s", url)

	req, err = http.NewRequest("GET", url, nil)
	if err != nil {
		log.Printf("[ERROR] Failed creating HTTP for app read request: %s", err)
		return appHealth, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+os.Getenv("SHUFFLE_OPS_DASHBOARD_APIKEY"))

	// send the request
	client = &http.Client{}
	resp, err = client.Do(req)
	if err != nil {
		log.Printf("[ERROR] Failed sending health check app read HTTP request: %s", err)
		return appHealth, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Printf("[ERROR] Failed reading app in app health check: %s. The status code was: %d", err, resp.StatusCode)
		log.Printf("[ERROR] The response body was: %s", respBody)
		return appHealth, err
	}

	appHealth.Create = true
	id = validatedResp.ID

	// 3. Run App
	// 3.1 call /api/v1/apps/<id>/execute POST
	url = baseURL + "/api/v1/apps/" + id + "/execute"

	log.Printf("[DEBUG] Running app with URL %s", url)

	var executeBody WorkflowAppAction

	appHealth.AppId = id
	executeBody.AppID = id
	executeBody.Name = "get_apps"
	executeBody.Parameters = []WorkflowAppActionParameter{
		{
			Name:  "apikey",
			Value: os.Getenv("SHUFFLE_OPS_DASHBOARD_APIKEY"),
		},
		{
			Name:          "url",
			Value:         baseURL,
			Configuration: true,
		},
	}

	executeBodyJSON, err := json.Marshal(executeBody)
	if err != nil {
		log.Printf("[ERROR] Failed marshalling app run JSON data: %s", err)
		return appHealth, err
	}

	req, err = http.NewRequest("POST", url, bytes.NewBuffer(executeBodyJSON))
	if err != nil {
		log.Printf("[ERROR] Failed creating HTTP for app run request: %s", err)
		return appHealth, err
	}

	// set the headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+os.Getenv("SHUFFLE_OPS_DASHBOARD_APIKEY"))

	// send the request
	client = &http.Client{}
	resp, err = client.Do(req)

	if err != nil {
		log.Printf("[ERROR] Failed sending health check app run HTTP request: %s", err)
		return appHealth, err
	}

	respBody, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[ERROR] Failed reading HTTP for app run response body: %s", err)
		return appHealth, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Printf("[ERROR] Failed running app in app health check: %s. The status code was: %d", err, resp.StatusCode)
		log.Printf("[ERROR] The response body was: %s", respBody)
		return appHealth, err
	}

	// Unmarshal the JSON data into a Workflow instance
	var runResponse executionResult

	err = json.Unmarshal(respBody, &runResponse)

	if err != nil {
		log.Printf("[ERROR] Failed unmarshalling generic run JSON data: %s", err)
		return appHealth, err
	}

	if runResponse.Success == false {
		log.Printf("[ERROR] Running returned false for app health check: %s", err)
		return appHealth, err
	}

	appHealth.Result = runResponse.Result
	appHealth.ExecutionID = runResponse.ID
	appHealth.Run = true

	// 4. Delete App
	// 4.1 call /api/v1/apps/<id> DELETE
	url = baseURL + "/api/v1/apps/" + id

	log.Printf("[DEBUG] Deleting app with URL %s", url)

	req, err = http.NewRequest("DELETE", url, nil)
	if err != nil {
		log.Printf("[ERROR] Failed creating HTTP for app delete request: %s", err)
		return appHealth, err
	}

	// set the headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+os.Getenv("SHUFFLE_OPS_DASHBOARD_APIKEY"))

	// send the request
	client = &http.Client{}
	resp, err = client.Do(req)

	if err != nil {
		log.Printf("[ERROR] Failed sending health check app delete HTTP request: %s", err)
		return appHealth, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Printf("[ERROR] Failed deleting app in app health check: %s. The status code was: %d", err, resp.StatusCode)
		return appHealth, err
	}

	appHealth.Delete = true

	return appHealth, nil
}

func RunOpsHealthCheck(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	log.Printf("cacheDb %#v", project.CacheDb)
	// Check cache if health check was run in last 5 minutes
	// If yes, return cached result, else run health check
	ctx := GetContext(request)
	platformHealth := HealthCheck{}
	cacheKey := fmt.Sprintf("ops-health-check")
	if project.CacheDb {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			//log.Printf("CACHEDATA: %s", cacheData)
			err = json.Unmarshal(cacheData, &platformHealth)
			if err == nil {
				// FIXME: Check if last updated is less than 5 minutes with platformHealth.Edited in unix time
				// If yes, return cached result, else run health check
				log.Printf("Platform health returned: %#v", platformHealth)
				marshalledData, err := json.Marshal(platformHealth)
				if err == nil {
					resp.WriteHeader(200)
					resp.Write(marshalledData)
					return
				} else {
					log.Printf("[ERROR] Failed marshalling cached platform health data: %s", err)
				}
			}
		} else {
			log.Print("[WARNING] Failed getting cache ops health on first try: %s", err)
		}
	}

	// Use channel for getting RunOpsWorkflow function results
	workflowHealthChannel := make(chan WorkflowHealth)
	// appHealthChannel := make(chan AppHealth)
	go func() {
		workflowHealth, err := RunOpsWorkflow()
		if err != nil {
			log.Printf("[ERROR] Failed running workflow health check: %s", err)
			workflowHealthChannel <- workflowHealth
			return
		}
		workflowHealthChannel <- workflowHealth
	}()

	// go func() {
	// 	appHealth, err := RunOpsAppHealthCheck()
	// 	if err != nil {
	// 		log.Printf("[ERROR] Failed running app health check: %s", err)
	// 		appHealthChannel <- appHealth
	// 		return
	// 	}
	// 	appHealthChannel <- appHealth
	// }()

	// Use channel for getting RunOpsWorkflow function results
	// platformHealth.Apps = <-appHealthChannel
	platformHealth.Workflows = <-workflowHealthChannel

	platformHealth.Success = true
	platformHealth.Updated = time.Now().Unix()

	platformData, err := json.Marshal(platformHealth)
	if err != nil {
		log.Printf("[ERROR] Failed marshalling platform health data: %s", err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false, "reason": "Failed JSON parsing platform health. Contact support@shuffler.io"}`))
		return
	}

	if project.CacheDb {
		// Set cache
		err = SetCache(ctx, cacheKey, platformData, 15)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache ops health at last: %s", err)
		}
	}

	resp.WriteHeader(200)
	resp.Write(platformData)
}

func RunOpsWorkflow() (WorkflowHealth, error) {
	// run workflow with id 602c7cf5-500e-4bd1-8a97-aa5bc8a554e6
	ctx := context.Background()

	workflowHealth := WorkflowHealth{
		Create:      false,
		Run:         false,
		RunFinished: false,
		Delete:      false,
		RunStatus:   "",
		ExecutionId: "",
	}

	// 1. Get workflow
	opsWorkflowID, err := InitOpsWorkflow()
	if err != nil {
		log.Printf("[ERROR] Failed creating Health check workflow: %s", err)
		return workflowHealth, err
	}

	workflowPtr, err := GetWorkflow(ctx, opsWorkflowID)
	if err != nil {
		log.Printf("[ERROR] Failed getting Health check workflow: %s", err)
		log.Printf("[DEBUG] Creating health check workflow")
		return workflowHealth, err
	}

	workflowHealth.Create = true
	updateCache(workflowHealth)

	workflow := *workflowPtr

	log.Printf("[DEBUG] Running health check workflow")

	// 2. Run workflow
	id := workflow.ID
	orgId := os.Getenv("SHUFFLE_OPS_DASHBOARD_ORG")
	_ = id
	_ = orgId

	workflowJson, _ := json.Marshal(workflow)
	baseUrl := os.Getenv("SHUFFLE_CLOUDRUN_URL")
	if len(baseUrl) == 0 {
		baseUrl = "https://shuffler.io"
	}

	// prepare the request
	url := baseUrl + "/api/v1/workflows/" + id + "/execute"
	log.Printf("[DEBUG] Running health check workflow with URL: %s", url)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(workflowJson))
	if err != nil {
		log.Printf("[ERROR] Failed creating HTTP request: %s", err)
		return workflowHealth, err
	}

	// set the headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+os.Getenv("SHUFFLE_OPS_DASHBOARD_APIKEY"))

	startId := "98713d6a-dd6b-4bd6-a11c-9778b80f2a28"
	body := map[string]string{"execution_argument": "", "start": startId}

	// convert the body to JSON
	bodyJson, err := json.Marshal(body)
	if err != nil {
		log.Printf("[ERROR] Failed marshalling body: %s", err)
		return workflowHealth, err
	}

	// set the body
	req.Body = ioutil.NopCloser(bytes.NewBuffer(bodyJson))

	// send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[ERROR] Failed sending health check HTTP request: %s", err)
		return workflowHealth, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Printf("[ERROR] Failed running health check workflow: %s. The status code is: %d", err, resp.StatusCode)
		// print the response body
		respBodyErr, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Printf("[ERROR] Failed reading health check HTTP response body: %s", err)
		} else {
			log.Printf("[ERROR] Health check running Workflow Response: %s", respBodyErr)
		}

		return workflowHealth, err
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[ERROR] Failed reading HTTP response body: %s", err)
		return workflowHealth, err
	}

	// Unmarshal the JSON data into a Workflow instance
	var execution WorkflowExecution
	err = json.Unmarshal(respBody, &execution)

	workflowHealth.Run = true
	workflowHealth.ExecutionId = execution.ExecutionId

	updateCache(workflowHealth)

	// 3. Check if workflow ran successfully
	// ping /api/v1/streams/results/<execution_id> while workflowHealth.RunFinished is false
	// if workflowHealth.RunFinished is true, return workflowHealth
	for workflowHealth.RunFinished == false {
		url := baseUrl + "/api/v1/streams/results"
		req, err := http.NewRequest("POST", url, nil)
		if err != nil {
			log.Printf("[ERROR] Failed creating HTTP request: %s", err)
			return workflowHealth, err
		}

		// set the headers
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+os.Getenv("SHUFFLE_OPS_DASHBOARD_APIKEY"))

		// convert the body to JSON
		reqBody := map[string]string{"execution_id": execution.ExecutionId, "authorization": os.Getenv("SHUFFLE_OPS_DASHBOARD_APIKEY")}
		reqBodyJson, err := json.Marshal(reqBody)

		// set the body
		req.Body = ioutil.NopCloser(bytes.NewBuffer(reqBodyJson))

		// send the request
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("[ERROR] Failed sending HTTP request: %s", err)
			return workflowHealth, err
		}

		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			log.Printf("[ERROR] Failed checking results for the workflow: %s. The status code was: %d", err, resp.StatusCode)
			return workflowHealth, err
		}

		respBody, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Printf("[ERROR] Failed reading HTTP response body: %s", err)
			return workflowHealth, err
		}

		// Unmarshal the JSON data into a Workflow instance
		var executionResults WorkflowExecution
		err = json.Unmarshal(respBody, &executionResults)

		if err != nil {
			log.Printf("[ERROR] Failed unmarshalling JSON data: %s", err)
			return workflowHealth, err
		}

		if executionResults.Status != "EXECUTING" {
			workflowHealth.RunFinished = true
			workflowHealth.RunStatus = executionResults.Status
		}

		updateCache(workflowHealth)

		log.Printf("[DEBUG] Workflow Health execution Result Status: %#v", executionResults.Status)
	}

	// 4. Delete workflow
	// make a DELETE request to https://shuffler.io/api/v1/workflows/<workflow_id>
	url = baseUrl + "/api/v1/workflows/" + id
	log.Printf("[DEBUG] Deleting workflow with id: %s", id)

	req, err = http.NewRequest("DELETE", url, nil)
	if err != nil {
		log.Printf("[ERROR] Failed creating HTTP request: %s", err)
		return workflowHealth, err
	}

	// set the headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+os.Getenv("SHUFFLE_OPS_DASHBOARD_APIKEY"))

	// send the request
	client = &http.Client{}
	resp, err = client.Do(req)
	if err != nil {
		log.Printf("[ERROR] Failed deleting the health check workflow with HTTP request: %s", err)
		return workflowHealth, err
	}

	if resp.StatusCode != 200 {
		log.Printf("[ERROR] Failed deleting the health check workflow: %s. The status code was: %d", err, resp.StatusCode)
		return workflowHealth, err
	}

	defer resp.Body.Close()

	workflowHealth.Delete = true

	return workflowHealth, nil
}

func InitOpsWorkflow() (string, error) {
	opsDashboardApikey := os.Getenv("SHUFFLE_OPS_DASHBOARD_APIKEY")
	if len(opsDashboardApikey) == 0 {
		log.Printf("[WARNING] Ops dashboard api key not set. Not setting up ops workflow")
		return "", errors.New("Ops dashboard api key not set")

	}

	opsDashboardOrgId := os.Getenv("SHUFFLE_OPS_DASHBOARD_ORG")
	if len(opsDashboardOrgId) == 0 {
		log.Printf("[WARNING] Ops dashboard org not set. Not setting up ops workflow")
		return "", errors.New("Ops dashboard org not set")
	}

	// verify if org with id opsDashboardOrg exists
	ctx := context.Background()
	opsDashboardOrg, err := GetOrg(ctx, opsDashboardOrgId)
	if err != nil {
		log.Printf("[ERROR] Ops dashboard org not found. Not setting up ops workflow")
		return "", err
	}

	user, err := GetApikey(ctx, opsDashboardApikey)
	if err != nil {
		log.Printf("[ERROR] Error in finding user: %s", err)
		return "", err
	}

	if len(user.Id) == 0 && len(user.Username) == 0 {
		fmt.Println("[ERROR] Ops dashboard user not found. Not setting up ops workflow")
		return "", errors.New("Ops dashboard user not found")
	}

	if user.Role != "admin" {
		log.Printf("[WARNING] Ops dashboard user not admin. Not setting up ops workflow")
		return "", errors.New("Ops dashboard user not admin")
	}

	// make a GET request to https://shuffler.io/api/v1/workflows/602c7cf5-500e-4bd1-8a97-aa5bc8a554e6
	// to get the workflow
	url := "https://shuffler.io/api/v1/workflows/602c7cf5-500e-4bd1-8a97-aa5bc8a554e6"

	// Create a new HTTP GET request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("[ERROR] creating HTTP request:", err)
		return "", errors.New("Error creating HTTP request: " + err.Error())
	}

	// Send the HTTP request using the default HTTP client
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println("[ERROR] sending Ops fetch app HTTP request:", err)
		return "", errors.New("Error sending HTTP request: " + err.Error())
	}

	defer resp.Body.Close()

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("[ERROR] reading HTTP response body:", err)
		return "", errors.New("Error reading HTTP App response response body: " + err.Error())
	}

	// Unmarshal the JSON data into a Workflow instance
	var workflowData Workflow
	err = json.Unmarshal(body, &workflowData)
	if err != nil {
		fmt.Println("[ERROR] unmarshalling Ops workflowData JSON data:", err)
		return "", errors.New("Error unmarshalling JSON data: " + err.Error())
	}

	variables := workflowData.WorkflowVariables
	for _, variable := range variables {
		if variable.Name == "apikey" {
			variable.Value = opsDashboardApikey
		} else if variable.Name == "cachekey" {
			variable.Value = "1234"
		}
	}

	// fix workflow org
	workflowData.OrgId = opsDashboardOrg.Id
	workflowData.Owner = user.Id
	workflowData.Public = false
	workflowData.Status = ""
	workflowData.Name = "Ops Dashboard Workflow"

	var actions []Action
	var blacklisted = []string{"Date_to_epoch", "input_data", "Compare_timestamps", "Get_current_timestamp"}

	for actionIndex, _ := range workflowData.Actions {
		action := workflowData.Actions[actionIndex]

		// capitalise the first letter of the environment
		if action.Environment != "Cloud" {
			action.Environment = "Cloud"
		}

		workflowData.Actions[actionIndex] = action
		if ArrayContains(blacklisted, action.Label) {
			// dates keep failing in opensearch
			// this is a grander issue, but for now, we'll just skip these actions
			log.Printf("[WARNING] Skipping action %s", action.Label)
			continue
		}

		actions = append(actions, action)
	}

	workflowData.Actions = actions

	workflowData.ExecutingOrg = OrgMini{
		Id:    opsDashboardOrg.Id,
		Name:  opsDashboardOrg.Name,
		Users: []UserMini{},
	}

	workflowData.WorkflowVariables = variables

	uniqueCheck := false
	for uniqueCheck == false {
		// generate a random UUID for the workflow
		randomUUID := uuid.New().String()
		log.Printf("[DEBUG] Random UUID generated for Ops dashboard: %s", randomUUID)

		// check if workflow with id randomUUID exists
		_, err = GetWorkflow(ctx, randomUUID)
		if err != nil {
			uniqueCheck = true
			workflowData.ID = randomUUID
		}
	}

	// Save the workflow
	err = SetWorkflow(ctx, workflowData, workflowData.ID)

	if err != nil {
		fmt.Println("[ERROR] saving ops dashboard workflow:", err)
		return "", errors.New("Error saving ops dashboard workflow: " + err.Error())
	}

	fmt.Println("[INFO] Ops dashboard workflow saved successfully with ID: workflowData.ID")
	return workflowData.ID, nil
}
