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
	"strconv"
	"strings"
	"time"
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

func updateOpsCache(workflowHealth WorkflowHealth) {
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

func RunOpsAppHealthCheck(apiKey string, orgId string) (AppHealth, error) {
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
	req.Header.Set("Authorization", "Bearer "+apiKey)

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
	req.Header.Set("Authorization", "Bearer "+apiKey)

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
	req.Header.Set("Authorization", "Bearer "+apiKey)

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
			Value: apiKey,
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
	req.Header.Set("Authorization", "Bearer "+apiKey)

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
	req.Header.Set("Authorization", "Bearer "+apiKey)

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

func deleteJunkOpsWorkflow(ctx context.Context, workflowHealth WorkflowHealth) error {
	// if project.Environment == "cloud" {
	// 	log.Printf("[DEBUG] Cloud environment. Not deleting junk ops workflow for now")
	// 	return errors.New("Cloud environment. Not deleting junk ops workflow for now")
	// }

	workflows, err := FindWorkflowByName(ctx, "SHUFFLE_INTERNAL_OPS_WORKFLOW")
	if err != nil {
		//log.Printf("[DEBUG] Failed finding any workflow named SHUFFLE_INTERNAL_OPS_WORKFLOW: %s. Is the health API initialized?", err)
		return err
	}


	if len(workflows) == 0 {
		//log.Printf("[DEBUG] Couldn't find any workflow named SHUFFLE_INTERNAL_OPS_WORKFLOW")
		return errors.New("Failed finding workflow named SHUFFLE_INTERNAL_OPS_WORKFLOW")
	}

	//log.Printf("[DEBUG] Found %d workflows named SHUFFLE_INTERNAL_OPS_WORKFLOW: ", len(workflows))

	for _, workflow := range workflows {
		// delete these workflows
		err = DeleteKey(ctx, "workflow", workflow.ID)
		if err != nil {
			log.Printf("[DEBUG] Failed deleting key %s", workflow.ID)
			return err
		} else {
			log.Printf("[INFO] Deleted junk workflow with id: %s", workflow.ID)
		}
	}

	return nil
}

func RunOpsHealthCheck(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	ctx := GetContext(request)
	if os.Getenv("SHUFFLE_HEALTHCHECK_DISABLED") == "true" {
		resp.WriteHeader(200)
		resp.Write([]byte(`{"success": false, "reason": "Healthcheck disabled (not default). Set SHUFFLE_HEALTHCHECK_DISABLED=false to re-enable it."}`))
		return
	}

	// Allows overwrites if they exist
	apiKey := os.Getenv("SHUFFLE_OPS_DASHBOARD_APIKEY")
	orgId := os.Getenv("SHUFFLE_OPS_DASHBOARD_ORG")
	if project.Environment == "onprem" && (len(apiKey) == 0 || len(orgId) == 0) {
		log.Printf("[DEBUG] Ops dashboard api key or org not set. Getting first org and user that is valid")
		org, err := GetFirstOrg(ctx)
		if err != nil {
			log.Printf("[ERROR] Failed getting first org: %s", err)
			resp.WriteHeader(500)
			resp.Write([]byte(`{"success": false, "reason": "Set up a user and org first!")}`))
			return
		}

		validIndex := -1

		// Check which user exists and is admin
		for index, user := range org.Users {
			_, err := GetApikey(ctx, user.ApiKey)
			if err != nil {
				log.Printf("[ERROR] Failed getting api key for user: %s", err)
				continue
			}

			if user.Role == "admin" {
				log.Printf("[DEBUG] Found admin user with api key: %s", user.Id)
				validIndex = index
				break
			}
		}

		if validIndex == -1 {
			log.Printf("[ERROR] Failed getting valid apikey for admin user in org: %s which exists!", org.Id)
			resp.WriteHeader(500)
			resp.Write([]byte(`{"success": false, "reason": "Set up an admin user first!"}`))
			return
		}

		log.Printf("[DEBUG] Setting api key to that of user %s and org id to %s ", org.Users[validIndex].ApiKey, org.Id)

		orgId = org.Id
		apiKey = org.Users[validIndex].ApiKey
	}

	if len(apiKey) == 0 || len(orgId) == 0 {
		log.Printf("[WARNING] Ops dashboard api key or org not set. Not setting up ops workflow")
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false, "reason": "SHUFFLE_OPS_DASHBOARD_APIKEY or SHUFFLE_OPS_DASHBOARD_ORG not set. Please set these to use this feature!"}`))
		return
	}

	platformHealth := HealthCheck{}
	force := request.URL.Query().Get("force")
	cacheKey := fmt.Sprintf("ops-health-check")
	if project.CacheDb && force != "true" {
		cache, err := GetCache(ctx, cacheKey)
		if err == nil {
			cacheData := []byte(cache.([]uint8))
			//log.Printf("CACHEDATA: %s", cacheData)
			err = json.Unmarshal(cacheData, &platformHealth)
			if err == nil {
				//log.Printf("[DEBUG] Platform health returned: %#v", platformHealth)
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
			log.Printf("[WARNING] Failed getting cache ops health on first try: %s", err)
		}
	} else if !project.CacheDb {
		log.Println("[WARNING] Cache not enabled. Not using cache for ops health isn't recommended!")
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false, "reason": "Cache not enabled. Not using cache for ops health isn't recommended!"}`))
		return
	}

	if force != "true" {
		// get last health check from database
		healths, err := GetPlatformHealth(ctx, 0, 0, 1)
		if len(healths) == 0 {
			resp.WriteHeader(500)
			resp.Write([]byte(`{"success": false, "reason": "Health check has never been run before! If you are an admin user, run with ?force=true to force a health check."}`))
			return
		}

		health := healths[0]

		if err == nil {
			log.Printf("[DEBUG] Last health check was: %#v", health)
			platformData, err := json.Marshal(health)
			if err != nil {
				log.Printf("[ERROR] Failed marshalling platform health data: %s", err)
				resp.WriteHeader(500)
				resp.Write([]byte(`{"success": false, "reason": "Failed JSON parsing platform health."}`))
				return
			}

			resp.WriteHeader(200)
			resp.Write(platformData)
			return
		} 

		log.Printf("[WARNING] Failed getting platform health from database: %s", err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false, "reason": "Failed getting platform health from database."}`))
		return
	}

	// Making a fake user to pass to the api authentication
	// This is mainly because nothing in here allows you to control it
	var err error
	userInfo := User{
		ApiKey: apiKey,
		Role: "admin",
	}

	if project.Environment != "onprem" {
		userInfo, err = HandleApiAuthentication(resp, request)
		if err != nil {
			log.Printf("[WARNING] Api authentication failed in handleInfo: %s", err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Api authentication failed!"}`))
			return
		}
	} else {
		// FIXME: Add a check for if it's been <interval> length at least between runs. This is 15 minutes by default.
	}

	if project.Environment == "onprem" && userInfo.Role != "admin" {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Only admins can run health check!"}`))
		return
	} else if project.Environment == "Cloud" && (userInfo.ApiKey != os.Getenv("SHUFFLE_OPS_DASHBOARD_APIKEY") || userInfo.SupportAccess) {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Only admins can run health check!"}`))
		return
	}

	//log.Printf("[DEBUG] Does user who is running health check have support access? %t", userInfo.SupportAccess)
	//log.Printf("[DEBUG] Is user api key same as ops dashboard api key? %t", userInfo.ApiKey == os.Getenv("SHUFFLE_OPS_DASHBOARD_APIKEY"))

	// Use channel for getting RunOpsWorkflow function results
	workflowHealthChannel := make(chan WorkflowHealth)
	go func() {
		log.Printf("[DEBUG] Running workflowHealthChannel goroutine")
		workflowHealth, err := RunOpsWorkflow(apiKey, orgId)
		if err != nil {
			log.Printf("[ERROR] Failed workflow health check: %s", err)
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

	if platformHealth.Workflows.Create == true && platformHealth.Workflows.Delete == true && platformHealth.Workflows.Run == true && platformHealth.Workflows.RunFinished == true {
		log.Printf("[DEBUG] Platform health check successful! All necessary values are true.")
		platformHealth.Success = true
	}

	platformHealth.Updated = time.Now().Unix()

	var HealthCheck HealthCheckDB
	HealthCheck.Success = platformHealth.Success
	HealthCheck.Updated = platformHealth.Updated
	HealthCheck.Workflows = platformHealth.Workflows

	// Add to database
	err = SetPlatformHealth(ctx, HealthCheck)
	if err != nil {
		log.Printf("[ERROR] Failed setting platform health in database: %s", err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false, "reason": "Failed setting platform health in database."}`))
		return
	}

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

func GetOpsDashboardStats(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	ctx := GetContext(request)

	limit := request.URL.Query().Get("limit")
	before := request.URL.Query().Get("before")
	after := request.URL.Query().Get("after")

	// convert all to int64
	limitInt, err := strconv.Atoi(limit)
	if err != nil {
		//log.Printf("[ERROR] Failed converting limit to int: %s", err)
		limitInt = 0
	}

	beforeInt, err := strconv.Atoi(before)
	if err != nil {
		//log.Printf("[ERROR] Failed converting before to int: %s", err)
		beforeInt = 0
	}

	// Default to 90 days
	afterInt, err := strconv.Atoi(after)
	if err != nil {
		afterInt = int(time.Now().AddDate(0, 0, -30).Unix())
	}

	healthChecks, err := GetPlatformHealth(ctx, afterInt, beforeInt, limitInt)
	if err != nil && strings.Contains(err.Error(), "Bad statuscode: 404") && project.Environment == "onprem" {
		log.Printf("[WARNING] Failed getting platform health from database: %s. Probably because no workflowexecutions have been done",err)
		resp.WriteHeader(200)
		resp.Write([]byte(`[]`))
		return
	}

	if err != nil {
		log.Printf("[ERROR] Failed getting platform health from database: %s", err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false, "reason": "Failed getting platform health from database."}`))
		return
	}

	executionIds := request.URL.Query().Get("execution_id")
	if len(executionIds) > 0 {
		allIds := []string{}
		if strings.Contains(executionIds, ",") {
			allIds = strings.Split(executionIds, ",")
		} else {
			allIds = append(allIds, executionIds)
		}

		log.Printf("[DEBUG] Getting platform health for execution ids: %s", allIds)

		newHealthChecks := []HealthCheckDB{}
		for _, item := range healthChecks {
			if ArrayContains(allIds, item.Workflows.ExecutionId) {
				newHealthChecks = append(newHealthChecks, item)
			}
		}

		if len(newHealthChecks) > 0 {
			healthChecks = newHealthChecks
		}
	}

	healthChecksData, err := json.MarshalIndent(healthChecks, "", "  ")
	if err != nil {
		log.Printf("[ERROR] Failed marshalling platform health data: %s", err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false, "reason": "Failed JSON parsing platform health."}`))
		return
	}

	resp.WriteHeader(200)
	resp.Write(healthChecksData)
}

func deleteOpsWorkflow(workflowHealth WorkflowHealth, apiKey string, orgId string) error {
	baseUrl := os.Getenv("SHUFFLE_CLOUDRUN_URL")
	if len(baseUrl) == 0 {
		log.Printf("[DEBUG] Base url not set. Setting to default: for delete")
		baseUrl = "https://shuffler.io"
	}

	if project.Environment == "onprem" {
		log.Printf("[DEBUG] Onprem environment. Setting base url to localhost: for delete")
		baseUrl = "http://localhost:5001"
	}

	if workflowHealth.Create == false || len(workflowHealth.WorkflowId) == 0 {
		log.Printf("[DEBUG] Seems like workflow wasn't created properly, and then delete workflow was called.")
		log.Printf("[DEBUG] Returning without deleting workflow. WorkflowHealth: %#v", workflowHealth)
		return errors.New("Workflow wasn't created properly")
	}

	id := workflowHealth.WorkflowId

	// 4. Delete workflow
	url := baseUrl + "/api/v1/workflows/" + id
	log.Printf("[DEBUG] Deleting workflow with id: %s", id)

	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		log.Printf("[ERROR] Failed creating HTTP request: %s", err)
		return err
	}

	// set the headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Org-Id", orgId)

	// send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[ERROR] Failed deleting the health check workflow with HTTP request: %s", err)
		return err
	}

	if resp.StatusCode != 200 {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Printf("[ERROR] Failed reading HTTP response body: %s", err)
		} else {
			log.Printf("[ERROR] Failed deleting the health check workflow. The status code was: %d and body was: %s", resp.StatusCode, body)
		}
		return errors.New("Failed deleting the health check workflow")
	}

	defer resp.Body.Close()

	return nil
}

func fixOpensearch() error {
	// Define the index mapping
	mapping := `{
		"properties": {
		  "workflow": {
			"properties": {
			  "actions": {
				"properties": {
				  "parameters": {
					"properties": {
					  "value": {
						"type": "text"
					  },
					  "example": {
						  "type": "text"
					  }
					}
				  }
				}
			  }
			}
		  }
		}
	  }`

	// Get the username and password from environment variables
	username := os.Getenv("SHUFFLE_OPENSEARCH_USERNAME")
	if len(username) == 0 {
		log.Printf("[DEBUG] Opensearch username not set. Setting to default")
		username = "admin"
	}

	password := os.Getenv("SHUFFLE_OPENSEARCH_PASSWORD")
	if len(password) == 0 {
		log.Printf("[DEBUG] Opensearch password not set. Setting to default")
		password = "admin"
	}

	opensearchUrl := os.Getenv("SHUFFLE_OPENSEARCH_URL")
	if len(opensearchUrl) == 0 {
		log.Printf("[DEBUG] Opensearch url not set. Setting to default")
		opensearchUrl = "http://localhost:9200"
	}

	apiUrl := opensearchUrl + "/workflowexecution/_mapping"

	log.Printf("[DEBUG] apiurl for fixing opensearch: %s", apiUrl)

	// Create a new request
	req, err := http.NewRequest("PUT", apiUrl, bytes.NewBufferString(mapping))
	if err != nil {
		log.Fatalf("Error creating the request: %s", err)
	}

	// Set the request headers
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(username, password)

	// Create a new HTTP client
	client := &http.Client{}

// Send the request in a loop until a 200 status code is received
	res, err := client.Do(req)
	if err != nil {
		log.Printf("Error sending the request while fixing execution body: %s", err)
		return err
	}

	// Read the response body
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Printf("Error reading the response body while fixing execution body: %s", err)
		return err
	}
	res.Body.Close()

	if res.StatusCode == 200 {
		log.Printf("Index created successfully: %s. Opensearch mappings should be fixed.", body)
		return nil
	} else {
		log.Printf("Failed to create index, retrying: %s", body)
		return errors.New("Failed index mapping")
	}

	return nil
}

func RunOpsWorkflow(apiKey string, orgId string) (WorkflowHealth, error) {
	// run workflow with id 602c7cf5-500e-4bd1-8a97-aa5bc8a554e6
	ctx := context.Background()

	workflowHealth := WorkflowHealth{
		Create:      false,
		Run:         false,
		RunFinished: false,
		Delete:      false,
		RunStatus:   "",
		ExecutionId: "",
		WorkflowId:  "",
	}

	baseUrl := os.Getenv("SHUFFLE_CLOUDRUN_URL")
	if len(baseUrl) == 0 {
		log.Printf("[DEBUG] Base url not set. Setting to default")
		baseUrl = "https://shuffler.io"
	}

	if project.Environment == "onprem" {
		log.Printf("[DEBUG] Onprem environment. Setting base url to localhost")
		baseUrl = "http://localhost:5001"
	}

	// 1. Get workflow
	opsWorkflowID, err := InitOpsWorkflow(apiKey, orgId)
	if err != nil {
		log.Printf("[ERROR] Failed creating Health check workflow: %s", err)
		return workflowHealth, err
	}

	if len(opsWorkflowID) == 0 {
		log.Printf("[ERROR] Failed creating Health check workflow. Exiting..")
		return workflowHealth, err
	}

	workflowPtr, err := GetWorkflow(ctx, opsWorkflowID)
	if err != nil {
		log.Printf("[ERROR] Failed getting Health check workflow: %s", err)
		return workflowHealth, err
	}

	workflowHealth.Create = true
	workflowHealth.WorkflowId = opsWorkflowID
	updateOpsCache(workflowHealth)

	workflow := *workflowPtr

	//log.Printf("[DEBUG] Running health check workflow. workflowHealth till now: %#v", workflowHealth)

	// 2. Run workflow
	id := workflow.ID
	url := baseUrl + "/api/v1/workflows/" + id + "/execute"
	//log.Printf("[DEBUG] Running health check workflow with URL: %s", url)
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		log.Printf("[ERROR] Failed creating HTTP request: %s", err)
		return workflowHealth, err
	}

	// set the headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Org-Id", orgId)

	// send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[ERROR] Failed sending health check HTTP request: %s", err)
		return workflowHealth, err	
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Printf("[ERROR] Failed running health check workflow: %s. The status code is: %d", id, resp.StatusCode)

		// print the response body
		respBodyErr, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Printf("[ERROR] Failed reading health check HTTP response body: %s", err)
		} else {
			log.Printf("[ERROR] Health check running Workflow Response: %s", respBodyErr)
		}
		if project.Environment == "onprem" {
			log.Printf("Trying to fix opensearch mappings")
			err = fixOpensearch()
			if err != nil {
				log.Printf("[ERROR] Failed fixing opensearch mappings: %s", err)
			} else {
				log.Printf("[DEBUG] Fixed opensearch mappings successfully! Maybe try ops dashboard again?")
			}
		}
		// return workflowHealth, err
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[ERROR] Failed reading HTTP response body: %s", err)
		return workflowHealth, err
	}

	// Unmarshal the JSON data into a Workflow instance
	var execution WorkflowExecution
	err = json.Unmarshal(respBody, &execution)

	if resp.StatusCode == 200 {
		workflowHealth.Run = true
		workflowHealth.ExecutionId = execution.ExecutionId
	}

	updateOpsCache(workflowHealth)
	timeout := time.After(5 * time.Minute)

	if workflowHealth.Create == true {
		log.Printf("[DEBUG] Deleting created ops workflow")
		err = deleteOpsWorkflow(workflowHealth, apiKey, orgId)
		if err != nil {
			log.Printf("[ERROR] Failed deleting workflow: %s", err)
		} else {
			log.Printf("[DEBUG] Deleted ops workflow successfully!")
			workflowHealth.Delete = true
			updateOpsCache(workflowHealth)
		}
	}

	// 3. Check if workflow ran successfully
	// ping /api/v1/streams/results/<execution_id> while workflowHealth.RunFinished is false
	// if workflowHealth.RunFinished is true, return workflowHealth
	for workflowHealth.RunFinished == false && workflowHealth.Run == true {
		url := baseUrl + "/api/v1/streams/results"
		req, err := http.NewRequest("POST", url, nil)
		if err != nil {
			log.Printf("[ERROR] Failed creating HTTP request: %s", err)
			return workflowHealth, err
		}

		// set the headers
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+apiKey)
		req.Header.Set("Org-Id", orgId)

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
			log.Printf("[DEBUG] Workflow Health execution Result Status: %#v for executionID: %s", executionResults.Status, workflowHealth.ExecutionId)
			workflowHealth.RunFinished = true
			workflowHealth.RunStatus = executionResults.Status
		}

		updateOpsCache(workflowHealth)

		//log.Printf("[DEBUG] Workflow Health execution Result Status: %#v for executionID: %s", executionResults.Status, workflowHealth.ExecutionId)

		// check if timeout
		select {
		case <-timeout:
			log.Printf("[ERROR] Timeout reached for workflow health check. Returning")
			workflowHealth.RunStatus = "ABANDONED_BY_HEALTHCHECK"
			return workflowHealth, errors.New("Timeout reached for workflow health check")
		default:
			// do nothing
		}

		//log.Printf("[DEBUG] Waiting 2 seconds before retrying")
		time.Sleep(2 * time.Second)
	}

	// Delete junk workflows
	err = deleteJunkOpsWorkflow(ctx, workflowHealth)
	if err != nil {
		//log.Printf("[ERROR] Failed deleting junk workflows: %s", err)
	}

	return workflowHealth, nil
}

func InitOpsWorkflow(apiKey string, OrgId string) (string, error) {
	opsDashboardApikey := apiKey
	opsDashboardOrgId := OrgId

	if len(opsDashboardApikey) == 0 {
		log.Printf("[WARNING] Ops dashboard api key not set. Not setting up ops workflow")
		return "", errors.New("Ops dashboard api key not set")

	}

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
		log.Println("[ERROR] Ops dashboard user not found. Not setting up ops workflow")
		return "", errors.New("Ops dashboard user not found")
	}

	if user.Role != "admin" {
		log.Printf("[WARNING] Ops dashboard user not admin. Not setting up ops workflow")
		return "", errors.New("Ops dashboard user not admin")
	}

	log.Printf("[DEBUG] Ops dashboard user found. Setting up ops workflow")


	client := &http.Client{}
	body := GetWorkflowTest()
	if project.Environment == "cloud" {
		// url := "https://shuffler.io/api/v1/workflows/602c7cf5-500e-4bd1-8a97-aa5bc8a554e6"
		url := "https://shuffler.io/api/v1/workflows/412256ca-ce62-4d20-9e55-1491548349e1"
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			log.Println("[ERROR] creating HTTP request:", err)
			return "", errors.New("Error creating HTTP request: " + err.Error())
		}

		log.Printf("[DEBUG] Fetching health ops workflow with URL: %s", url)

		// send the request
		resp, err := client.Do(req)
		if err != nil {
			log.Println("[ERROR] sending Ops fetch app HTTP request:", err)
			return "", errors.New("Error sending HTTP request: " + err.Error())
		}

		defer resp.Body.Close()

		// Read the response body
		body, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Println("[ERROR] reading HTTP response body:", err)
			return "", errors.New("Error reading HTTP App response response body: " + err.Error())
		}

		log.Printf("[DEBUG] Successfully fetched workflow! Now creating a copy workflow for ops dashboard")
	}

	// Unmarshal the JSON data into a Workflow instance
	var workflowData Workflow
	err = json.Unmarshal(body, &workflowData)
	if err != nil {
		log.Println("[ERROR] unmarshalling Ops workflowData JSON data:", err)
		return "", errors.New("Error unmarshalling JSON data: " + err.Error())
	}

	log.Printf("[DEBUG] Original workflow has ID: %s", workflowData.ID)

	variables := workflowData.WorkflowVariables
	for _, variable := range variables {
		if variable.Name == "apikey" {
			variable.Value = opsDashboardApikey
		} else if variable.Name == "cachekey" {
			variable.Value = "1234"
		}
	}

	// fix workflow org
	workflowData.Public = false
	workflowData.Status = ""
	workflowData.Name = "Ops Dashboard Workflow"
	workflowData.Hidden = true

	miniOrg := OrgMini{
		Id:    opsDashboardOrg.Id,
		Name:  opsDashboardOrg.Name,
		Users: []UserMini{},
	}

	workflowData.Org = []OrgMini{}
	workflowData.Org = append(workflowData.Org, miniOrg)

	var actions []Action
	// var blacklisted = []string{"Date_to_epoch", "input_data", "Compare_timestamps", "Get_current_timestamp"}

	for actionIndex, _ := range workflowData.Actions {
		action := workflowData.Actions[actionIndex]

		if project.Environment == "onprem" {
			if action.Environment != "Shuffle" {
				action.Environment = "Shuffle"
			}
		} else {
			if action.Environment != "Cloud" {
				action.Environment = "Cloud"
			}
		}

		workflowData.Actions[actionIndex] = action

		actions = append(actions, action)
	}

	workflowData.Actions = actions

	// // Save the workflow
	// err = SetWorkflow(ctx, workflowData, workflowData.ID)

	// if err != nil {
	// 	log.Println("[ERROR] saving ops dashboard workflow:", err)
	// 	return "", errors.New("Error saving ops dashboard workflow: " + err.Error())
	// }

	// create an empty workflow
	// make a POST request to https://shuffler.io/api/v1/workflows
	baseUrl := os.Getenv("SHUFFLE_CLOUDRUN_URL")
	if len(baseUrl) == 0 {
		log.Printf("[DEBUG] Base url not set. Setting to default")
		baseUrl = "https://shuffler.io"
	}

	if project.Environment == "onprem" {
		log.Printf("[DEBUG] Onprem environment. Setting base url to localhost")
		baseUrl = "http://localhost:5001"
	}

	// {"name":"demo","description":"demo","blogpost":"","status":"test","default_return_value":"","usecase_ids":[]}
	jsonData := `{"name":"SHUFFLE_INTERNAL_OPS_WORKFLOW","description":"demo","hidden":true,"blogpost":"","status":"test","default_return_value":"","usecase_ids":[]}`

	// res, err := http.Post(url, "application/json", bytes.NewBuffer([]byte(jsonData)))
	req, err := http.NewRequest("POST", baseUrl+"/api/v1/workflows", bytes.NewBuffer([]byte(jsonData)))

	if err != nil {
		log.Println("[ERROR] creating HTTP request:", err)
		return "", errors.New("Error creating HTTP request: " + err.Error())
	}

	// set the headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Org-Id", opsDashboardOrgId)

	// send the request
	resp, err := client.Do(req)
	if err != nil {
		log.Println("[ERROR] sending Ops create workflow HTTP request:", err)
		return "", errors.New("Error sending HTTP request: " + err.Error())
	}

	if resp.StatusCode != 200 {
		log.Printf("[ERROR] Failed creating ops dashboard workflow: %s. The status code was: %d", err, resp.StatusCode)
		// print the response body
		respBodyErr, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Printf("[ERROR] Failed reading HTTP response body: %s", err)
		} else {
			log.Printf("[ERROR] Ops dashboard creating Workflow Response: %s", respBodyErr)
		}
		return "", errors.New("Failed creating ops dashboard workflow")
	}

	defer resp.Body.Close()

	// Read the response body
	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println("[ERROR] reading HTTP response body:", err)
		return "", errors.New("Error reading HTTP response response body: " + err.Error())
	}

	var tmpworkflow Workflow

	// Unmarshal the JSON data into a Workflow instance
	err = json.Unmarshal(body, &tmpworkflow)

	if err != nil {
		log.Println("[ERROR] unmarshalling Ops workflowData JSON data:", err)
		return "", errors.New("Error unmarshalling JSON data: " + err.Error())
	}

	workflowData.ID = tmpworkflow.ID
	workflowData.Org = tmpworkflow.Org
	workflowData.OrgId = tmpworkflow.OrgId
	workflowData.Owner = tmpworkflow.Owner
	workflowData.ExecutingOrg = tmpworkflow.ExecutingOrg
	workflowData.Hidden = true
	workflowData.Public = false

	// Save the workflow: PUT http://localhost:5002/api/v1/workflows/{id}?skip_save=true
	req, err = http.NewRequest("PUT", baseUrl+"/api/v1/workflows/"+workflowData.ID+"?skip_save=true", nil)
	if err != nil {
		log.Println("[ERROR] creating HTTP request:", err)
		return "", errors.New("Error creating HTTP request: " + err.Error())
	}

	// set the headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Org-Id", opsDashboardOrgId)

	// convert the body to JSON
	workflowDataJSON, err := json.Marshal(workflowData)
	if err != nil {
		log.Printf("[ERROR] Failed marshalling workflow data: %s", err)
		return "", err
	}

	// set the body
	req.Body = ioutil.NopCloser(bytes.NewBuffer(workflowDataJSON))

	// send the request
	client = &http.Client{}
	resp, err = client.Do(req)
	if err != nil {
		log.Printf("[ERROR] Failed sending HTTP request: %s", err)
		return "", err
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Printf("[ERROR] Failed saving ops dashboard workflow: %s. The status code was: %d", err, resp.StatusCode)
		// print the response body
		respBodyErr, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Printf("[ERROR] Failed reading HTTP response body: %s", err)
		} else {
			log.Printf("[ERROR] Ops dashboard saving Workflow Response: %s", respBodyErr)
		}
		return "", errors.New("Failed saving ops dashboard workflow")
	}

	//log.Printf("[INFO] Ops dashboard workflow saved successfully with ID: %s", workflowData.ID)
	return workflowData.ID, nil
}
