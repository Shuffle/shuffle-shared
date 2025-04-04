package shuffle

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Masterminds/semver"
	"github.com/frikky/kin-openapi/openapi3"
	uuid "github.com/satori/go.uuid"
)

type appConfig struct {
	Success bool   `json:"success"`
	OpenAPI string `json:"openapi"`
	App     string `json:"app"`
}

type AppResponse struct {
	Success bool	`json:"success"`
	Id string		`json:"id"`
	Details string	`json:"details"`
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

type testRun struct {
	CRUrl string `json:"cloudrun_url"`
	Region string `json:"region"`
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

	baseURL := "https://shuffler.io"
	if os.Getenv("SHUFFLE_CLOUDRUN_URL") != "" {
		log.Printf("[DEBUG] Setting the baseUrl for health check to %s", baseURL)
		baseURL = os.Getenv("SHUFFLE_CLOUDRUN_URL")
	}

	if project.Environment != "cloud" {
		log.Printf("[DEBUG] Onprem environment. Setting base url to localhost: for delete")
		baseURL = "http://localhost:5001"
		if os.Getenv("BASE_URL") != "" {
			baseURL = os.Getenv("BASE_URL")
		}
	}

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

	type OpenApiData struct {
		Body string `json:"body"`
		Id	string	`json:"id"`
		Success	bool `json:"success"`
	}
	var openApiData OpenApiData

	err = json.Unmarshal([]byte(openapiString), &openApiData)
	if err != nil {
		log.Printf("Error in unm %s", err)
		return appHealth, err
	}

	openapiString = openApiData.Body

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
		respBodyErr, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Printf("[ERROR] Failed reading HTTP response body: %s", err)
		} else {
			log.Printf("[ERROR] Ops dashboard app deleting Response: %s", respBodyErr)
		}

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
	// replace edaa73d40238ee60874a853dc3ccaa6f
	// with id from above and bunch of other data to
	// not get same app id when verified
	data, err := openapi3.NewSwaggerLoader().LoadSwaggerFromData([]byte(openapiString))
	jsonId := json.RawMessage(`"`+id+`"`)
	data.ExtensionProps.Extensions["id"] = jsonId
	data.ExtensionProps.Extensions["editing"] = json.RawMessage(`false`)
	data.Info.Title = "Shuffle-Copy"
	data.Info.Version = "2.0"

	//	newOpenapiString := strings.Replace(openapiString, `"edaa73d40238ee60874a853dc3ccaa6f"`, `"`+id+`"`, 1)
	//	newOpenapiString = strings.Replace(newOpenapiString, `"editing":true`, `"editing":false`, 1)
	//	newOpenapiString = strings.Replace(newOpenapiString, `"title":"Shuffle"`, `"title":"Shuffle-Copy"`, 1)
	//	newOpenapiString = strings.Replace(newOpenapiString, `"version":"1.0"`, `"version":"2.0"`, 1)
	//	newOpenapiString = strings.Replace(newOpenapiString, `"tags":[{"name":"SOAR"},{"name":"Automation"},{"name":"Shuffle"}]`, `"tags":[]`, 1)
	//	newOpenapiString = strings.Replace(newOpenapiString, `"/api/v1/apps/search"`, `"/api/v1/different/endpoint"`, 1)

	url = baseURL + "/api/v1/verify_openapi"

	newOpenapi, err := json.Marshal(data)
	if err != nil {
		log.Printf("[ERROR] Failed to edit app data. Did we change the specs?")
		return appHealth, err
	}

	req, err = http.NewRequest("POST", url, bytes.NewBuffer(newOpenapi))
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

	id = validatedResp.ID
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

	body, err := io.ReadAll(resp.Body) // Read response body
	if err != nil {
		log.Printf("[ERROR] Failed reading response body: %s", err)
		return appHealth, err
	}

	if resp.StatusCode != 200 {
		log.Printf("[ERROR] Failed reading app in app health check: %s. The status code was: %d", err, resp.StatusCode)
		log.Printf("[ERROR] The response body was: %s", body)
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
		respBodyErr, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Printf("[ERROR] Failed reading HTTP response body: %s", err)
		} else {
			log.Printf("[ERROR] Ops dashboard app deleting Response: %s", respBodyErr)
		}

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

func checkQueueForHealthRun(ctx context.Context, orgId string) error{

	executionRequests, err := GetWorkflowQueue(ctx, orgId, 50)
	if err != nil {
		log.Printf("[ERROR] Failed to get org (%s) workflow queue: %s", orgId,err)
		return err
	}

	// Check if it is greater than a threshold why loop?
	if len(executionRequests.Data) > 40 {
		log.Printf("[INFO] Queue is clogged skipping the health check for now")
		return errors.New("clogged queue, too many executions")
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
		Role:   "admin",
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
		err := checkQueueForHealthRun(ctx, orgId)
		if err != nil {
			log.Printf("[ERROR] Failed running health check (4): %s", err)

			var HealthCheck HealthCheckDB
			HealthCheck.Success = false
			HealthCheck.Updated = time.Now().Unix()
			HealthCheck.Workflows = WorkflowHealth{}

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
				err = SetCache(ctx, cacheKey, platformData, 15)
				if err != nil {
					log.Printf("[WARNING] Failed setting cache ops health at last: %s", err)
				}
			}

			resp.WriteHeader(500)
			resp.Write(platformData)
		}
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
	errorChannel := make(chan error)
	go func() {
		log.Printf("[DEBUG] Running workflowHealthChannel goroutine")
		workflowHealth, err := RunOpsWorkflow(apiKey, orgId, "")
		if err != nil {
			if project.Environment == "cloud" {
				log.Printf("[ERROR] Failed workflow health check: %s", err)
			}
		}

		workflowHealthChannel <- workflowHealth
		errorChannel <- err
	}()
	
	// TODO: More testing for onprem health checks
	if project.Environment == "cloud" {
		openapiAppHealthChannel := make(chan AppHealth)
		go func() {
			appHealth, err := RunOpsAppHealthCheck(apiKey, orgId)
			if err != nil {
				log.Printf("[ERROR] Failed running app health check: %s", err)
			}
	
			openapiAppHealthChannel <- appHealth
			errorChannel <- err
		}()
	
		pythonAppHealthChannel := make(chan AppHealth)
		go func() {
			pythonAppHealth, err := RunOpsAppUpload(apiKey, orgId)
			if err != nil {
				log.Printf("[ERROR] Failed running python app health check: %s", err)
			}
	
			pythonAppHealthChannel <- pythonAppHealth
			errorChannel <- err
		}()
		
		// Use channel for getting RunOpsWorkflow function results
		platformHealth.Apps = <- openapiAppHealthChannel
		platformHealth.PythonApps = <- pythonAppHealthChannel
	}

	platformHealth.Workflows = <-workflowHealthChannel
	err = <-errorChannel

	if err != nil {
		if err.Error() == "High number of requests. Try again later" {
			log.Printf("[DEBUG] High number of requests sent to the backend. Skipping this run.")
			resp.WriteHeader(400)
			resp.Write([]byte(`{"success": false, "reason": "High number of requests sent to the backend. Try again later."}`))
			return
		}

		if err.Error() == "Unauthorized user saving ops workflow" {
			log.Printf("[DEBUG] Unauthorized user saving ops workflow. Skipping this run.")
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Unauthorized user saving ops workflow."}`))
			return
		}
	}

	if platformHealth.Workflows.Create == true && platformHealth.Workflows.Delete == true && platformHealth.Workflows.Run == true && platformHealth.Workflows.RunFinished == true && platformHealth.Workflows.RunStatus == "FINISHED" {
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

func GetLiveExecutionStats(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in handleInfo: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Api authentication failed!"}`))
		return 
	}

	if !user.SupportAccess {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Only users with support access can view live execution stats!"}`))
		return
	}

	ctx := GetContext(request)

	limit := request.URL.Query().Get("limit")

	limitInt, err := strconv.Atoi(limit)
	if err != nil {
		// log.Printf("[ERROR] Failed converting limit to int: %s", err)
		limitInt = 0
	}

	before := request.URL.Query().Get("before")
	beforeInt, err := strconv.Atoi(before)
	if err != nil {
		// log.Printf("[ERROR] Failed converting before to int: %s", err)
		beforeInt = 0
	}

	after := request.URL.Query().Get("after")
	afterInt, err := strconv.Atoi(after)
	if err != nil {
		// log.Printf("[ERROR] Failed converting after to int: %s", err)
		afterInt = 0
	}

	mode := request.URL.Query().Get("mode")

	data, err := GetLiveWorkflowExecutionData(
		ctx,
		beforeInt,
		afterInt,
		limitInt,
		mode,
	)

	if err != nil {	
		log.Printf("[ERROR] Failed getting live execution data: %s", err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false, "reason": "Failed getting live execution data."}`))
		return
	}

	dataJSON, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		log.Printf("[ERROR] Failed marshalling live execution data: %s", err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false, "reason": "Failed JSON parsing live execution data."}`))
		return
	}

	resp.WriteHeader(200)
	resp.Write(dataJSON)
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
		log.Printf("[WARNING] Failed getting platform health from database: %s. Probably because no workflowexecutions have been done", err)
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

func fixHealthSubflowParameters(ctx context.Context, workflow *Workflow) (Workflow, error) {
	subflowActionId := ""
	for _, action := range workflow.Actions {
		if action.Label == "call_subflow" {
			subflowActionId = action.ID
			break
		}
	}


	for i := range workflow.Triggers {
		if workflow.Triggers[i].AppName != "Shuffle Workflow" {
			continue
		}

		for j := range workflow.Triggers[i].Parameters {
			if workflow.Triggers[i].Parameters[j].Name == "workflow" {
				workflow.Triggers[i].Parameters[j].Value = workflow.ID
			}

			if workflow.Triggers[i].Parameters[j].Name == "startnode" {
				workflow.Triggers[i].Parameters[j].Value = subflowActionId
				break
			}
		}
		break
	}

	return *workflow, nil
}

func RunOpsWorkflow(apiKey string, orgId string, cloudRunUrl string) (WorkflowHealth, error) {
	// run workflow with id 602c7cf5-500e-4bd1-8a97-aa5bc8a554e6
	ctx := context.Background()

	workflowHealth := WorkflowHealth{
		Create:      false,
		BackendVersion: os.Getenv("SHUFFLE_BACKEND_VERSION"),
		Run:         false,
		RunFinished: false,
		ExecutionTook: 0,
		Delete:      false,
		RunStatus:   "",
		ExecutionId: "",
		WorkflowId:  "",
		WorkflowValidation: false,
	}

	baseUrl := os.Getenv("SHUFFLE_CLOUDRUN_URL")
	if len(baseUrl) == 0 && (cloudRunUrl == "" || len(cloudRunUrl) == 0) {
		log.Printf("[DEBUG] Base url not set. Setting to default")
		baseUrl = "https://shuffler.io"
	}

	if len(baseUrl) == 0 {
		baseUrl = cloudRunUrl
	}

	if project.Environment == "onprem" {
		log.Printf("[DEBUG] Onprem environment. Setting base url to localhost")
		baseUrl = "http://localhost:5001"
	}

	// 1. Get workflow
	opsWorkflowID, err := InitOpsWorkflow(apiKey, orgId)
	if err != nil {
		// if error string contains "High number of requests. Try again later", skip this run
		if strings.Contains(err.Error(), "High number of requests. Try again later") {
			log.Printf("[DEBUG] High number of requests sent to the backend. Skipping this run.")
			return workflowHealth, err
		}

		if strings.Contains(err.Error(), "Unauthorized user saving ops workflow") {
			log.Printf("[DEBUG] Unauthorized user saving the ops workflow. Skipping this run.")
			return workflowHealth, err
		}

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
	startTime := time.Now()
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

		if executionResults.Status == "FINISHED" {
			log.Printf("[DEBUG] Workflow Health exeution is finished, checking it's results")
			workflowHealth.WorkflowValidation = executionResults.Workflow.Validation.Valid
			finishTime := time.Since(startTime).Seconds()
			workflowHealth.ExecutionTook = finishTime
			//workflowHealth = time.Since(startTime)
		}


		updateOpsCache(workflowHealth)

		//log.Printf("[DEBUG] Workflow Health execution Result Status: %#v for executionID: %s", executionResults.Status, workflowHealth.ExecutionId)

		// check if timeout
		select {
		case <-timeout:
			if project.Environment == "cloud" {
				log.Printf("[ERROR] Timeout reached for workflow health check. Returning")
			}

			workflowHealth.RunStatus = "ABANDONED_BY_HEALTHCHECK"

			return workflowHealth, errors.New("Timeout reached for workflow health check")
		default:
			// do nothing
		}

		//log.Printf("[DEBUG] Waiting 2 seconds before retrying")
		time.Sleep(2 * time.Second)
	}

	if workflowHealth.Create == true {
		//log.Printf("[DEBUG] Deleting created ops workflow")
		err = deleteOpsWorkflow(workflowHealth, apiKey, orgId)
		if err != nil {
			log.Printf("[ERROR] Failed deleting workflow: %s", err)
		} else {
			//log.Printf("[DEBUG] Deleted ops workflow successfully!")
			workflowHealth.Delete = true
			updateOpsCache(workflowHealth)
		}
	}


	// Delete junk workflows, this will remove all the healthWorkflow which failed
	err = deleteJunkOpsWorkflow(ctx, workflowHealth)
	if err != nil {
		log.Printf("[WARNING] Failed deleting junk workflows: %s", err)
	}

	return workflowHealth, nil
}

func RunOpsAppUpload(apiKey string, orgId string) (AppHealth, error){
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

	appZipUrl := "https://github.com/shuffle/python-apps/raw/refs/heads/master/shuffle-tools-copy.zip"

	resp, err := http.Get(appZipUrl)
	if err != nil {
		log.Printf("[ERROR] Failed to create an http request to the appZipUrl: %s", err)
		return appHealth, errors.New("Failed creating an http request")
	}
	defer resp.Body.Close()

	pr, pw := io.Pipe()
	writer := multipart.NewWriter(pw)

	go func() {
		defer pw.Close()
		defer writer.Close()

		part, err := writer.CreateFormFile("shuffle_file", "app.zip")
		if err != nil {
			log.Printf("[ERROR] Failed to creating form field: %s", err)
			return
		}

		_, err = io.Copy(part, resp.Body)
		if err != nil {
			log.Printf("[ERROR] Failed to stream file: %s", err)
			return
		}
	}()

	baseUrl := "https://shuffler.io"
	if os.Getenv("BASE_URL") != "" {
		baseUrl = os.Getenv("BASE_URL")
	}

	if os.Getenv("SHUFFLE_CLOUDRUN_URL") != "" {
		log.Printf("[DEBUG] Setting the baseUrl for health check to %s", baseUrl)
		baseUrl = os.Getenv("SHUFFLE_CLOUDRUN_URL")
	}


	if project.Environment != "cloud" {
		log.Printf("[DEBUG] Onprem environment. Setting base url to localhost: for delete")
		baseUrl = "http://localhost:5001"
		if os.Getenv("BASE_URL") != "" {
			baseUrl = os.Getenv("BASE_URL")
		}
	}

	appHealth.Read = true

	appUploadUrl := baseUrl + "/api/v1/apps/upload"

	req, err := http.NewRequest("POST", appUploadUrl, pr)
	if err != nil {
		log.Printf("[ERROR] Failed to create http request for app upload: %s", err)
		return appHealth, errors.New("Failed to create http request for app upload")
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+apiKey)

	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		log.Printf("[ERROR] Failed sending request to app upload: %s", err)
		return appHealth, errors.New("Failed sending http request to app upload")
	}

	defer res.Body.Close()

	response, err := io.ReadAll(res.Body)
	if err != nil {
		log.Printf("[ERROR] Failed to read app upload response: %s", err)
		return appHealth, errors.New("Failed to read app upload response")
	}

	if res.StatusCode != 200{
		log.Printf("[ERROR] Failed to upload an ops app. Response: %s", string(response))
		return appHealth, errors.New("Failed to upload app")
	}

	var appData AppResponse
	err = json.Unmarshal(response, &appData)
	if err != nil {
		log.Printf("[ERROR] Failed to unmarshal response? Did we change the response struct?")
		return appHealth, errors.New("Failed to unmarshal response")
	}

	appHealth.Create = true
	appHealth.AppId = appData.Id

	// wait 5 second before execution
	time.Sleep(5 * time.Second)

	executeUrl := baseUrl + "/api/v1/apps/" + appData.Id + "/run"

	var executeBody WorkflowAppAction
	executeBody.AppID = appData.Id
	executeBody.AppName = "Shuffle Tools Copy"
	executeBody.AppVersion = "1.0.0"
	executeBody.Name = "repeat_back_to_me"
	executeBody.Environment = "cloud"
	executeBody.Sharing = false
	executeBody.Parameters = []WorkflowAppActionParameter{
		{
			Name: "call",
			Value: "run the test app, hello",
			Configuration: false,
		},
	}

	executeBodyJSON, err := json.Marshal(executeBody)
	if err != nil {
		log.Printf("[ERROR] Failed marshalling app run JSON data: %s", err)
		return appHealth, errors.New("Failed marshalling app run JSON data")
	}

	req, err = http.NewRequest("POST", executeUrl, bytes.NewBuffer(executeBodyJSON))
	if err != nil {
		log.Printf("[ERROR] Failed creating HTTP for app run request: %s", err)
		return appHealth, errors.New("Failed to create HTTP for app run")
	}

	// set the headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	// send the request
	client = &http.Client{}
	resp, err = client.Do(req)

	if err != nil {
		log.Printf("[ERROR] Failed sending health check app run HTTP request: %s", err)
		return appHealth, errors.New("Failed sending HTTP request")
	}

	defer resp.Body.Close()

	appExecuteData, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[ERROR] Failed to read app execution data")
		return appHealth, err
	}

	var executionData SingleResult

	err = json.Unmarshal(appExecuteData, &executionData)
	if err != nil {
		log.Printf("[ERROR] Failed to unmarshal single app result")
		return appHealth, errors.New("Failed to unmarshal")
	}

	appHealth.Run = true
	appHealth.ExecutionID = executionData.Id

	runCount := 0
	for executionData.Result == "" {
		if runCount > 5 {
			return appHealth, errors.New("Failed to get app execution result")
		}

		url := baseUrl + "/api/v1/streams/results"
		req, err := http.NewRequest("POST", url, nil)
		if err != nil {
			log.Printf("[ERROR] Failed creating HTTP request: %s", err)
			return appHealth, errors.New("Failed creating HTTP request")
		}

		// set the headers
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+apiKey)
		req.Header.Set("Org-Id", orgId)

		// convert the body to JSON
		reqBody := map[string]string{"execution_id": executionData.Id, "authorization": executionData.Authorization}
		reqBodyJson, err := json.Marshal(reqBody)

		// set the body
		req.Body = ioutil.NopCloser(bytes.NewBuffer(reqBodyJson))

		// send the request
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("[ERROR] Failed sending HTTP request: %s", err)
			return appHealth, err
		}

		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			log.Printf("[ERROR] Failed checking results for the workflow: %s. The status code was: %d", err, resp.StatusCode)
			return appHealth, err
		}

		respBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Printf("[ERROR] Failed reading HTTP response body: %s", err)
			return appHealth, err
		}

		// Unmarshal the JSON data into a Workflow instance
		var executionResults WorkflowExecution
		err = json.Unmarshal(respBody, &executionResults)

		if err != nil {
			log.Printf("[ERROR] Failed unmarshalling JSON data: %s", err)
			return appHealth, err
		}

		if executionResults.Status != "EXECUTING" {
			log.Printf("[DEBUG] Workflow Health execution Result Status: %#v for executionID: %s", executionResults.Status, executionResults.ExecutionId)
		}

		if executionResults.Status == "FINISHED" {
			log.Printf("[DEBUG] Workflow Health exeution is finished, checking it's results")
			executionData.Result = executionResults.Result
			appHealth.Validate = executionResults.Workflow.Validated
		}

		time.Sleep(2 * time.Second)
		runCount += 1
	}

	appHealth.Result = executionData.Result

	// Delete the app
	url := baseUrl + "/api/v1/apps/" + appData.Id

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

func RunHealthTest(resp http.ResponseWriter, req *http.Request) {
	response, err := io.ReadAll(req.Body)
	if err != nil {
		log.Printf("[ERROR] Failed to read body of the health test case: %s", err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false, "reason": "failed to read the body"}`))
		return
	}

	var execData testRun
	err = json.Unmarshal(response, &execData)
	if err != nil {
		log.Printf("[ERROR] Error unmarshaling test data: %s", err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false, "reason": "failed to unmarshal the data"}`))
		return
	}

	apiKey := os.Getenv("SHUFFLE_OPS_DASHBOARD_APIKEY")
	orgId := os.Getenv("SHUFFLE_OPS_DASHBOARD_ORG")

	
	health, err := RunOpsWorkflow(apiKey, orgId, execData.CRUrl)
	if err != nil {
		log.Printf("[ERROR] Health test failed %v", err)
	}

	jsonHealth, err := json.Marshal(health)
	resp.WriteHeader(200)
	resp.Write(jsonHealth)
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
		// url := "https://shuffler.io/api/v1/workflows/7b729319-b395-4ba3-b497-d8246da67b1c"
		// url := "https://shuffler.io/api/v1/workflows/412256ca-ce62-4d20-9e55-1491548349e1"
		url := "https://shuffler.io/api/v1/workflows/ae89a788-a26b-4866-8a0b-ce0b31d354ea"
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

	if resp.StatusCode == 503 {
		log.Printf("[ERROR] This happened because of a high number of requests. We will try again later")

		respBodyErr, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Printf("[ERROR] Failed reading HTTP response body: %s", err)
		} else {
			log.Printf("[ERROR] Ops dashboard creating Workflow Response: %s", respBodyErr)
		}

		return "", errors.New("High number of requests. Try again later")
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

	workflowData, err = fixHealthSubflowParameters(ctx, &workflowData)
	if err != nil {
		log.Printf("[ERROR] Subflow parameter changing failed might create an issue.")
	}

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

	// This happend due to deleteJunkOpsWorkflow deleting the workflow before we even save
	// data. Reason behind is we are making health checks request too fast i.e. less than 
	// 1s.
	if resp.StatusCode == 401 {
		log.Printf("[ERROR] Authentication issue, are we making the health checks request too many health check request? Skipping this run due to authentication problem.")
		return "", errors.New("Unauthorized user saving ops workflow")
	}

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

func GetStaticWorkflowHealth(ctx context.Context, workflow Workflow) (Workflow, []string, error) {
	orgUpdated := false
	startnodeFound := false
	newOrgApps := []string{}
	org := &Org{}

	if len(workflow.OrgId) == 0 {
		//log.Printf("[ERROR] Org ID not set for workflow %s in GetStaticWorkflowHealth()", workflow.ID)
		return workflow, []string{}, errors.New("Org ID not set")
	}

	workflow.Errors = []string{}
	user := User{
		Username: "HealthWorkflowFunction",
		Id: "HealthWorkflowFunction",
		ActiveOrg: OrgMini{
			Id: workflow.OrgId,
		},
	}

	environments := []Environment{
		Environment{
			Name:       "Cloud",
			Type:       "cloud",
			Archived:   false,
			Registered: true,
			Default:    false,
			OrgId:      user.ActiveOrg.Id,
			Id:         uuid.NewV4().String(),
		},
	}

	environments, err := GetEnvironments(ctx, user.ActiveOrg.Id)
	if err != nil {
		log.Printf("[WARNING] Failed getting environments for org %s", user.ActiveOrg.Id)
		environments = []Environment{}
	}

	defaultEnv := ""
	for _, env := range environments {
		if env.Default {
			defaultEnv = env.Name
			break
		}
	}

	if defaultEnv == "" {
		if project.Environment == "cloud" {
			defaultEnv = "Cloud"
		} else {
			defaultEnv = "Shuffle"
		}
	}

	workflowapps := []WorkflowApp{}

	if len(workflow.ParentWorkflowId) == 0 {
		var apperr error
		workflowapps, apperr = GetPrioritizedApps(ctx, user)
		if apperr != nil {
			log.Printf("[ERROR] Failed getting apps for org %s", user.ActiveOrg.Id)
		}
	} else {
		// This is to ensure checking in Multi-Tenant workflows is FAST
	}

	allNodes := []string{}
	newActions := []Action{}
	allNames := []string{}
	for _, action := range workflow.Actions {

		if action.AppID == "integration" || action.AppID == "shuffle_agent" {
			if action.IsStartNode {
				startnodeFound = true
			}

			newActions = append(newActions, action)
			continue
		}

		if action.SourceWorkflow != workflow.ID && len(action.SourceWorkflow) > 0 {
			continue
		}

		newLabelName := strings.Replace(strings.ToLower(action.Label), " ", "_", -1)
		if len(action.Label) > 0 && ArrayContains(allNames, newLabelName) {
			parsedError := fmt.Sprintf("Multiple actions with name '%s'. May cause problems unless changed.", action.Label)
			if !ArrayContains(workflow.Errors, parsedError) {
				workflow.Errors = append(workflow.Errors, parsedError)
			}
		}

		allNames = append(allNames, newLabelName)
		allNodes = append(allNodes, action.ID)
		if workflow.Start == action.ID {
			//log.Printf("[INFO] FOUND STARTNODE %d", workflow.Start)
			startnodeFound = true
			action.IsStartNode = true
		}

		if len(action.Errors) > 0 || !action.IsValid {
			action.IsValid = true
			action.Errors = []string{}
		}

		if action.ExecutionDelay > 86400 {
			parsedError := fmt.Sprintf("Max execution delay for an action is 86400 (1 day)")
			if !ArrayContains(workflow.Errors, parsedError) {
				workflow.Errors = append(workflow.Errors, parsedError)
			}

			action.ExecutionDelay = 86400
		}

		if action.Environment == "" {
			if project.Environment == "cloud" {
				action.Environment = defaultEnv
			} else {
				if len(environments) > 0 {
					for _, env := range environments {
						if !env.Archived && env.Default {
							//log.Printf("FOUND ENV %s", env)
							action.Environment = env.Name
							break
						}
					}
				}

				if action.Environment == "" {
					action.Environment = defaultEnv
				}

				action.IsValid = true
			}
		} else {
			warned := []string{}
			found := false
			for _, env := range environments {
				if env.Name == action.Environment {
					found = true
					if env.Archived {
						//log.Printf("[DEBUG] Environment %s is archived. Changing to default.", env.Name)
						action.Environment = defaultEnv
					}

					break
				}
			}

			if !found {
				if ArrayContains(warned, action.Environment) {
					log.Printf("[DEBUG] Environment %s isn't available. Changing to default.", action.Environment)
					warned = append(warned, action.Environment)
				}

				action.Environment = defaultEnv
			}
		}

		// Fixing apps with bad IDs. This can happen a lot because of
		// autogeneration of app IDs, and export/imports of workflows
		idFound := false
		nameVersionFound := false
		nameFound := false

		discoveredApp := WorkflowApp{}
		for _, innerApp := range workflowapps {
			if innerApp.ID == action.AppID {
				discoveredApp = innerApp
				//log.Printf("[INFO] ID, Name AND version for %s:%s (%s) was FOUND (2)", action.AppName, action.AppVersion, action.AppID)
				action.Sharing = innerApp.Sharing
				action.Public = innerApp.Public
				action.Generated = innerApp.Generated
				action.ReferenceUrl = innerApp.ReferenceUrl

				idFound = true
				break
			}
		}

		if !idFound {
			for _, innerApp := range workflowapps {
				if innerApp.Name == action.AppName && innerApp.AppVersion == action.AppVersion {
					discoveredApp = innerApp

					action.AppID = innerApp.ID
					action.Sharing = innerApp.Sharing
					action.Public = innerApp.Public
					action.Generated = innerApp.Generated
					action.ReferenceUrl = innerApp.ReferenceUrl
					nameVersionFound = true
					break
				}
			}
		}

		if !idFound {
			for _, innerApp := range workflowapps {
				if innerApp.Name == action.AppName {
					discoveredApp = innerApp

					action.AppID = innerApp.ID
					action.Sharing = innerApp.Sharing
					action.Public = innerApp.Public
					action.Generated = innerApp.Generated
					action.ReferenceUrl = innerApp.ReferenceUrl

					nameFound = true
					break
				}
			}
		}

		// Handles backend labeling
		if len(action.CategoryLabel) == 0 && len(discoveredApp.ID) > 0 {
			for _, discoveredAction := range discoveredApp.Actions {
				if action.Name != discoveredAction.Name {
					continue
				}

				if len(discoveredAction.CategoryLabel) == 0 {
					break
				}

				action.CategoryLabel = discoveredAction.CategoryLabel
				break
			}
		}

		if !idFound {
			if nameVersionFound {
			} else if nameFound {
			} else {
				//log.Printf("[WARNING] ID, Name AND version for %s:%s (%s) was NOT found", action.AppName, action.AppVersion, action.AppID)
				handled := false

				if project.Environment == "cloud" {
					appid, err := HandleAlgoliaAppSearch(ctx, action.AppName)
					if err == nil && len(appid.ObjectID) > 0 {
						//log.Printf("[INFO] Found NEW appid %s for app %s", appid, action.AppName)
						tmpApp, err := GetApp(ctx, appid.ObjectID, user, false)
						if err == nil {
							handled = true
							action.AppID = tmpApp.ID
							newOrgApps = append(newOrgApps, action.AppID)

							workflowapps = append(workflowapps, *tmpApp)
						}
					} else {
						//log.Printf("[WARNING] Failed finding name %s in Algolia", action.AppName)
					}
				}

				if !handled {
					action.Errors = []string{fmt.Sprintf("Couldn't find app %s:%s", action.AppName, action.AppVersion)}
					action.IsValid = false
				}
			}
		}

		if !action.IsValid && len(action.Errors) > 0 {
			//log.Printf("[INFO] Node %s is invalid and needs to be remade. Errors: %s", action.Label, strings.Join(action.Errors, "\n"))
		}

		workflow.Categories = HandleCategoryIncrease(workflow.Categories, action, workflowapps)
		newActions = append(newActions, action)

		// FIXMe: Should be authenticated first?
		if len(discoveredApp.Categories) > 0 {
			category := discoveredApp.Categories[0]

			if org.Id == "" {
				org, err = GetOrg(ctx, user.ActiveOrg.Id)
				if err != nil {
					log.Printf("[WARNING] Failed getting org: %s", err)
					continue
				}
			}

			if strings.ToLower(category) == "siem" && org.SecurityFramework.SIEM.ID == "" {
				org.SecurityFramework.SIEM.Name = discoveredApp.Name
				org.SecurityFramework.SIEM.Description = discoveredApp.Description
				org.SecurityFramework.SIEM.ID = discoveredApp.ID
				org.SecurityFramework.SIEM.LargeImage = discoveredApp.LargeImage

				orgUpdated = true
			} else if strings.ToLower(category) == "network" && org.SecurityFramework.Network.ID == "" {
				org.SecurityFramework.Network.Name = discoveredApp.Name
				org.SecurityFramework.Network.Description = discoveredApp.Description
				org.SecurityFramework.Network.ID = discoveredApp.ID
				org.SecurityFramework.Network.LargeImage = discoveredApp.LargeImage

				orgUpdated = true
			} else if strings.ToLower(category) == "edr" || strings.ToLower(category) == "edr & av" && org.SecurityFramework.EDR.ID == "" {
				org.SecurityFramework.EDR.Name = discoveredApp.Name
				org.SecurityFramework.EDR.Description = discoveredApp.Description
				org.SecurityFramework.EDR.ID = discoveredApp.ID
				org.SecurityFramework.EDR.LargeImage = discoveredApp.LargeImage

				orgUpdated = true
			} else if strings.ToLower(category) == "cases" && org.SecurityFramework.Cases.ID == "" {
				org.SecurityFramework.Cases.Name = discoveredApp.Name
				org.SecurityFramework.Cases.Description = discoveredApp.Description
				org.SecurityFramework.Cases.ID = discoveredApp.ID
				org.SecurityFramework.Cases.LargeImage = discoveredApp.LargeImage

				orgUpdated = true
			} else if strings.ToLower(category) == "iam" && org.SecurityFramework.IAM.ID == "" {
				org.SecurityFramework.IAM.Name = discoveredApp.Name
				org.SecurityFramework.IAM.Description = discoveredApp.Description
				org.SecurityFramework.IAM.ID = discoveredApp.ID
				org.SecurityFramework.IAM.LargeImage = discoveredApp.LargeImage

				orgUpdated = true
			} else if strings.ToLower(category) == "assets" && org.SecurityFramework.Assets.ID == "" {
				log.Printf("Setting assets?")
				org.SecurityFramework.Assets.Name = discoveredApp.Name
				org.SecurityFramework.Assets.Description = discoveredApp.Description
				org.SecurityFramework.Assets.ID = discoveredApp.ID
				org.SecurityFramework.Assets.LargeImage = discoveredApp.LargeImage

				orgUpdated = true
			} else if strings.ToLower(category) == "intel" && org.SecurityFramework.Intel.ID == "" {
				org.SecurityFramework.Intel.Name = discoveredApp.Name
				org.SecurityFramework.Intel.Description = discoveredApp.Description
				org.SecurityFramework.Intel.ID = discoveredApp.ID
				org.SecurityFramework.Intel.LargeImage = discoveredApp.LargeImage

				orgUpdated = true
			} else if strings.ToLower(category) == "comms" && org.SecurityFramework.Communication.ID == "" {
				org.SecurityFramework.Communication.Name = discoveredApp.Name
				org.SecurityFramework.Communication.Description = discoveredApp.Description
				org.SecurityFramework.Communication.ID = discoveredApp.ID
				org.SecurityFramework.Communication.LargeImage = discoveredApp.LargeImage

				orgUpdated = true
			} else {
				//log.Printf("[WARNING] No handler for type %s in app framework", category)
			}

		}
	}

	// Handle app versions & upgrades
	for _, action := range workflow.Actions {
		if action.AppID == "integration" || action.AppID == "shuffle_agent" {
			if action.IsStartNode {
				startnodeFound = true
			}

			continue
		}

		actionApp := strings.ToLower(strings.Replace(action.AppName, " ", "", -1))

		for _, app := range workflowapps {
			if strings.ToLower(strings.Replace(app.Name, " ", "", -1)) != actionApp {
				continue
			}

			if len(app.Versions) <= 1 {
				continue
			}

			v2, err := semver.NewVersion(action.AppVersion)
			if err != nil {
				log.Printf("[ERROR] Failed parsing original app version %s: %s", app.AppVersion, err)
				continue
			}

			newVersion := ""
			for _, loopedApp := range app.Versions {
				if action.AppVersion == loopedApp.Version {
					continue
				}

				appConstraint := fmt.Sprintf("< %s", loopedApp.Version)
				c, err := semver.NewConstraint(appConstraint)
				if err != nil {
					log.Printf("[ERROR] Failed preparing constraint %s: %s", appConstraint, err)
					continue
				}

				if c.Check(v2) {
					newVersion = loopedApp.Version
					action.AppVersion = loopedApp.Version
				}
			}

			if len(newVersion) > 0 {
				newError := fmt.Sprintf("App %s has version %s available.", app.Name, newVersion)
				if !ArrayContains(workflow.Errors, newError) {
					workflow.Errors = append(workflow.Errors, newError)
				}
			}
		}
	}

	if !startnodeFound {
		// log.Printf("[ERROR] No startnode during cleanup (save) of of workflow %s!!", workflow.ID)
		// Select the first action as startnode
		if len(newActions) > 0 {
			workflow.Start = newActions[0].ID
			newActions[0].IsStartNode = true
			startnodeFound = true
		}
	}

	workflow.Actions = newActions

	// Automatically adding new apps from imports
	if len(newOrgApps) > 0 && len(workflow.ParentWorkflowId) == 0 {
		log.Printf("[WARNING] Adding new apps to org: %s", newOrgApps)

		if org.Id == "" {
			org, err = GetOrg(ctx, user.ActiveOrg.Id)
			if err != nil {
				log.Printf("[WARNING] Failed getting org during new app update for %s: %s", user.ActiveOrg.Id, err)
			}
		}

		if org.Id != "" {
			added := false
			for _, newApp := range newOrgApps {
				if !ArrayContains(org.ActiveApps, newApp) {
					org.ActiveApps = append(org.ActiveApps, newApp)
					added = true
				}
			}

			if added {
				orgUpdated = true
				//log.Printf("[DEBUG] Org updated with new apps: %s", org.ActiveApps)

				//DeleteCache(ctx, fmt.Sprintf("apps_%s", user.Id))
				DeleteCache(ctx, fmt.Sprintf("workflowapps-sorted-100"))
				DeleteCache(ctx, fmt.Sprintf("workflowapps-sorted-500"))
				DeleteCache(ctx, fmt.Sprintf("workflowapps-sorted-1000"))
				DeleteCache(ctx, fmt.Sprintf("user_%s", user.Username))
				DeleteCache(ctx, fmt.Sprintf("user_%s", user.Id))
				DeleteCache(ctx, fmt.Sprintf("apps_%s", user.ActiveOrg.Id))
				DeleteCache(ctx, fmt.Sprintf("apps_%s", user.Id))
			}
			//}
		}
	}

	newTriggers := []Trigger{}
	for _, trigger := range workflow.Triggers {
		if trigger.SourceWorkflow != workflow.ID && len(trigger.SourceWorkflow) > 0 {
			continue
		}

		// Check if it's actually running
		if trigger.TriggerType == "SCHEDULE" && trigger.Status != "uninitialized" {
			schedule, err := GetSchedule(ctx, trigger.ID)
			if err != nil {
				trigger.Status = "stopped"
			} else if schedule.Id == "" {
				trigger.Status = "stopped"
			}
		} else if trigger.TriggerType == "SUBFLOW" {
			for _, param := range trigger.Parameters {
				if param.Name != "workflow" {
					continue
				}

				/*
				// Validate workflow exists
				_, err := GetWorkflow(ctx, param.Value)
				if err != nil {
					parsedError := fmt.Sprintf("Selected Subflow in Action %s doesn't exist", trigger.Label)
					if !ArrayContains(workflow.Errors, parsedError) {
						workflow.Errors = append(workflow.Errors, parsedError)
					}

					log.Printf("[ERROR] Couldn't find subflow '%s' for workflow %s (%s). NOT setting to self as failover for now, and trusting authentication system instead.", param.Value, workflow.Name, workflow.ID)
					//trigger.Parameters[paramIndex].Value = workflow.ID
				}
				*/
			}
		} else if trigger.TriggerType == "WEBHOOK" {
			if trigger.Status != "uninitialized" && trigger.Status != "stopped" {
				hook, err := GetHook(ctx, trigger.ID)
				if err != nil {
					log.Printf("[WARNING] Failed getting webhook %s (%s)", trigger.ID, trigger.Status)
					trigger.Status = "stopped"
				} else if hook.Id == "" {
					trigger.Status = "stopped"
				}
			}

			//log.Printf("WEBHOOK: %d", len(trigger.Parameters))
			if len(trigger.Parameters) < 2 {
				log.Printf("[ERROR] Issue with parameters in webhook %s in workflow %s - missing params", trigger.ID, workflow.ID)
			} else {
				if !strings.Contains(trigger.Parameters[0].Value, trigger.ID) {
					//log.Printf("[INFO] Fixing webhook URL for %s", trigger.ID)
					baseUrl := "https://shuffler.io"
					if len(os.Getenv("SHUFFLE_GCEPROJECT")) > 0 && len(os.Getenv("SHUFFLE_GCEPROJECT_LOCATION")) > 0 {
						baseUrl = fmt.Sprintf("https://%s.%s.r.appspot.com", os.Getenv("SHUFFLE_GCEPROJECT"), os.Getenv("SHUFFLE_GCEPROJECT_LOCATION"))
					}

					if len(os.Getenv("SHUFFLE_CLOUDRUN_URL")) > 0 {
						baseUrl = os.Getenv("SHUFFLE_CLOUDRUN_URL")
					}

					if project.Environment != "cloud" {
						baseUrl = "http://localhost:3001"
					}

					newTriggerName := fmt.Sprintf("webhook_%s", trigger.ID)
					trigger.Parameters[0].Value = fmt.Sprintf("%s/api/v1/hooks/%s", baseUrl, newTriggerName)
					trigger.Parameters[1].Value = newTriggerName
				}
			}
		} else if trigger.TriggerType == "USERINPUT" {
			// E.g. check email
			sms := ""
			email := ""
			subflow := ""
			triggerType := ""
			triggerInformation := ""
			for _, item := range trigger.Parameters {
				if item.Name == "alertinfo" {
					triggerInformation = item.Value
				} else if item.Name == "type" {
					triggerType = item.Value
				} else if item.Name == "email" {
					email = item.Value
				} else if item.Name == "sms" {
					sms = item.Value
				} else if item.Name == "subflow" {
					subflow = item.Value
				}
			}

			_ = subflow

			if len(triggerType) == 0 {
				//log.Printf("[WARNING] No TriggerType specified for User Input node %s in %s (%s)", trigger.Label, workflow.Name, workflow.ID)
				workflow.Errors = append(workflow.Errors, fmt.Sprintf("No TriggerType specified for User Input action %s", strings.ReplaceAll(trigger.Label, " ", "_")))
				if workflow.PreviouslySaved {
					//resp.WriteHeader(401)
					//resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "No contact option specified in user input"}`)))
					//return
				}
			}

			// FIXME: This is not the right time to send them, BUT it's well served for testing. Save -> send email / sms
			_ = triggerInformation
			if strings.Contains(triggerType, "email") {
				if email == "test@test.com" {
					log.Printf("Email isn't specified during save.")
					if workflow.PreviouslySaved {
						workflow.Errors = append(workflow.Errors, "Email field in user input can't be empty")
						continue
					}
				}

				//log.Printf("[DEBUG] Should send email to %s during execution.", email)
			}

			if strings.Contains(triggerType, "sms") {
				if sms == "0000000" {
					log.Printf("Email isn't specified during save.")
					if workflow.PreviouslySaved {
						workflow.Errors = append(workflow.Errors, "SMS field in user input can't be empty")
						continue
					}
				}

				log.Printf("[DEBUG] Should send SMS to %s during execution.", sms)
			}
		}

		allNodes = append(allNodes, trigger.ID)
		newTriggers = append(newTriggers, trigger)
	}

	newComments := []Comment{}
	for _, comment := range workflow.Comments {
		if comment.Height < 50 {
			comment.Height = 150
		}

		if comment.Width < 50 {
			comment.Height = 150
		}

		if len(comment.BackgroundColor) == 0 {
			comment.BackgroundColor = "#1f2023"
		}

		if len(comment.Color) == 0 {
			comment.Color = "#ffffff"
		}

		comment.Position.X = float64(comment.Position.X)
		comment.Position.Y = float64(comment.Position.Y)

		newComments = append(newComments, comment)
	}

	workflow.Comments = newComments
	workflow.Triggers = newTriggers

	if len(workflow.Actions) == 0 {
		workflow.Actions = []Action{}
	}
	if len(workflow.Branches) == 0 {
		workflow.Branches = []Branch{}
	}
	if len(workflow.Triggers) == 0 {
		workflow.Triggers = []Trigger{}
	}
	if len(workflow.Errors) == 0 {
		workflow.Errors = []string{}
	}
	if len(workflow.Comments) == 0 {
		workflow.Comments = []Comment{}
	}

	//log.Printf("PRE VARIABLES")
	for _, variable := range workflow.WorkflowVariables {
		if len(variable.Value) == 0 {
			log.Printf("[WARNING] Health API: Workflow Variable %s is empty!", variable.Name)
			workflow.Errors = append(workflow.Errors, fmt.Sprintf("Variable %s is empty!", variable.Name))
		}
	}

	if len(workflow.ExecutionVariables) > 0 {
		//log.Printf("[INFO] Found %d runtime variable(s) for workflow %s", len(workflow.ExecutionVariables), workflow.ID)
	}

	if len(workflow.WorkflowVariables) > 0 {
		//log.Printf("[INFO] Found %d workflow variable(s) for workflow %s", len(workflow.WorkflowVariables), workflow.ID)
	}

	// Check every app action and param to see whether they exist
	allAuths, autherr := GetAllWorkflowAppAuth(ctx, user.ActiveOrg.Id)
	authGroups := []AppAuthenticationGroup{}
	newActions = []Action{}
	for _, action := range workflow.Actions {
		reservedApps := []string{
			"0ca8887e-b4af-4e3e-887c-87e9d3bc3d3e",
		}

		builtin := false
		for _, id := range reservedApps {
			if id == action.AppID {
				builtin = true
				break
			}
		}

		// Check auth
		// 1. Find the auth in question
		// 2. Update the node and workflow info in the auth
		// 3. Get the values in the auth and add them to the action values
		handleOauth := false
		_ = handleOauth
		if action.AuthenticationId == "authgroups" {
			log.Printf("[DEBUG] Action %s (%s) in workflow %s (%s) uses authgroups", action.Label, action.ID, workflow.Name, workflow.ID)

			// Check if the authgroups exists
			if len(workflow.AuthGroups) > 0 && len(authGroups) == 0 {
				authGroups, err = GetAuthGroups(ctx, user.ActiveOrg.Id)
				if err != nil {
					log.Printf("[WARNING] Failed getting authgroups for org %s: %s", user.ActiveOrg.Id, err)
				} else {
					log.Printf("[INFO] Found %d authgroups for org %s", len(authGroups), user.ActiveOrg.Id)

					// Validate the workflow groups to see if they exist. Remove if not.
					newGroups := []string{}
					for _, group := range workflow.AuthGroups {
						found := false

						for _, authGroup := range authGroups {
							if group == authGroup.Id {
								found = true
								break
							}
						}

						if !found {
							log.Printf("[WARNING] Authgroup %s doesn't exist. Removing from workflow", group)
						} else {
							newGroups = append(newGroups, group)
						}
					}

					workflow.AuthGroups = newGroups
				}
			}

		} else if len(action.AuthenticationId) > 0 {
			authFound := false
			for _, auth := range allAuths {
				if auth.Id == action.AuthenticationId {
					authFound = true

					if strings.ToLower(auth.Type) == "oauth2" {
						handleOauth = true
					}

					// Updates the auth item itself IF necessary
					UpdateAppAuth(ctx, auth, workflow.ID, action.ID, true)
					break
				}
			}

			if !authFound {
				//log.Printf("[WARNING] App auth %s used in workflow %s doesn't exist. Setting error", action.AuthenticationId, workflow.ID)

				errorMsg := fmt.Sprintf("Authentication for action %s in app '%s' doesn't exist!", strings.ReplaceAll(action.Label, " ", "_"), strings.ToLower(strings.ReplaceAll(action.AppName, "_", " ")))
				if !ArrayContains(workflow.Errors, errorMsg) {
					workflow.Errors = append(workflow.Errors, errorMsg)
				}

				workflow.IsValid = false
				action.Errors = append(action.Errors, "App authentication doesn't exist")
				action.IsValid = false
				action.AuthenticationId = ""
			}
		}

		if builtin {
			newActions = append(newActions, action)
		} else {
			curapp := WorkflowApp{}

			// ID first, then name + version
			// If it can't find param, it will swap it over farther down
			for _, app := range workflowapps {
				if app.ID == "" {
					break
				}

				if app.ID == action.AppID {
					curapp = app
					break
				}
			}

			if curapp.ID == "" && action.AppID != "integration" && action.AppID != "shuffle_agent" {
				//log.Printf("[WARNING] Didn't find the App ID for action %s (%s) with appname %s", action.Label, action.AppID, action.AppName)
				for _, app := range workflowapps {
					if app.ID == action.AppID {
						curapp = app
						break
					}

					// Has to NOT be generated
					if app.Name == action.AppName {
						if app.AppVersion == action.AppVersion {
							curapp = app
							break
						} else if ArrayContains(app.LoopVersions, action.AppVersion) {
							// Get the real app
							for _, item := range app.Versions {
								if item.Version == action.AppVersion {
									//log.Printf("Should get app %s - %s", item.Version, item.ID)

									tmpApp, err := GetApp(ctx, item.ID, user, false)
									if err != nil && tmpApp.ID == "" {
										log.Printf("[WARNING] Failed getting app %s (%s): %s", app.Name, item.ID, err)
									}

									curapp = *tmpApp
									break
								}
							}

							//curapp = app
							break
						}
					}
				}
			} else {
				//log.Printf("[DEBUG] Found correct App ID for %s", action.AppID)
			}

			if curapp.ID != action.AppID && curapp.Name != action.AppName {
				if action.AppID == "integration" || action.AppID == "shuffle_agent"  {
					for _, param := range action.Parameters {
						if param.Name == "action" {
							if len(param.Value) > 0 {
								continue
							}

							errorMsg := fmt.Sprintf("Parameter %s in Action %s is empty", param.Name, action.Label)
							if !ArrayContains(workflow.Errors, errorMsg) {
								workflow.Errors = append(workflow.Errors, errorMsg)
							}
						}
					}
				} else {
					errorMsg := fmt.Sprintf("App %s version %s doesn't exist", action.AppName, action.AppVersion)

					if len(workflow.ParentWorkflowId) == 0 {
						action.Errors = append(action.Errors, "This app doesn't exist.")
						if !ArrayContains(workflow.Errors, errorMsg) {
							workflow.Errors = append(workflow.Errors, errorMsg)
							//log.Printf("[WARNING] App %s:%s doesn't exist. Adding as error.", action.AppName, action.AppVersion)
						}
					}

					action.IsValid = false
					workflow.IsValid = false

				}

				newActions = append(newActions, action)
			} else {
				// Check to see if the appaction is valid
				curappaction := WorkflowAppAction{}
				for _, curAction := range curapp.Actions {
					if action.Name == curAction.Name {
						curappaction = curAction
						break
					}
				}

				if curappaction.Name != action.Name {
					for _, app := range workflowapps {
						if app.ID == curapp.ID {
							continue
						}

						// Has to NOT be generated
						if app.Name == action.AppName && app.AppVersion == action.AppVersion {
							for _, curAction := range app.Actions {
								if action.Name == curAction.Name {
									log.Printf("[DEBUG] Found app %s (NOT %s) with the param: %s", app.ID, curapp.ID, curAction.Name)
									curappaction = curAction
									action.AppID = app.ID
									curapp = app
									break
								}
							}
						}

						if curappaction.Name == action.Name {
							break
						}
					}
				}

				// Check to see if the action is valid
				if curappaction.Name != action.Name {
					//log.Printf("[ERROR] Action '%s' in app %s doesn't exist. Workflow: %s (%s)", action.Name, curapp.Name, workflow.Name, workflow.ID)
					// Reserved names
					if action.Name != "router" {
						thisError := fmt.Sprintf("%s: Action %s in app %s doesn't exist", action.Label, action.Name, action.AppName)
						workflow.Errors = append(workflow.Errors, thisError)
						workflow.IsValid = false

						if !ArrayContains(action.Errors, thisError) {
							action.Errors = append(action.Errors, thisError)
						}

						action.IsValid = false
					}
				}

				selectedAuth := AppAuthenticationStorage{}
				if len(action.AuthenticationId) > 0 && autherr == nil {
					for _, auth := range allAuths {
						if auth.Id == action.AuthenticationId {
							selectedAuth = auth
							break
						}
					}
				}

				// Check if it uses oauth2 and if it's authenticated or not
				if selectedAuth.Id == "" && len(action.AuthenticationId) == 0 {
					authRequired := false
					fieldsFilled := 0
					for _, param := range curappaction.Parameters {
						if param.Configuration {
							if len(param.Value) > 0 {
								fieldsFilled += 1
							}
							authRequired = true
							break
						}
					}

					if authRequired && fieldsFilled > 1 {
						foundErr := fmt.Sprintf("Action %s (%s) requires authentication", action.Label, strings.ToLower(strings.Replace(action.AppName, "_", " ", -1)))
						if !ArrayContains(workflow.Errors, foundErr) {
							log.Printf("\n\n[DEBUG] Adding auth error 1: %s\n\n", foundErr)
							workflow.Errors = append(workflow.Errors, foundErr)
						}

						if !ArrayContains(action.Errors, foundErr) {
							action.Errors = append(action.Errors, foundErr)
							action.IsValid = false
						}
					} else if authRequired && fieldsFilled == 1 {
						foundErr := fmt.Sprintf("Action %s (%s) requires authentication", action.Label, strings.ToLower(strings.Replace(action.AppName, "_", " ", -1)))

						if !ArrayContains(workflow.Errors, foundErr) {
							//log.Printf("[DEBUG] Workflow save - adding auth error 2: %s", foundErr)
							workflow.Errors = append(workflow.Errors, foundErr)
							//continue
						}

						if !ArrayContains(action.Errors, foundErr) {
							action.Errors = append(action.Errors, foundErr)
							action.IsValid = false
						}
					}
				}

				// This is weird and for sure wrong somehow
				// Uses the current apps' actions and not the ones sent in. For comparison.
				newParams := []WorkflowAppActionParameter{}
				for _, param := range curappaction.Parameters {

					// Handles check for parameter exists + value not empty in used fields
					foundWithValue := false
					for _, actionParam := range action.Parameters {
						if actionParam.Name != param.Name {
							continue
						}

						param = actionParam
						if len(actionParam.Value) > 0 {
							foundWithValue = true
						}

						newParamsContains := false
						for _, newParam := range newParams {
							if newParam.Name == actionParam.Name {
								newParamsContains = true

								break
							}
						}

						if !newParamsContains {
							newParams = append(newParams, actionParam)
						}

						break
					}

					if foundWithValue {
						continue
					}

					//log.Printf("CHECK: %#v, %#v, %#v", action.Label, param.Name, param.Required)

					// Missing actions go here
					if param.Value == "" && param.Variant == "STATIC_VALUE" && param.Required == true {
						// Validating if the field is an authentication field
						if len(selectedAuth.Id) > 0 {
							authFound := false
							for _, field := range selectedAuth.Fields {
								if field.Key == param.Name {
									authFound = true
									//log.Printf("FOUND REQUIRED KEY %s IN AUTH", field.Key)
									break
								}
							}

							if authFound {
								newParams = append(newParams, param)
								continue
							}
						}

						// Some internal reserves that don't need
						// strict param measuring 
						if ((strings.ToLower(action.AppName) == "http" && param.Name == "body") || (strings.ToLower(action.Name) == "send_sms_shuffle" || strings.ToLower(action.Name) == "send_email_shuffle") && param.Name == "apikey") || (action.Name == "repeat_back_to_me") || (action.Name == "filter_list" && param.Name == "field") || action.Name == "custom_action" {
							// Do nothing
						} else {

							thisError := fmt.Sprintf("Action %s is missing required parameter %s", action.Label, param.Name)
							if param.Configuration && len(action.AuthenticationId) == 0 {
								thisError = fmt.Sprintf("Action %s (%s) requires authentication", action.Label, strings.ToLower(strings.Replace(action.AppName, "_", " ", -1)))
							}

							if !ArrayContains(action.Errors, thisError) {
								action.Errors = append(action.Errors, thisError)
								action.IsValid = false
							}

							// Updates an existing version of the same one for each missing param
							errorFound := false
							for errIndex, oldErr := range workflow.Errors {
								if oldErr == thisError {
									errorFound = true
									break
								}

								if strings.Contains(oldErr, action.Label) && strings.Contains(oldErr, "missing required parameter") {
									workflow.Errors[errIndex] += ", " + param.Name
									errorFound = true
									break
								}
							}

							if !errorFound {
								workflow.Errors = append(workflow.Errors, thisError)
							}

							action.IsValid = false
						}
					}

					if param.Variant == "" {
						param.Variant = "STATIC_VALUE"
					}

					found := false
					for paramIndex, newParam := range newParams {
						if newParam.Name == param.Name {
							if len(newParam.Value) == 0 && len(param.Value) > 0 {
								newParams[paramIndex].Value = param.Value
							}

							found = true
							break
						}
					}

					if !found {
						newParams = append(newParams, param)
					}
				}

				action.Parameters = newParams
				newActions = append(newActions, action)
			}

		}
	}

	for _, trigger := range workflow.Triggers {
		if trigger.Status != "running" && trigger.TriggerType != "SUBFLOW" && trigger.TriggerType != "USERINPUT" {

			// Schedules = parent controlled 
			if trigger.TriggerType == "SCHEDULE" && workflow.ParentWorkflowId != "" {
				continue
			}

			errorInfo := fmt.Sprintf("Trigger %s needs to be started", trigger.Name)
			if !ArrayContains(workflow.Errors, errorInfo) {
				workflow.Errors = append(workflow.Errors, errorInfo)
			}
		}
	}

	if orgUpdated && len(org.Name) > 0 && len(org.Id) > 0 && len(org.Users) > 0 {
		err = SetOrg(ctx, *org, org.Id)
		if err != nil {
			log.Printf("[WARNING] Failed setting org when autoadding apps and updating framework on save workflow save (%s): %s", workflow.ID, err)
		} else {
			log.Printf("[DEBUG] Successfully updated org %s during save of %s for user %s (%s", user.ActiveOrg.Id, workflow.ID, user.Username, user.Id)
		}
	}

	return workflow, allNodes, nil
}

func cleanupExecutionNodes(ctx context.Context, exec WorkflowExecution) WorkflowExecution {
	if exec.Status != "FINISHED" && exec.Status != "ABORTED" {
		return exec
	}

	if len(exec.Workflow.FormControl.CleanupActions) == 0 {
		return exec
	}

	for resultIndex, result := range exec.Results { 
		if !ArrayContains(exec.Workflow.FormControl.CleanupActions, result.Action.ID) {
			continue
		}

		if result.Status == "SUCCESS" || result.Status == "ABORTED" {

			exec.Results[resultIndex].Result = `{
				"success": true,
				"reason": "CLEANED. Edit the workflow to disable node cleanup."
			}`
		}
	}

	return exec 
}

func HandleRerunExecutions(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in Rerun executions: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
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

	if user.Role != "admin" {
		log.Printf("[AUDIT] User isn't admin during stop executions")
		resp.WriteHeader(409)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Must be admin to perform this action"}`)))
		return
	}

	if strings.ToLower(os.Getenv("SHUFFLE_DISABLE_RERUN_AND_ABORT")) == "true" {
		//log.Printf("[AUDIT] Rerunning is disabled by the SHUFFLE_DISABLE_RERUN_AND_ABORT argument. Stopping.")
		resp.WriteHeader(409)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "SHUFFLE_DISABLE_RERUN_AND_ABORT is active. Won't rerun executions."}`)))
		return
	}

	//ctx := GetContext(request)
	ctx := context.Background()
	environmentName := fileId
	if len(fileId) != 36 {
		log.Printf("[DEBUG] Environment length %d for %s is not good for reruns. Attempting to find the actual ID for it", len(fileId), fileId)

		environments, err := GetEnvironments(ctx, user.ActiveOrg.Id)
		if err != nil {
			log.Printf("[WARNING] Failed getting environments to validate: %s", err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Failed to validate environment"}`))
			return
		}

		for _, environment := range environments {
			if environment.Name == fileId && len(environment.Id) > 0 {
				environmentName = fileId
				fileId = environment.Id

				break
			}
		}

		if len(fileId) != 36 {
			log.Printf("[WARNING] Failed getting environments to validate. New FileId: %s", fileId)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Failed updating environment"}`))
			return
		}
	}

	// 1: Loop all workflows
	workflows, err := GetAllWorkflowsByQuery(ctx, user, 250, "")
	if err != nil {
		log.Printf("[WARNING] Failed getting workflows for user %s (0): %s", user.Username, err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	total := 0
	maxTotalReruns := 100
	for _, workflow := range workflows {
		if workflow.OrgId != user.ActiveOrg.Id {
			//log.Printf("[DEBUG] Skipping workflow for org %s (user: %s)", workflow.OrgId, user.Username)
			continue
		}

		if total > maxTotalReruns {
			log.Printf("[DEBUG] Stopping because more than %d (%d) executions are pending. Checking reruns again on next iteration", maxTotalReruns, total)
			break
		}

		cnt, err := RerunExecution(ctx, environmentName, workflow)
		if err != nil {
			log.Printf("[ERROR] Failed rerunning execution for workflow %s: %s", workflow.ID, err)
		}

		total += cnt
	}

	//log.Printf("[DEBUG] RERAN %d execution(s) in total for environment %s for org %s", total, fileId, user.ActiveOrg.Id)
	resp.WriteHeader(200)
	resp.Write([]byte(fmt.Sprintf(`{"success": true, "reason": "Successfully RERAN %d executions"}`, total)))
}

// Send in deleteall=true to delete ALL executions for the environment ID
func HandleStopExecutions(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in ABORT dangling executions: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
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
		if strings.Contains(fileId, "?") {
			fileId = strings.Split(fileId, "?")[0]
		}
	}

	if user.Role != "admin" {
		log.Printf("[AUDIT] User isn't admin during stop executions")
		resp.WriteHeader(409)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Must be admin to perform this action"}`)))
		return
	}

	ctx := GetContext(request)
	environmentName := fileId
	if len(fileId) != 36 {
		//log.Printf("[DEBUG] Runtime Location length %d for '%s' is not good for executions aborts. Attempting to find the actual ID for it", len(fileId), fileId)

		environments, err := GetEnvironments(ctx, user.ActiveOrg.Id)
		if err != nil {
			log.Printf("[WARNING] Failed getting environments to validate: %s", err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Failed to validate environment"}`))
			return
		}

		for _, environment := range environments {
			if environment.Name == fileId && len(environment.Id) > 0 {
				environmentName = fileId
				fileId = environment.Id
				break
			}
		}

		if len(fileId) != 36 {
			log.Printf("[WARNING] Failed getting environments to validate. New FileId: %s", fileId)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Failed updating environment"}`))
			return
		}
	}

	cleanAll := false
	deleteAll, ok := request.URL.Query()["deleteall"]

	if ok {
		if deleteAll[0] == "true" {
			cleanAll = true

			log.Printf("[DEBUG] Deleting and aborting ALL executions for this environment and org %s!", user.ActiveOrg.Id)

			env, err := GetEnvironment(ctx, fileId, user.ActiveOrg.Id)
			if err != nil {
				log.Printf("[WARNING] Failed to get environment %s for org %s", fileId, user.ActiveOrg.Id)
				resp.WriteHeader(401)
				resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed to get environment %s"}`, fileId)))
				return
			}

			if env.OrgId != user.ActiveOrg.Id {
				log.Printf("[WARNING] %s (%s) doesn't have permission to stop all executions for environment %s", user.Username, user.Id, fileId)
				resp.WriteHeader(401)
				resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "You don't have permission to stop environment executions for ID %s"}`, fileId)))
				return
			}

			// If here, it should DEFINITELY clean up all executions
			// Runs on 10.000 workflows max
			maxAmount := 1000
			queueName := env.Name
			if project.Environment == "cloud" {
				queueName = fmt.Sprintf("%s_%s", strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(env.Name, " ", "-"), "_", "-")), user.ActiveOrg.Id)
			} else {
				queueName = strings.ReplaceAll(env.Name, " ", "-")
			}

			for i := 0; i < 10; i++ {
				executionRequests, err := GetWorkflowQueue(ctx, queueName, maxAmount)
				log.Printf("[DEBUG] Got %d item(s) from queue %s to be deleted", len(executionRequests.Data), queueName)
				if err != nil {
					log.Printf("[WARNING] Jumping out of workflowqueue delete handler: %s", err)
					break
				}

				if len(executionRequests.Data) == 0 {
					//log.Printf("[DEBUG] No more executions in queue. Stopping")
					break
				}

				ids := []string{}
				for _, execution := range executionRequests.Data {
					if project.Environment != "cloud" {
						if !ArrayContains(execution.Environments, env.Name) {
							continue
						}
					}

					ids = append(ids, execution.ExecutionId)
				}

				log.Printf("[DEBUG] Deleting %d execution keys for org %s", len(ids), env.Name)

				parsedId := fmt.Sprintf("workflowqueue-%s", queueName)

				err = DeleteKeys(ctx, parsedId, ids)
				if err != nil {
					log.Printf("[ERROR] Failed deleting %d execution keys for org %s during force stop: %s", len(ids), env.Name, err)
				} else {
					log.Printf("[INFO] Deleted %d keys from org %s during force stop", len(ids), parsedId)
				}

				if len(executionRequests.Data) != maxAmount {
					log.Printf("[DEBUG] Less than 1000 in queue. Stopping search requests")
					break
				}
			}

			// Delete the index entirely
			indexName := "workflowqueue-" + queueName
			if project.Environment == "cloud" {
				indexName = fmt.Sprintf("workflowqueue-%s-%s", queueName, user.ActiveOrg.Id)
			}

			indexName = strings.ToLower(indexName)
			err = DeleteDbIndex(ctx, indexName)
			if err != nil {
				log.Printf("[ERROR] Failed deleting index %s: %s", indexName, err)
			}
		}
	}

	// Fix here by allowing cleanup from UI anyway :)
	if strings.ToLower(os.Getenv("SHUFFLE_DISABLE_RERUN_AND_ABORT")) == "true" {
		if ok && deleteAll[0] == "true" {
			log.Printf("[DEBUG] Allowing rerun and abort for environment %s for org %s with env set due to deleteall=true from frontend", fileId, user.ActiveOrg.Id)
		} else {
			//log.Printf("[AUDIT] Rerunning is disabled by the SHUFFLE_DISABLE_RERUN_AND_ABORT argument. Stopping. (abort)")
			resp.WriteHeader(409)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "SHUFFLE_DISABLE_RERUN_AND_ABORT is active. Won't rerun executions (abort)"}`)))
			return
		}
	}

	// 1: Loop all workflows
	// 2: Stop all running executions (manually abort)
	workflows, err := GetAllWorkflowsByQuery(ctx, user, 250, "")
	if err != nil {
		log.Printf("[WARNING] Failed getting workflows for user %s (0): %s", user.Username, err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	total := 0
	for _, workflow := range workflows {
		if workflow.OrgId != user.ActiveOrg.Id {
			log.Printf("[DEBUG] Skipping workflow for org %s (user: %s)", workflow.OrgId, user.Username)
			continue
		}

		cnt, _ := CleanupExecutions(ctx, environmentName, workflow, cleanAll)
		total += cnt
	}

	if total > 0 {
		log.Printf("[DEBUG] Stopped %d executions in total for environment %s for org %s", total, fileId, user.ActiveOrg.Id)
	}

	resp.WriteHeader(200)
	resp.Write([]byte(fmt.Sprintf(`{"success": true, "reason": "Successfully deleted and stopped %d executions"}`, total)))
}
