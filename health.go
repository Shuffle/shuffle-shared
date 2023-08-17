package shuffle

import (
	"context"
	"net/http"
	"fmt"
	"os"
	"io/ioutil"
	"strconv"
	"time"
	"log"
	"encoding/json"
)

func RunOpsAppHealthCheck() (AppHealth, error) {
	appHealth := AppHealth{
		Create: false,
		Run: false,
		Delete: false, 
	}

	return appHealth, nil
}

func RunOpsHealthCheck(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

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
				if platformHealth.Updated + 300 < time.Now().Unix() {
					marshalledData, err := json.Marshal(platformHealth) 
					if err == nil {
						resp.WriteHeader(200)
						resp.Write(marshalledData)
						return
					} 
				}

				log.Printf("[ERROR] Failed marshalling cached platform health data: %s", err)
			}
		}
	}


	// Use channel for getting RunOpsWorkflow function results
	workflowHealthChannel := make(chan WorkflowHealth)
	appHealthChannel := make(chan AppHealth)
	go func() {
		workflowHealth, err := RunOpsWorkflow()
		if err != nil {
			workflowHealthChannel <- workflowHealth
			return
		}
		workflowHealthChannel <- workflowHealth
	}()

	go func() {
		appHealth, err := RunOpsAppHealthCheck()
		if err != nil {
			appHealthChannel <- appHealth
			return
		}
		appHealthChannel <- appHealth
	}()

	// Use channel for getting RunOpsWorkflow function results
	platformHealth.Apps = <- appHealthChannel
	platformHealth.Workflows = <- workflowHealthChannel

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
		// Caching for 15 min. Will rerun every 5 min.
		err = SetCache(ctx, cacheKey, platformData, 15)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache ops health: %s", err)
		}
	}

	resp.WriteHeader(200)
	resp.Write(platformData)
}

func RunOpsWorkflow() (WorkflowHealth, error) {
	// run workflow with id 602c7cf5-500e-4bd1-8a97-aa5bc8a554e6
	ctx := context.Background()

	workflowHealth := WorkflowHealth{
		Create: false,
		Run: false,
		RunFinished: false,
		Delete: false,
	}

	// 1. Get workflow
	opsWorkflowID := "602c7cf5-500e-4bd1-8a97-aa5bc8a554e6"
	workflowPtr, err := GetWorkflow(ctx, opsWorkflowID)
	if err != nil {
		log.Printf("[ERROR] Failed getting workflow: %s", err)
		return workflowHealth, err
	}

	workflow := *workflowPtr

	// 2. Check if workflow ran in last SHUFFLE_OPS_WORKFLOW_RUN_TIME seconds
	opsShuffleRunTime := os.Getenv("SHUFFLE_OPS_WORKFLOW_RUN_TIME")
	if len(opsShuffleRunTime) == 0 {
		opsShuffleRunTime = "3600"
	}

	opsShuffleRunTimeInt, err := strconv.Atoi(opsShuffleRunTime)
	if err != nil {
		log.Printf("[ERROR] Failed converting SHUFFLE_OPS_WORKFLOW_RUN_TIME to int: %s", err)
		return workflowHealth, err
	}

	// 2.1 Get workflow executions
	workflowExecutions, err := GetAllWorkflowExecutions(ctx, opsWorkflowID, 1)

	// 2.2 Check if workflow ran in last SHUFFLE_OPS_WORKFLOW_RUN_TIME seconds
	if len(workflowExecutions) != 0 {
		// get last workflow execution
		lastWorkflowExecution := workflowExecutions[len(workflowExecutions)-1]

		lastWorkflowExecutionTimeInt := lastWorkflowExecution.StartedAt
		if err != nil {
			log.Printf("[ERROR] Failed converting last workflow execution time to int: %s", err)
			return workflowHealth, err
		}

		// check if last workflow execution time is less than SHUFFLE_OPS_WORKFLOW_RUN_TIME seconds
		if lastWorkflowExecutionTimeInt+int64(opsShuffleRunTimeInt) > int64(time.Now().Unix()) {
			log.Printf("[INFO] Last workflow execution time is less than SHUFFLE_OPS_WORKFLOW_RUN_TIME seconds. Returning last result")
			//lastWorkflowExecutionResultsJson, err  := json.Marshal(lastWorkflowExecution.Results)
			//if err != nil {
			//	log.Printf("[ERROR] Failed marshalling last workflow execution results: %s", err)
			//	return workflowHealth, err
			//}

			return workflowHealth, nil
		}
	}

	// 3. Run workflow
	id := workflow.ID
	orgId := os.Getenv("SHUFFLE_OPS_DASHBOARD_ORG")
	_ = id 
	_ = orgId

	workflowHealth.Run = true


	/*
		@0x0eliot: Replace this with an API call to do this.
		The point is to test the API, not just the function 
	*/
	/*
	execution, _, err := handleExecution(id, workflow, request, orgId)
	if err != nil {
		log.Printf("[ERROR] Failed running workflow: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed running workflow"}`))
		return
	}

	// JSONify execution.Results
	executionResultsJson, _ := json.Marshal(execution.Results)
	*/

	//resp.WriteHeader(200)
	//resp.Write([]byte(fmt.Sprintf(`{"success": true, "result": %s}`, executionResultsJson)))
	return workflowHealth, nil
}

func InitOpsWorkflow() {
	opsDashboardApikey := os.Getenv("SHUFFLE_OPS_DASHBOARD_APIKEY")
	if len(opsDashboardApikey) == 0 {
		log.Printf("[WARNING] Ops dashboard api key not set. Not setting up ops workflow")
		return
	}

	opsDashboardOrgId := os.Getenv("SHUFFLE_OPS_DASHBOARD_ORG")
	if len(opsDashboardOrgId) == 0 {
		log.Printf("[WARNING] Ops dashboard org not set. Not setting up ops workflow")
		return
	}

	// verify if org with id opsDashboardOrg exists
	ctx := context.Background()
	opsDashboardOrg, err := GetOrg(ctx, opsDashboardOrgId)
	if err != nil {
		log.Printf("[ERROR] Ops dashboard org not found. Not setting up ops workflow")
		return
	}

	user, err := GetApikey(ctx, opsDashboardApikey)
	if err != nil {
		log.Printf("[ERROR] Error in finding user: %s", err)
		return
	}
	
	if len(user.Id) == 0 && len(user.Username) == 0 {
		fmt.Println("[ERROR] Ops dashboard user not found. Not setting up ops workflow")
		return
	}

	if user.Role != "admin" {
		log.Printf("[WARNING] Ops dashboard user not admin. Not setting up ops workflow")
		return
	}


	// make a GET request to https://shuffler.io/api/v1/workflows/602c7cf5-500e-4bd1-8a97-aa5bc8a554e6
	// to get the workflow
	workflow, err := GetWorkflow(ctx, "602c7cf5-500e-4bd1-8a97-aa5bc8a554e6")
	if err == nil {
		log.Printf("[WARNING] Ops workflow exists. Not setting it up.")
		// JSONify workflow and print it
		// workflowJson, _ := json.Marshal(workflow)
		// log.Printf("[DEBUG] Ops workflow: %s", workflowJson)
		// DeleteKey(ctx, "workflow", workflow.ID)
		// log.Printf("[INFO] Ops workflow deleted successfully")
		return
	}

	log.Printf("[INFO] Ops Workflow not found. Moving further.")

	url := "https://shuffler.io/api/v1/workflows/602c7cf5-500e-4bd1-8a97-aa5bc8a554e6"

	// Create a new HTTP GET request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("[ERROR] creating HTTP request:", err)
		return
	}

    // Send the HTTP request using the default HTTP client
    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        fmt.Println("[ERROR] sending HTTP request:", err)
        return
    }

	defer resp.Body.Close()

    // Read the response body
    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        fmt.Println("[ERROR] reading HTTP response body:", err)
        return
    }

	// Unmarshal the JSON data into a Workflow instance
	var workflowData Workflow
	err = json.Unmarshal(body, &workflowData)
	if err != nil {
		fmt.Println("[ERROR] unmarshalling JSON data:", err)
		return
	}

	variables := workflow.WorkflowVariables
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
		if project.Environment != "cloud" {
			action.Environment = "Shuffle"
		} else {
			action.Environment = "Cloud"
		}

		if action.Position.X == 206 {
			action.Position.X = 206.1
		}

		action.Position.X = float64(action.Position.X)
		action.Position.Y = float64(action.Position.Y)

		log.Println(action.Position.X)
		log.Println(action.Position.Y)

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
		Id:   opsDashboardOrg.Id,
		Name: opsDashboardOrg.Name,
		Users: []UserMini{},
	}
	
	workflowData.WorkflowVariables = variables

	// Save the workflow
	err = SetWorkflow(ctx, workflowData, workflowData.ID)
	if err != nil {
		fmt.Println("[ERROR] saving ops dashboard workflow:", err)
		return
	}
	fmt.Println("[INFO] Ops dashboard workflow saved successfully")
}
