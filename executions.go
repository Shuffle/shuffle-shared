package shuffle

// This file contains all the function
// related to managing workflows

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	//"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"encoding/json"

	"github.com/satori/go.uuid"
)

func HandleRerunExecutions(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in stop executions: %s", err)
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
		log.Printf("[AUDIT] Rerunning is disabled by the SHUFFLE_DISABLE_RERUN_AND_ABORT argument. Stopping.")
		resp.WriteHeader(409)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "SHUFFLE_DISABLE_RERUN_AND_ABORT is active. Won't rerun executions."}`)))
		return
	}

	ctx := GetContext(request)
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
	// 2: Stop all running executions (manually abort)
	workflows, err := GetAllWorkflowsByQuery(ctx, user)
	if err != nil {
		log.Printf("[WARNING] Failed getting workflows for user %s (0): %s", user.Username, err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	maxTotalReruns := 100
	total := 0
	for _, workflow := range workflows {
		if workflow.OrgId != user.ActiveOrg.Id {
			//log.Printf("[DEBUG] Skipping workflow for org %s (user: %s)", workflow.OrgId, user.Username)
			continue
		}

		if total > maxTotalReruns {
			log.Printf("[DEBUG] Stopping because more than %d (%d) executions are pending. Checking reruns again on next iteration", maxTotalReruns, total)
			break
		}

		cnt, _ := RerunExecution(ctx, environmentName, workflow)
		total += cnt
	}

	//log.Printf("[DEBUG] RERAN %d execution(s) in total for environment %s for org %s", total, fileId, user.ActiveOrg.Id)
	resp.WriteHeader(200)
	resp.Write([]byte(fmt.Sprintf(`{"success": true, "reason": "Successfully RERAN and stopped %d executions"}`, total)))
}

// Send in deleteall=true to delete ALL executions for the environment ID
func HandleStopExecutions(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in stop executions: %s", err)
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

	if strings.ToLower(os.Getenv("SHUFFLE_DISABLE_RERUN_AND_ABORT")) == "true" {
		log.Printf("[AUDIT] Rerunning is disabled by the SHUFFLE_DISABLE_RERUN_AND_ABORT argument. Stopping. (abort)")
		resp.WriteHeader(409)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "SHUFFLE_DISABLE_RERUN_AND_ABORT is active. Won't rerun executions (abort)"}`)))
		return
	}

	ctx := GetContext(request)
	environmentName := fileId
	if len(fileId) != 36 {
		log.Printf("[DEBUG] Environment length %d for %s is not good for executions aborts. Attempting to find the actual ID for it", len(fileId), fileId)

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

			if project.Environment != "cloud" {
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
				for i := 0; i < 10; i++ {
					executionRequests, err := GetWorkflowQueue(ctx, env.Name, maxAmount)
					if err != nil {
						log.Printf("[WARNING] Jumping out of workflowqueue delete handler: %s", err)
						break
					}

					if len(executionRequests.Data) == 0 {
						break
					}

					ids := []string{}
					for _, execution := range executionRequests.Data {
						if !ArrayContains(execution.Environments, env.Name) {
							continue
						}

						ids = append(ids, execution.ExecutionId)
					}

					parsedId := fmt.Sprintf("workflowqueue-%s", strings.ToLower(env.Name))
					err = DeleteKeys(ctx, parsedId, ids)
					if err != nil {
						log.Printf("[ERROR] Failed deleting %d execution keys for org %s during force stop: %s", len(ids), env.Name, err)
					} else {
						log.Printf("[INFO] Deleted %d keys from org %s during force stop", len(ids), parsedId)
					}

					if len(executionRequests.Data) != maxAmount {
						log.Printf("[DEBUG] Less than 1000 in queue. Not querying more")
						break
					}
				}
			}
		}
	}

	// 1: Loop all workflows
	// 2: Stop all running executions (manually abort)
	workflows, err := GetAllWorkflowsByQuery(ctx, user)
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

func RerunExecution(ctx context.Context, environment string, workflow Workflow) (int, error) {
	maxReruns := 100
	//log.Printf("[DEBUG] Finding executions for %s", workflow.ID)
	executions, err := GetUnfinishedExecutions(ctx, workflow.ID)
	if err != nil {
		log.Printf("[DEBUG] Failed getting executions for workflow %s", workflow.ID)
		return 0, err
	}

	if len(executions) == 0 {
		return 0, nil
	}

	//log.Printf("[DEBUG] Found %d POTENTIALLY unfinished executions for workflow %s (%s) with environment %s that are more than 30 minutes old", len(executions), workflow.Name, workflow.ID, environment)
	//log.Printf("[DEBUG] Found %d unfinished executions for workflow %s (%s) with environment %s that are more than 30 minutes old", len(executions), workflow.Name, workflow.ID, environment)

	//backendUrl := os.Getenv("BASE_URL")
	//if project.Environment == "cloud" {
	//	backendUrl = "https://shuffler.io"
	//} else {
	//	backendUrl = "http://127.0.0.1:5001"
	//}

	//topClient := &http.Client{
	//	Transport: &http.Transport{
	//		Proxy: nil,
	//	},
	//}
	//_ = backendUrl
	//_ = topClient

	//StartedAt           int64          `json:"started_at" datastore:"started_at"`
	timeNow := int64(time.Now().Unix())
	cnt := 0

	// Rerun after 570 seconds (9.5 minutes), ensuring it can check 3 times before
	// automated aborting of the execution happens
	waitTime := 270
	//waitTime := 0
	executed := []string{}
	for _, execution := range executions {
		if timeNow < execution.StartedAt+int64(waitTime) {
			//log.Printf("Bad timing: %d", execution.StartedAt)
			continue
		}

		if execution.Status != "EXECUTING" {
			//log.Printf("Bad status: %s", execution.Status)
			continue
		}

		if ArrayContains(executed, execution.ExecutionId) {
			continue
		}

		executed = append(executed, execution.ExecutionId)

		found := false
		environments := []string{}
		for _, action := range execution.Workflow.Actions {
			if action.Environment == environment {
				environments = append(environments, action.Environment)
				found = true
				break
			}
		}

		if len(environments) == 0 {
			found = true
		}

		if !found {
			continue
		}

		if cnt > maxReruns {
			log.Printf("[DEBUG] Breaking because more than 100 executions are executing")
			break
		}

		if project.Environment != "cloud" {
			executionRequest := ExecutionRequest{
				ExecutionId:   execution.ExecutionId,
				WorkflowId:    execution.Workflow.ID,
				Authorization: execution.Authorization,
				Environments:  environments,
			}

			executionRequest.Priority = execution.Priority
			err = SetWorkflowQueue(ctx, executionRequest, environment)
			if err != nil {
				log.Printf("[ERROR] Failed re-adding execution to db: %s", err)
			}
		} else {
			log.Printf("[DEBUG] Rerunning executions is not available in cloud yet.")
		}

		cnt += 1
		log.Printf("[DEBUG] Should rerun execution %s (%s - Workflow: %s) with environments %#v", execution.ExecutionId, execution.Status, execution.Workflow.ID, environments)
		//log.Printf("[DEBUG] Result from rerunning %s: %s", execution.ExecutionId, string(body))
	}

	return cnt, nil
}

func CleanupExecutions(ctx context.Context, environment string, workflow Workflow, cleanAll bool) (int, error) {
	executions, err := GetUnfinishedExecutions(ctx, workflow.ID)
	if err != nil {
		log.Printf("[DEBUG] Failed getting executions for workflow %s", workflow.ID)
		return 0, err
	}

	if len(executions) == 0 {
		return 0, nil
	}

	//log.Printf("[DEBUG] Found %d POTENTIALLY unfinished executions for workflow %s (%s) with environment %s that are more than 30 minutes old", len(executions), workflow.Name, workflow.ID, environment)
	//log.Printf("[DEBUG] Found %d unfinished executions for workflow %s (%s) with environment %s that are more than 30 minutes old", len(executions), workflow.Name, workflow.ID, environment)

	backendUrl := os.Getenv("BASE_URL")
	// Redundant, but working ;)
	if project.Environment == "cloud" {
		backendUrl = "https://shuffler.io"

		if len(os.Getenv("SHUFFLE_GCEPROJECT")) > 0 && len(os.Getenv("SHUFFLE_GCEPROJECT_LOCATION")) > 0 {
			backendUrl = fmt.Sprintf("https://%s.%s.r.appspot.com", os.Getenv("SHUFFLE_GCEPROJECT"), os.Getenv("SHUFFLE_GCEPROJECT_LOCATION"))
		}

		if len(os.Getenv("SHUFFLE_CLOUDRUN_URL")) > 0 {
			backendUrl = os.Getenv("SHUFFLE_CLOUDRUN_URL")
		}

	} else {
		backendUrl = "http://127.0.0.1:5001"
	}

	topClient := &http.Client{
		Transport: &http.Transport{
			Proxy: nil,
		},
	}

	//StartedAt           int64          `json:"started_at" datastore:"started_at"`
	timeNow := int64(time.Now().Unix())
	cnt := 0
	for _, execution := range executions {
		if cleanAll {
		} else if timeNow < execution.StartedAt+1800 {
			//log.Printf("Bad timing: %d", execution.StartedAt)
			continue
		}

		if execution.Status != "EXECUTING" {
			//log.Printf("Bad status: %s", execution.Status)
			continue
		}

		found := false
		environments := []string{}
		for _, action := range execution.Workflow.Actions {
			if action.Environment == environment {
				environments = append(environments, action.Environment)
				found = true
				break
			}
		}

		if len(environments) == 0 {
			found = true
		}

		if !found {
			continue
		}

		//log.Printf("[DEBUG] Got execution with status %s!", execution.Status)

		streamUrl := fmt.Sprintf("%s/api/v1/workflows/%s/executions/%s/abort?reason=%s", backendUrl, execution.Workflow.ID, execution.ExecutionId, url.QueryEscape(`{"success": False, "reason": "Shuffle's automated cleanup bot stopped this execution as it didn't finish within 30 minutes."}`))
		//log.Printf("Url: %s", streamUrl)
		req, err := http.NewRequest(
			"GET",
			streamUrl,
			nil,
		)

		if err != nil {
			log.Printf("[ERROR] Error in auto-abort request: %s", err)
			continue
		}

		req.Header.Add("Authorization", fmt.Sprintf(`Bearer %s`, execution.Authorization))
		newresp, err := topClient.Do(req)
		if err != nil {
			log.Printf("[ERROR] Error auto-aborting workflow: %s", err)
			continue
		}

		body, err := ioutil.ReadAll(newresp.Body)
		if err != nil {
			log.Printf("[ERROR] Failed reading parent body: %s", err)
			continue
		}
		//log.Printf("BODY (%d): %s", newresp.StatusCode, string(body))

		if newresp.StatusCode != 200 {
			log.Printf("[ERROR] Bad statuscode in auto-abort: %d, %s", newresp.StatusCode, string(body))
			continue
		}

		cnt += 1
		log.Printf("[DEBUG] Result from aborting %s: %s", execution.ExecutionId, string(body))
	}

	return cnt, nil
}

func GetWorkflowExecutions(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in getting workflow executions: %s", err)
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

	if len(fileId) != 36 {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Workflow ID when getting workflow executions is not valid"}`))
		return
	}

	ctx := GetContext(request)
	workflow, err := GetWorkflow(ctx, fileId)
	if err != nil {
		log.Printf("[WARNING] Failed getting the workflow %s locally (get executions): %s", fileId, err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	// FIXME - have a check for org etc too..
	if user.Id != workflow.Owner || len(user.Id) == 0 {
		if workflow.OrgId == user.ActiveOrg.Id && (user.Role == "admin" || user.Role == "org-reader") {
			log.Printf("[AUDIT] User %s is accessing workflow %#v (%s) executions as %s (get executions)", user.Username, workflow.Name, workflow.ID, user.Role)
		} else if project.Environment == "cloud" && user.Verified == true && user.Active == true && user.SupportAccess == true && strings.HasSuffix(user.Username, "@shuffler.io") {
			log.Printf("[AUDIT] Letting verified support admin %s access workflow execs for %s", user.Username, workflow.ID)
		} else {
			log.Printf("[AUDIT] Wrong user (%s) for workflow %s (get workflow execs)", user.Username, workflow.ID)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}
	}

	// Query for the specifci workflowId
	//q := datastore.NewQuery("workflowexecution").Filter("workflow_id =", fileId).Order("-started_at").Limit(30)
	//q := datastore.NewQuery("workflowexecution").Filter("workflow_id =", fileId)
	maxAmount := 100
	top, topOk := request.URL.Query()["top"]
	if topOk && len(top) > 0 {
		val, err := strconv.Atoi(top[0])
		if err == nil {
			maxAmount = val
		}
	}

	if maxAmount > 1000 {
		maxAmount = 1000
	}

	workflowExecutions, err := GetAllWorkflowExecutions(ctx, fileId, maxAmount)
	if err != nil {
		log.Printf("[WARNING] Failed getting executions for %s", fileId)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	//log.Printf("[DEBUG] Got %d executions", len(workflowExecutions))

	if len(workflowExecutions) == 0 {
		resp.WriteHeader(200)
		resp.Write([]byte("[]"))
		return
	}

	for index, execution := range workflowExecutions {
		newResults := []ActionResult{}
		for _, result := range execution.Results {
			newParams := []WorkflowAppActionParameter{}
			for _, param := range result.Action.Parameters {
				//log.Printf("PARAM: %#v", param)
				if param.Configuration || strings.Contains(strings.ToLower(param.Name), "user") || strings.Contains(strings.ToLower(param.Name), "key") || strings.Contains(strings.ToLower(param.Name), "pass") {
					param.Value = ""
					//log.Printf("FOUND CONFIG: %s!!", param.Name)
				}

				newParams = append(newParams, param)
			}

			result.Action.Parameters = newParams
			newResults = append(newResults, result)
		}

		workflowExecutions[index].Results = newResults
	}

	newjson, err := json.Marshal(workflowExecutions)
	if err != nil {
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed unpacking workflow executions"}`)))
		return
	}

	resp.WriteHeader(200)
	resp.Write(newjson)
}

func AbortExecution(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
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
		resp.Write([]byte(`{"success": false, "reason": "Workflow ID to abort is not valid"}`))
		return
	}

	executionId := location[6]
	if len(executionId) != 36 {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "ExecutionID not valid"}`))
		return
	}

	ctx := GetContext(request)
	workflowExecution, err := GetWorkflowExecution(ctx, executionId)
	if err != nil {
		log.Printf("[ERROR] Failed getting execution (abort) %s: %s", executionId, err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed getting execution ID %s because it doesn't exist (abort)."}`, executionId)))
		return
	}

	apikey := request.Header.Get("Authorization")
	parsedKey := ""
	if strings.HasPrefix(apikey, "Bearer ") {
		apikeyCheck := strings.Split(apikey, " ")
		if len(apikeyCheck) == 2 {
			parsedKey = apikeyCheck[1]
		}
	}

	// Checks the users' role and such if the key fails
	//log.Printf("Abort info: %#v vs %#v", workflowExecution.Authorization, parsedKey)
	if workflowExecution.Authorization != parsedKey {
		user, err := HandleApiAuthentication(resp, request)
		if err != nil {
			log.Printf("[AUDIT] Api authentication failed in abort workflow: %s", err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		//log.Printf("User: %s, org: %s vs %s", user.Role, workflowExecution.Workflow.OrgId, user.ActiveOrg.Id)
		if user.Id != workflowExecution.Workflow.Owner {
			if workflowExecution.Workflow.OrgId == user.ActiveOrg.Id && user.Role == "admin" {
				log.Printf("[AUDIT] User %s is aborting execution %s as admin", user.Username, workflowExecution.Workflow.ID)
			} else {
				log.Printf("[AUDIT] Wrong user (%s) for ABORT of workflowexecution workflow %s", user.Username, workflowExecution.Workflow.ID)
				resp.WriteHeader(401)
				resp.Write([]byte(`{"success": false}`))
				return
			}
		}
	} else {
		//log.Printf("[INFO] API key to abort/finish execution %s is correct.", executionId)
	}

	if workflowExecution.Status == "ABORTED" || workflowExecution.Status == "FAILURE" || workflowExecution.Status == "FINISHED" {
		//err = SetWorkflowExecution(ctx, *workflowExecution, true)
		//if err != nil {
		//}
		log.Printf("[INFO] Stopped execution of %s with status %s", executionId, workflowExecution.Status)
		if len(workflowExecution.ExecutionParent) > 0 {
		}

		//ExecutionSource    string         `json:"execution_source" datastore:"execution_source"`
		//ExecutionParent    string         `json:"execution_parent" datastore:"execution_parent"`

		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Status for %s is %s, which can't be aborted."}`, executionId, workflowExecution.Status)))
		return
	}

	topic := "workflowexecution"

	workflowExecution.CompletedAt = int64(time.Now().Unix())
	workflowExecution.Status = "ABORTED"
	log.Printf("[INFO] Running shutdown (abort) of execution %s", workflowExecution.ExecutionId)

	lastResult := ""
	newResults := []ActionResult{}
	// type ActionResult struct {
	for _, result := range workflowExecution.Results {
		if result.Status == "EXECUTING" {
			result.Status = "ABORTED"
			result.Result = "Aborted because of error in another node (1)"
		}

		if len(result.Result) > 0 {
			lastResult = result.Result
		}

		newResults = append(newResults, result)
	}

	workflowExecution.Results = newResults
	if len(workflowExecution.Result) == 0 {
		workflowExecution.Result = lastResult
	}

	addResult := true
	for _, result := range workflowExecution.Results {
		if result.Status != "SKIPPED" {
			addResult = false
		}
	}

	extra := 0
	for _, trigger := range workflowExecution.Workflow.Triggers {
		//log.Printf("Appname trigger (0): %s", trigger.AppName)
		if trigger.AppName == "User Input" || trigger.AppName == "Shuffle Workflow" {
			extra += 1
		}
	}

	parsedReason := "An error occurred during execution of this node"
	reason, reasonok := request.URL.Query()["reason"]
	if reasonok {
		parsedReason = reason[0]
	}

	returnData := SubflowData{
		Success: false,
		Result:  parsedReason,
	}

	reasonData, err := json.Marshal(returnData)
	if err != nil {
		reasonData = []byte(parsedReason)
	}

	if len(workflowExecution.Results) == 0 || addResult {
		newaction := Action{
			ID: workflowExecution.Start,
		}

		for _, action := range workflowExecution.Workflow.Actions {
			if action.ID == workflowExecution.Start {
				newaction = action
				break
			}
		}

		workflowExecution.Results = append(workflowExecution.Results, ActionResult{
			Action:        newaction,
			ExecutionId:   workflowExecution.ExecutionId,
			Authorization: workflowExecution.Authorization,
			Result:        string(reasonData),
			StartedAt:     workflowExecution.StartedAt,
			CompletedAt:   workflowExecution.StartedAt,
			Status:        "FAILURE",
		})
	} else if len(workflowExecution.Results) >= len(workflowExecution.Workflow.Actions)+extra {
		log.Printf("[INFO] DONE - Nothing to add during abort!")
	} else {
		//log.Printf("VALIDATING INPUT!")
		node, nodeok := request.URL.Query()["node"]
		if nodeok {
			nodeId := node[0]
			log.Printf("[INFO] Found abort node %s", nodeId)
			newaction := Action{
				ID: nodeId,
			}

			// Check if result exists first
			found := false
			for _, result := range workflowExecution.Results {
				if result.Action.ID == nodeId {
					found = true
					break
				}
			}

			if !found {
				for _, action := range workflowExecution.Workflow.Actions {
					if action.ID == nodeId {
						newaction = action
						break
					}
				}

				workflowExecution.Results = append(workflowExecution.Results, ActionResult{
					Action:        newaction,
					ExecutionId:   workflowExecution.ExecutionId,
					Authorization: workflowExecution.Authorization,
					Result:        string(reasonData),
					StartedAt:     workflowExecution.StartedAt,
					CompletedAt:   workflowExecution.StartedAt,
					Status:        "FAILURE",
				})
			}
		}
	}

	for resultIndex, result := range workflowExecution.Results {
		for parameterIndex, param := range result.Action.Parameters {
			if param.Configuration {
				workflowExecution.Results[resultIndex].Action.Parameters[parameterIndex].Value = ""
			}
		}
	}

	for actionIndex, action := range workflowExecution.Workflow.Actions {
		for parameterIndex, param := range action.Parameters {
			if param.Configuration {
				//log.Printf("Cleaning up %s in %s", param.Name, action.Name)
				workflowExecution.Workflow.Actions[actionIndex].Parameters[parameterIndex].Value = ""
			}
		}
	}

	// This is the same as aborted
	IncrementCache(ctx, workflowExecution.ExecutionOrg, "workflow_executions_failed")
	err = SetWorkflowExecution(ctx, *workflowExecution, true)
	if err != nil {
		log.Printf("[WARNING] Error saving workflow execution for updates when aborting (2) %s: %s", topic, err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed setting workflowexecution status to abort"}`)))
		return
	} else {
		log.Printf("[INFO] Set workflowexecution %s to aborted.", workflowExecution.ExecutionId)
	}

	resp.WriteHeader(200)
	resp.Write([]byte(fmt.Sprintf(`{"success": true}`)))
}

// Handles workflow executions across systems (open source, worker, cloud)
// getWorkflow
// GetWorkflow
// executeWorkflow

// This should happen locally.. Meaning, polling may be stupid.
// Let's do it anyway, since it seems like the best way to scale
// without remoting problems and the like.
func updateExecutionParent(ctx context.Context, executionParent, returnValue, parentAuth, parentNode, subflowExecutionId string) error {

	// Was an error here. Now defined to run with http://shuffle-backend:5001 by default
	backendUrl := os.Getenv("BASE_URL")
	if project.Environment == "cloud" {
		backendUrl = "https://shuffler.io"

		if len(os.Getenv("SHUFFLE_GCEPROJECT")) > 0 && len(os.Getenv("SHUFFLE_GCEPROJECT_LOCATION")) > 0 {
			backendUrl = fmt.Sprintf("https://%s.%s.r.appspot.com", os.Getenv("SHUFFLE_GCEPROJECT"), os.Getenv("SHUFFLE_GCEPROJECT_LOCATION"))
		}

		if len(os.Getenv("SHUFFLE_CLOUDRUN_URL")) > 0 {
			backendUrl = os.Getenv("SHUFFLE_CLOUDRUN_URL")
		}

		//backendUrl = "http://localhost:5002"
	}

	// FIXME: This MAY fail at scale due to not being able to get the right worker
	// Maybe we need to pass the worker's real id, and not its VIP?
	if os.Getenv("SHUFFLE_SWARM_CONFIG") == "run" && (project.Environment == "" || project.Environment == "worker") {
		backendUrl = "http://shuffle-workers:33333"

		hostenv := os.Getenv("WORKER_HOSTNAME")
		if len(hostenv) > 0 {
			backendUrl = fmt.Sprintf("http://%s:33333", hostenv)
		}

		// From worker:
		//parsedRequest.BaseUrl = fmt.Sprintf("http://%s:%d", hostname, baseport)

		//log.Printf("[DEBUG] Sending request for shuffle-subflow result to %s", backendUrl)
	}

	//log.Printf("[INFO] PARENTEXEC: %s, AUTH: %s, parentNode: %s, BackendURL: %s, VALUE: %s. ", executionParent, parentAuth, parentNode, backendUrl, returnValue)

	// Callback to itself
	if len(backendUrl) == 0 {
		backendUrl = "http://localhost:5001"
	}

	resultUrl := fmt.Sprintf("%s/api/v1/streams/results", backendUrl)
	//log.Printf("[DEBUG] ResultURL: %s", backendUrl)
	topClient := &http.Client{
		Transport: &http.Transport{
			Proxy: nil,
		},
	}
	newExecution := WorkflowExecution{}

	httpProxy := os.Getenv("HTTP_PROXY")
	httpsProxy := os.Getenv("HTTPS_PROXY")
	if len(httpProxy) > 0 || len(httpsProxy) > 0 {
		topClient = &http.Client{}
	} else {
		if len(httpProxy) > 0 {
			log.Printf("Running with HTTP proxy %s (env: HTTP_PROXY)", httpProxy)
		}
		if len(httpsProxy) > 0 {
			log.Printf("Running with HTTPS proxy %s (env: HTTPS_PROXY)", httpsProxy)
		}
	}

	requestData := ActionResult{
		Authorization: parentAuth,
		ExecutionId:   executionParent,
	}

	data, err := json.Marshal(requestData)
	if err != nil {
		log.Printf("[WARNING] Failed parent init marshal: %s", err)
		return err
	}

	req, err := http.NewRequest(
		"POST",
		resultUrl,
		bytes.NewBuffer([]byte(data)),
	)

	newresp, err := topClient.Do(req)
	if err != nil {
		log.Printf("[ERROR] Failed making parent request: %s. Is URL valid: %s", err, backendUrl)
		return err
	}

	body, err := ioutil.ReadAll(newresp.Body)
	if err != nil {
		log.Printf("[ERROR] Failed reading parent body: %s", err)
		return err
	}
	//log.Printf("BODY (%d): %s", newresp.StatusCode, string(body))

	if newresp.StatusCode != 200 {
		log.Printf("[ERROR] Bad statuscode setting subresult with URL %s: %d, %s", resultUrl, newresp.StatusCode, string(body))
		return errors.New(fmt.Sprintf("Bad statuscode: %s", newresp.StatusCode))
	}

	err = json.Unmarshal(body, &newExecution)
	if err != nil {
		log.Printf("[ERROR] Failed newexecutuion parent unmarshal: %s", err)
		return err
	}

	foundResult := ActionResult{}
	for _, result := range newExecution.Results {
		if result.Action.ID == parentNode {
			foundResult = result
			break
		}
	}

	//log.Printf("FOUND RESULT: %#v", foundResult)
	isLooping := false
	selectedTrigger := Trigger{}
	for _, trigger := range newExecution.Workflow.Triggers {
		if trigger.ID == parentNode {
			selectedTrigger = trigger
			for _, param := range trigger.Parameters {
				if param.Name == "argument" && strings.Contains(param.Value, "$") && strings.Contains(param.Value, ".#") {
					isLooping = true
					break
				}
			}

			break
		}
	}

	// IF the workflow is looping, the result is added in the backend to not
	// cause consistency issues. This means the result will be sent back, and instead
	// Added to the workflow result by the backend itself.
	// When all the "WAITING" executions are done, the backend will set the execution itself
	// back to executing, allowing the parent to continue
	sendRequest := false
	resultData := []byte{}
	if isLooping {
		//log.Printf("\n\n[DEBUG] ITS LOOPING - SHOULD ADD TO A LIST INSTEAD!\n\n")

		subflowResultCacheId := fmt.Sprintf("%s_%s_subflowresult", subflowExecutionId, parentNode)
		err = SetCache(ctx, subflowResultCacheId, []byte(returnValue))
		if err != nil {
			log.Printf("\n\n\n[ERROR] Failed setting subflow loop cache result for action in parsed exec results %s: %s\n\n", subflowResultCacheId, err)
			return err
		}

		// Every time we get here, we need to both SET the value in cache AND look for other values in cache to make sure the list is good.
		parentNodeFound := false
		var parentSubflowResult []SubflowData
		for _, result := range newExecution.Results {
			if result.Action.ID == parentNode {
				//log.Printf("[DEBUG] FOUND RES: %#v", foundResult.Result)

				parentNodeFound = true
				err = json.Unmarshal([]byte(foundResult.Result), &parentSubflowResult)
				if err != nil {
					log.Printf("[ERROR] Failed to unmarshal result to parentsubflow res: %s", err)
					continue
				}

				break
			}
		}

		// If found, loop through and make sure to check the result for ALL of them. If they're not in there, add them as values.
		if parentNodeFound {
			//log.Printf("[DEBUG] Found result for subflow. Adding!")

			ranUpdate := false

			newResults := []SubflowData{}
			finishedSubflows := 0
			for _, res := range parentSubflowResult {
				// If value length = 0 for any, then check cache and add the result
				//log.Printf("[DEBUG] EXEC: %#v", res)
				if res.ExecutionId == subflowExecutionId {
					//foundResult.Result
					res.Result = string(returnValue)
					res.ResultSet = true

					ranUpdate = true

					//log.Printf("[DEBUG] Set the result for the node! Run update with %#v", res)
					finishedSubflows += 1
				} else {
					//log.Printf("[DEBUG] Does it have a result? %#v", res)

					if !res.ResultSet {
						subflowResultCacheId = fmt.Sprintf("%s_%s_subflowresult", res.ExecutionId, parentNode)

						cache, err := GetCache(ctx, subflowResultCacheId)
						if err == nil {
							cacheData := []byte(cache.([]uint8))
							//log.Printf("[DEBUG] Cachedata for other subflow: %s", string(cacheData))
							res.Result = string(cacheData)
							res.ResultSet = true
							ranUpdate = true

							finishedSubflows += 1
						} else {
							//log.Printf("[DEBUG] No cache data set for subflow cache %s", subflowResultCacheId)
						}
					} else {
						finishedSubflows += 1
					}
				}

				newResults = append(newResults, res)
			}

			if finishedSubflows == len(newResults) {
				log.Printf("[DEBUG] Finished workflow because status of all should be set to finished now")
				foundResult.Status = "FINISHED"
			}

			if ranUpdate {

				sendRequest = true
				baseResultData, err := json.Marshal(newResults)
				if err != nil {
					log.Printf("[ERROR] Failed marshalling subflow loop request data (1): %s", err)
					return err
				}

				foundResult.Result = string(baseResultData)
				resultData, err = json.Marshal(foundResult)
				if err != nil {
					log.Printf("[ERROR] Failed marshalling FULL subflow loop request data (2): %s", err)
					return err
				}

				//log.Printf("[DEBUG] Should update with multiple results for the subflow. Fullres: %s!", string(foundResult.Result))

			}
		}

		// Check if the item alreayd exists or not in results
		//return nil
	} else {

		// 1. Get result of parentnode's subflow (foundResult.Result)
		// 2. Try to marshal parent into a loop.
		// 3. If possible, loop through and find the one matching SubflowData.ExecutionId with "executionParent"
		// 4. If it's matching, update ONLY that one.
		var subflowDataLoop []SubflowData
		err = json.Unmarshal([]byte(foundResult.Result), &subflowDataLoop)
		if err == nil {
			for subflowIndex, subflowData := range subflowDataLoop {
				if subflowData.ExecutionId == executionParent {
					log.Printf("[DEBUG] Updating execution Id %s with subflow info", subflowData.ExecutionId)
					subflowDataLoop[subflowIndex].Result = returnValue
				}
			}

			//bytes.NewBuffer([]byte(resultData)),
			resultData, err = json.Marshal(subflowDataLoop)
			if err != nil {
				log.Printf("[WARNING] Failed updating resultData: %s", err)
				return err
			}

			sendRequest = true
		} else {
			actionValue := SubflowData{
				Success:       true,
				ExecutionId:   executionParent,
				Authorization: parentAuth,
				Result:        returnValue,
			}

			parsedActionValue, err := json.Marshal(actionValue)
			if err != nil {
				return err
			}

			// This is probably bad for loops
			if len(foundResult.Action.ID) == 0 {
				//log.Printf("Couldn't find the result!")
				parsedAction := Action{
					Label:       selectedTrigger.Label,
					ID:          selectedTrigger.ID,
					Name:        "run_subflow",
					AppName:     "shuffle-subflow",
					AppVersion:  "1.0.0",
					Environment: selectedTrigger.Environment,
					Parameters:  []WorkflowAppActionParameter{},
				}

				timeNow := time.Now().Unix()
				newResult := ActionResult{
					Action:        parsedAction,
					ExecutionId:   executionParent,
					Authorization: parentAuth,
					Result:        string(parsedActionValue),
					StartedAt:     timeNow,
					CompletedAt:   timeNow,
					Status:        "SUCCESS",
				}

				resultData, err = json.Marshal(newResult)
				if err != nil {
					return err
				}

				sendRequest = true
			} else {
				foundResult.Result = string(parsedActionValue)
				resultData, err = json.Marshal(foundResult)
				if err != nil {
					return err
				}

				sendRequest = true
			}
		}
	}

	if sendRequest && len(resultData) > 0 {
		//log.Printf("SHOULD SEND REQUEST!")
		streamUrl := fmt.Sprintf("%s/api/v1/streams", backendUrl)
		req, err := http.NewRequest(
			"POST",
			streamUrl,
			bytes.NewBuffer([]byte(resultData)),
		)

		if err != nil {
			log.Printf("Error building subflow request: %s", err)
			return err
		}

		newresp, err := topClient.Do(req)
		if err != nil {
			log.Printf("Error running subflow request: %s", err)
			return err
		}

		//body, err := ioutil.ReadAll(newresp.Body)
		//if err != nil {
		//	log.Printf("Failed reading body when waiting: %s", err)
		//	return err
		//}
		//log.Printf("[INFO] ADDED NEW ACTION RESULT (%d): %s", newresp.StatusCode, body)
		//_ = body
		_ = newresp
	} else {
		log.Printf("[INFO] NOT sending request because data len is %d and request is %#v", len(resultData), sendRequest)
	}

	return nil

	//log.Printf("Results: %d, status: %s, result: %s", len(newExecution.Results), newExecution.Status, newExecution.Result)
	//if newExecution.Status == "FINISHED" || newExecution.Status == "SUCCESS" {
	//	subflowResults[subflowIndex].Result = newExecution.Result
	//	updated = true
	//	finished += 1
	//}
}

// Re-validating whether the workflow is done or not IF a result should be found.
func validateFinishedExecution(ctx context.Context, workflowExecution WorkflowExecution, executed []string, retries int64) {
	var err error

	execution := &WorkflowExecution{}
	if os.Getenv("SHUFFLE_SWARM_CONFIG") == "run" && (project.Environment == "worker" || project.Environment == "") {
		//log.Printf("[DEBUG] Defaulting to current workflow in worker")
		execution = &workflowExecution
	} else {
		execution, err = GetWorkflowExecution(ctx, workflowExecution.ExecutionId)
		if err != nil {
			log.Printf("\n\n[WARNING] Failed to get workflow in fix it up: %s\n\n", err)
			return
		}
	}

	if execution.Status != "EXECUTING" {
		log.Printf("[WARNING] Workflow is finished, but with status: %s", execution.Status)
		return
	}

	// Make sure to deduplicate and update before checking
	for _, action := range workflowExecution.Workflow.Actions {
		found := false
		for _, result := range workflowExecution.Results {
			if result.Action.ID == action.ID {
				found = true
				break
			}
		}

		if found {
			continue
		}

		//log.Printf("[DEBUG] Maybe not handled yet: %s", action.ID)
		cacheId := fmt.Sprintf("%s_%s_result", workflowExecution.ExecutionId, action.ID)
		cache, err := GetCache(ctx, cacheId)
		if err != nil {
			//log.Printf("[WARNING] Couldn't find in fix exec %s (2): %s", cacheId, err)
			continue
		}

		actionResult := ActionResult{}
		cacheData := []byte(cache.([]uint8))

		// Just ensuring the data is good
		err = json.Unmarshal(cacheData, &actionResult)
		if err != nil {
			continue
		} else {
			workflowExecution.Results = append(workflowExecution.Results, actionResult)
		}
	}

	foundNotExecuted := []string{}
	for _, executedItem := range executed {
		found := false
		for _, result := range execution.Results {
			if result.Action.ID == executedItem {
				found = true
				break
			}
		}

		if !found {
			foundNotExecuted = append(foundNotExecuted, executedItem)
		}
	}

	if len(foundNotExecuted) == 0 {
		log.Printf("[DEBUG] No result missing that has been executed based on %#v", executed)
		return
	}

	//log.Printf("\n\nSTILL NOT FINISHED: %#v - add to results", foundNotExecuted)
	for _, executionItem := range foundNotExecuted {
		cacheId := fmt.Sprintf("%s_%s_result", execution.ExecutionId, executionItem)
		cache, err := GetCache(ctx, cacheId)
		if err != nil {
			//log.Printf("[WARNING] Couldn't find in fix exec %s: %s", cacheId, err)
			continue
		}

		actionResult := ActionResult{}
		cacheData := []byte(cache.([]uint8))
		//log.Printf("Data: %s", string(cacheData))

		// Just ensuring the data is good
		err = json.Unmarshal(cacheData, &actionResult)
		if err != nil {
			//log.Printf("[WARNING] Failed unmarshal in fix exec %s: %s", cacheId, err)
			continue
		}

		//log.Printf("[DEBUG] Rerunning request for %s", cacheId)
		//go ResendActionResult(cacheData, 0)
		log.Printf("[DEBUG] Should rerun (2)? %s (%s - %s)", actionResult.Action.Label, actionResult.Action.Name, actionResult.Action.ID)
		//go ResendActionResult(cacheData, retries)

		if len(actionResult.Action.ExecutionVariable.Name) > 0 && (actionResult.Status == "SUCCESS" || actionResult.Status == "FINISHED") {

			setExecVar := true
			//log.Printf("\n\n[DEBUG] SETTING ExecVar RESULTS: %#v", actionResult.Result)
			if strings.Contains(actionResult.Result, "\"success\":") {
				type SubflowMapping struct {
					Success bool `json:"success"`
				}

				var subflowData SubflowMapping
				err := json.Unmarshal([]byte(actionResult.Result), &subflowData)
				if err != nil {
					log.Printf("[ERROR] Failed to map in set execvar name with success: %s", err)
					setExecVar = false
				} else {
					if subflowData.Success == false {
						setExecVar = false
					}
				}
			}

			if len(actionResult.Result) == 0 {
				setExecVar = false
			}

			if setExecVar {
				log.Printf("[DEBUG] Updating exec variable %s with new value of length %d (3)", actionResult.Action.ExecutionVariable.Name, len(actionResult.Result))

				if len(workflowExecution.Results) > 0 {
					lastResult := workflowExecution.Results[len(workflowExecution.Results)-1].Result
					_ = lastResult
					//log.Printf("LAST: %s", lastResult)
				}

				actionResult.Action.ExecutionVariable.Value = actionResult.Result

				foundIndex := -1
				for i, executionVariable := range workflowExecution.ExecutionVariables {
					if executionVariable.Name == actionResult.Action.ExecutionVariable.Name {
						foundIndex = i
						break
					}
				}

				if foundIndex >= 0 {
					workflowExecution.ExecutionVariables[foundIndex] = actionResult.Action.ExecutionVariable
				} else {
					workflowExecution.ExecutionVariables = append(workflowExecution.ExecutionVariables, actionResult.Action.ExecutionVariable)
				}
			} else {
				log.Printf("[DEBUG] NOT updating exec variable %s with new value of length %d. Checkp revious errors, or if action was successful (success: true)", actionResult.Action.ExecutionVariable.Name, len(actionResult.Result))
			}
		}

		if os.Getenv("SHUFFLE_SWARM_CONFIG") == "run" && (project.Environment == "" || project.Environment == "worker") {
			go ResendActionResult(cacheData, retries)
		} else {
			workflowExecution.Results = append(workflowExecution.Results, actionResult)
		}
	}

	saveToDb := false
	extra := 0
	for _, trigger := range execution.Workflow.Triggers {
		//log.Printf("Appname trigger (0): %s", trigger.AppName)
		if trigger.AppName == "User Input" || trigger.AppName == "Shuffle Workflow" {
			extra += 1
		}
	}

	if len(workflowExecution.Results) >= len(workflowExecution.Workflow.Actions)+extra {
		saveToDb = true
	}

	err = SetWorkflowExecution(ctx, workflowExecution, saveToDb)
	if err != nil {
		log.Printf("[ERROR] Failed setting execution after rerun 2: %s", err)
	}
}

func ResendActionResult(actionData []byte, retries int64) {
	if project.Environment == "cloud" && retries == 0 {
		retries = 4
		//return

		//var res ActionResult
		//err := json.Unmarshal(actionData, &res)
		//if err == nil {
		//	log.Printf("[WARNING] Cloud - skipping rerun with %d retries for %s (%s)", retries, res.Action.Label, res.Action.ID)
		//}

		//return
	}

	if retries >= 5 {
		return
	}

	backendUrl := os.Getenv("BASE_URL")
	if project.Environment == "cloud" {
		backendUrl = "https://shuffler.io"

		if len(os.Getenv("SHUFFLE_GCEPROJECT")) > 0 && len(os.Getenv("SHUFFLE_GCEPROJECT_LOCATION")) > 0 {
			backendUrl = fmt.Sprintf("https://%s.%s.r.appspot.com", os.Getenv("SHUFFLE_GCEPROJECT"), os.Getenv("SHUFFLE_GCEPROJECT_LOCATION"))
		}

		if len(os.Getenv("SHUFFLE_CLOUDRUN_URL")) > 0 {
			backendUrl = os.Getenv("SHUFFLE_CLOUDRUN_URL")
		}

		//backendUrl = fmt.Sprintf("http://localhost:5002")
	}

	if os.Getenv("SHUFFLE_SWARM_CONFIG") == "run" && (project.Environment == "" || project.Environment == "worker") {
		backendUrl = "http://shuffle-workers:33333"

		// Should connect to self, not shuffle-workers
		hostenv := os.Getenv("WORKER_HOSTNAME")
		if len(hostenv) > 0 {
			backendUrl = fmt.Sprintf("http://%s:33333", hostenv)
		}
		//parsedRequest.BaseUrl = fmt.Sprintf("http://%s:%d", hostname, baseport)

		// From worker:
		//parsedRequest.BaseUrl = fmt.Sprintf("http://%s:%d", hostname, baseport)

		log.Printf("\n\n[DEBUG] REsending request to rerun action result to %s\n\n", backendUrl)

		// Here to prevent infinite loops
		var res ActionResult
		err := json.Unmarshal(actionData, &res)
		if err == nil {
			ctx := context.Background()
			parsedValue, err := GetBackendexecution(ctx, res.ExecutionId, res.Authorization)
			if err != nil {
				log.Printf("[WARNING] Failed getting execution from backend to verify (3): %s", err)
			} else {
				log.Printf("[INFO][%s] Found execution result (3) %s for subflow %s in backend with %d results and result %#v", res.ExecutionId, parsedValue.Status, res.ExecutionId, len(parsedValue.Results), parsedValue.Result)
				if parsedValue.Status != "EXECUTING" {
					return
				}
			}
		}
	}

	if len(backendUrl) == 0 {
		backendUrl = "http://localhost:5001"
	}

	streamUrl := fmt.Sprintf("%s/api/v1/streams?rerun=true&retries=%d", backendUrl, retries+1)
	req, err := http.NewRequest(
		"POST",
		streamUrl,
		bytes.NewBuffer(actionData),
	)

	if err != nil {
		log.Printf("[ERROR] Error building resend action request - retries: %d, err: %s", retries, err)

		if project.Environment != "cloud" && retries < 5 {
			if strings.Contains(fmt.Sprintf("%s", err), "cannot assign requested address") {
				time.Sleep(5 * time.Second)
				retries = retries + 1

				ResendActionResult(actionData, retries)
			}
		}

		return
	}

	//Timeout: 3 * time.Second,
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: nil,
		},
	}

	_, err = client.Do(req)
	if err != nil {
		log.Printf("[ERROR] Error running resend action request - retries: %d, err: %s", retries, err)

		if !strings.Contains(fmt.Sprintf("%s", err), "context deadline") && !strings.Contains(fmt.Sprintf("%s", err), "Client.Timeout exceeded") {
			// How to self repair? Quit and restart the worker?
			// This means worker is buggy when talking to itself
			if project.Environment != "cloud" && retries < 5 {
				if strings.Contains(fmt.Sprintf("%s", err), "cannot assign requested address") {
					time.Sleep(5 * time.Second)
					retries = retries + 1

					ResendActionResult(actionData, retries)
				}
			} else if project.Environment != "cloud" && retries >= 5 {
				//panic("No more sockets available. Restarting worker to self-repair.")
				log.Printf("[WARNING] Should we quit out on worker and start a new? How can we remove socket boundry?")
			}
		}

		return
	}

	//body, err := ioutil.ReadAll(newresp.Body)
	//if err != nil {
	//	log.Printf("[WARNING] Error getting body from rerun: %s", err)
	//	return
	//}

	//log.Printf("[DEBUG] Status %d and Body from rerun: %s", newresp.StatusCode, string(body))
}

// Updateparam is a check to see if the execution should be continuously validated
func ParsedExecutionResult(ctx context.Context, workflowExecution WorkflowExecution, actionResult ActionResult, updateParam bool, retries int64) (*WorkflowExecution, bool, error) {
	var err error
	if actionResult.Action.ID == "" {
		//log.Printf("[ERROR] Failed handling EMPTY action %#v. Usually happens during worker run that sets everything?", actionResult)
		return &workflowExecution, true, nil
	}

	// 1. Set cache
	// 2. Find executed without a result
	// 3. Ensure the result is NOT set when running an action

	// Don't set cache for triggers?
	//log.Printf("\n\nACTIONRES: %#v\n\nRES: %s\n", actionResult, actionResult.Result)

	setCache := true
	if actionResult.Action.AppName == "shuffle-subflow" {

		for _, param := range actionResult.Action.Parameters {
			if param.Name == "check_result" {
				//log.Printf("[INFO] RESULT: %#v", param)
				if param.Value == "true" {
					setCache = false
				}

				break
			}
		}

		if !setCache {
			var subflowData SubflowData
			jsonerr := json.Unmarshal([]byte(actionResult.Result), &subflowData)
			if jsonerr == nil && len(subflowData.Result) == 0 && !strings.Contains(actionResult.Result, "\"result\"") {
				setCache = false
			} else {
				setCache = true
			}

		}

		log.Printf("[DEBUG] Skipping setcache for subflow? SetCache: %#v", setCache)
		//log.Printf("[WARNING] Should maybe not set cache for subflow if it should wait for result.")
	}

	if setCache {
		actionCacheId := fmt.Sprintf("%s_%s_result", actionResult.ExecutionId, actionResult.Action.ID)
		actionResultBody, err := json.Marshal(actionResult)
		if err == nil {
			//log.Printf("[DEBUG] Setting cache for %s", actionCacheId)
			err = SetCache(ctx, actionCacheId, actionResultBody)
			if err != nil {
				log.Printf("\n\n\n[ERROR] Failed setting cache for action in parsed exec results %s: %s\n\n", actionCacheId, err)
			}
		}
	}

	skipExecutionCount := false
	if workflowExecution.Status == "FINISHED" {
		skipExecutionCount = true
	}

	dbSave := false
	startAction, extra, children, parents, visited, executed, nextActions, environments := GetExecutionVariables(ctx, workflowExecution.ExecutionId)

	//log.Printf("RESULT: %#v", actionResult.Action.ExecutionVariable)
	// Shitty workaround as it may be missing it at times
	for _, action := range workflowExecution.Workflow.Actions {
		if action.ID == actionResult.Action.ID {
			//log.Printf("HAS EXEC VARIABLE: %#v", action.ExecutionVariable)
			actionResult.Action.ExecutionVariable = action.ExecutionVariable
			break
		}
	}

	newResult := FixBadJsonBody([]byte(actionResult.Result))
	actionResult.Result = string(newResult)

	//if len(actionResult.Action.ExecutionVariable.Name) > 0 && (actionResult.Status == "SUCCESS" || actionResult.Status == "FINISHED") {
	if len(actionResult.Action.ExecutionVariable.Name) > 0 && (actionResult.Status == "SUCCESS" || actionResult.Status == "FINISHED") {

		setExecVar := true
		//log.Printf("\n\n[DEBUG] SETTING ExecVar RESULTS: %#v", actionResult.Result)
		if strings.Contains(actionResult.Result, "\"success\":") {
			type SubflowMapping struct {
				Success bool `json:"success"`
			}

			var subflowData SubflowMapping
			err := json.Unmarshal([]byte(actionResult.Result), &subflowData)
			if err != nil {
				log.Printf("[ERROR] Failed to map in set execvar name with success: %s", err)
				setExecVar = false
			} else {
				if subflowData.Success == false {
					setExecVar = false
				}
			}
		}

		if len(actionResult.Result) == 0 {
			setExecVar = false
		}

		if setExecVar {
			log.Printf("[DEBUG] Updating exec variable %s with new value of length %d (2)", actionResult.Action.ExecutionVariable.Name, len(actionResult.Result))

			if len(workflowExecution.Results) > 0 {
				lastResult := workflowExecution.Results[len(workflowExecution.Results)-1].Result
				_ = lastResult
				//log.Printf("LAST: %s", lastResult)
			}

			actionResult.Action.ExecutionVariable.Value = actionResult.Result

			foundIndex := -1
			for i, executionVariable := range workflowExecution.ExecutionVariables {
				if executionVariable.Name == actionResult.Action.ExecutionVariable.Name {
					foundIndex = i
					break
				}
			}

			if foundIndex >= 0 {
				workflowExecution.ExecutionVariables[foundIndex] = actionResult.Action.ExecutionVariable
			} else {
				workflowExecution.ExecutionVariables = append(workflowExecution.ExecutionVariables, actionResult.Action.ExecutionVariable)
			}
		} else {
			log.Printf("[DEBUG] NOT updating exec variable %s with new value of length %d. Checkp revious errors, or if action was successful (success: true)", actionResult.Action.ExecutionVariable.Name, len(actionResult.Result))
		}
	}

	actionResult.Action = Action{
		AppName:           actionResult.Action.AppName,
		AppVersion:        actionResult.Action.AppVersion,
		Label:             actionResult.Action.Label,
		Name:              actionResult.Action.Name,
		ID:                actionResult.Action.ID,
		Parameters:        actionResult.Action.Parameters,
		ExecutionVariable: actionResult.Action.ExecutionVariable,
	}

	// Cleaning up result authentication
	for paramIndex, param := range actionResult.Action.Parameters {
		if param.Configuration {
			//log.Printf("[INFO] Deleting param %s (auth)", param.Name)
			actionResult.Action.Parameters[paramIndex].Value = ""
		}
	}

	// Used for testing subflow shit
	//if strings.Contains(actionResult.Action.Label, "Shuffle Workflow_30") {
	//	log.Printf("RESULT FOR %s: %#v", actionResult.Action.Label, actionResult.Result)
	//	if !strings.Contains(actionResult.Result, "\"result\"") {
	//		log.Printf("NO RESULT - RETURNING!")
	//		return &workflowExecution, false, nil
	//	}
	//}

	// Fills in data from subflows, whether they're loops or not
	// Deprecated! Now runs updateExecutionParent() instead
	// Update: handling this farther down the function
	//log.Printf("[DEBUG] STATUS OF %s: %s", actionResult.Action.AppName, actionResult.Status)
	if actionResult.Status == "SUCCESS" && actionResult.Action.AppName == "shuffle-subflow" {
		dbSave = true

		//runCheck := false
		//for _, param := range actionResult.Action.Parameters {
		//	if param.Name == "check_result" {
		//		//log.Printf("[INFO] RESULT: %#v", param)
		//		if param.Value == "true" {
		//			runCheck = true
		//		}

		//		break
		//	}
		//}

		//_ = runCheck
		////log.Printf("\n\nRUNCHECK: %#v\n\n", runCheck)
		//if runCheck {
		//	log.Printf("[WARNING] Sinkholing request IF the subflow-result DOESNT have result. Value: %s", actionResult.Result)
		//	var subflowData SubflowData
		//	err = json.Unmarshal([]byte(actionResult.Result), &subflowData)
		//	if err == nil {
		//		if len(subflowData.Result) == 0 {
		//			//func updateExecutionParent(executionParent, returnValue, parentAuth, parentNode string) error {
		//			log.Printf("\n\nNO RESULT FOR SUBFLOW RESULT - RETURNING\n\n")
		//			return &workflowExecution, false, nil
		//		}
		//	}
		//	//type SubflowData struct {
		//}
		//	log.Printf("[INFO] Validating subflow result in workflow %s", workflowExecution.ExecutionId)

		//	// WAY lower timeout in cloud
		//	// Should probably change it for enterprise customers?
		//	// Idk how to handle this in cloud yet.
		//	// FIXME: Check "if finished {" location, and the ExecutionParent for realtime data
		//	// E.g. the subitem itself updating it
		//	// 60*30 = 1800 = 30 minutes of waiting potentially
		//	// This is NOT ideal.
		//	subflowTimeout := 1800
		//	if project.Environment == "cloud" {
		//		subflowTimeout = 120
		//	}

		//	subflowResult := SubflowData{}
		//	subflowResults := []SubflowData{}
		//	err = json.Unmarshal([]byte(actionResult.Result), &subflowResult)

		//	// This is just in case it's running in the worker
		//	backendUrl := os.Getenv("BASE_URL")
		//	resultUrl := fmt.Sprintf("%s/api/v1/streams/results", backendUrl)
		//	log.Printf("[DEBUG] ResultURL: %s", backendUrl)
		//	topClient := &http.Client{
		//		Transport: &http.Transport{
		//			Proxy: nil,
		//		},
		//	}
		//	newExecution := WorkflowExecution{}

		//	httpProxy := os.Getenv("HTTP_PROXY")
		//	httpsProxy := os.Getenv("HTTPS_PROXY")
		//	if len(httpProxy) > 0 || len(httpsProxy) > 0 {
		//		topClient = &http.Client{}
		//	} else {
		//		if len(httpProxy) > 0 {
		//			log.Printf("Running with HTTP proxy %s (env: HTTP_PROXY)", httpProxy)
		//		}
		//		if len(httpsProxy) > 0 {
		//			log.Printf("Running with HTTPS proxy %s (env: HTTPS_PROXY)", httpsProxy)
		//		}
		//	}

		//	if err != nil {
		//		subflowResults = []SubflowData{}
		//		err = json.Unmarshal([]byte(actionResult.Result), &subflowResults)
		//		if err == nil {
		//			//log.Printf("[INFO] Should get data for %d subflow executions", len(subflowResults))
		//			count := 0
		//			updated := false
		//			//newResult := ""

		//			for {
		//				time.Sleep(3 * time.Second)

		//				finished := 0
		//				for subflowIndex, subflowResult := range subflowResults {
		//					if !subflowResult.Success || len(subflowResult.Result) != 0 {
		//						finished += 1
		//						continue
		//					}

		//					// Have to get from backend IF no environment (worker, onprem)
		//					// "worker"
		//					if project.Environment == "" {
		//						data, err := json.Marshal(subflowResult)
		//						if err != nil {
		//							log.Printf("[WARNING] Failed init marshal: %s", err)
		//							continue
		//						}

		//						req, err := http.NewRequest(
		//							"POST",
		//							resultUrl,
		//							bytes.NewBuffer([]byte(data)),
		//						)

		//						newresp, err := topClient.Do(req)
		//						if err != nil {
		//							log.Printf("[ERROR] Failed making request: %s", err)
		//							continue
		//						}

		//						body, err := ioutil.ReadAll(newresp.Body)
		//						if err != nil {
		//							log.Printf("[ERROR] Failed reading body: %s", err)
		//							continue
		//						}

		//						if newresp.StatusCode != 200 {
		//							log.Printf("[ERROR] Bad statuscode getting subresult: %d, %s", newresp.StatusCode, string(body))
		//							continue
		//						}

		//						err = json.Unmarshal(body, &newExecution)
		//						if err != nil {
		//							log.Printf("[ERROR] Failed newexecutuion unmarshal: %s", err)
		//							continue
		//						}

		//						//log.Printf("Results: %d, status: %s, result: %s", len(newExecution.Results), newExecution.Status, newExecution.Result)
		//						if newExecution.Status == "FINISHED" || newExecution.Status == "SUCCESS" {
		//							subflowResults[subflowIndex].Result = newExecution.Result
		//							updated = true
		//							finished += 1
		//						}

		//					} else {
		//						tmpExecution, err := GetWorkflowExecution(ctx, subflowResult.ExecutionId)
		//						newExecution := *tmpExecution
		//						if err != nil {
		//							log.Printf("[WARNING] Error getting subflow data: %s", err)
		//						} else {
		//							//log.Printf("Results: %d, status: %s", len(workflowExecution.Results), workflowExecution.Status)
		//							if newExecution.Status == "FINISHED" || newExecution.Status == "ABORTED" {
		//								subflowResults[subflowIndex].Result = newExecution.Result
		//								updated = true
		//								finished += 1
		//							}
		//						}
		//					}
		//				}

		//				if finished == len(subflowResults) {
		//					break
		//				}

		//				if count >= subflowTimeout/3 {
		//					break
		//				}

		//				count += 1
		//			}

		//			if updated {
		//				newJson, err := json.Marshal(subflowResults)
		//				if err == nil {
		//					actionResult.Result = string(newJson)
		//				} else {
		//					log.Printf("[WARNING] Failed marshalling subflowresultS: %s", err)
		//				}
		//			}
		//		}
		//	}

		//	if err == nil && subflowResult.Success == true && len(subflowResult.ExecutionId) > 0 {
		//		log.Printf("[DEBUG] Should get data for subflow execution %s", subflowResult.ExecutionId)
		//		count := 0
		//		for {
		//			time.Sleep(3 * time.Second)

		//			if count >= subflowTimeout/3 {
		//				break
		//			}

		//			// Worker & onprem
		//			if project.Environment == "" {
		//				data, err := json.Marshal(subflowResult)
		//				if err != nil {
		//					log.Printf("[WARNING] Failed init marshal: %s", err)
		//					count += 1
		//					continue
		//				}

		//				req, err := http.NewRequest(
		//					"POST",
		//					resultUrl,
		//					bytes.NewBuffer([]byte(data)),
		//				)

		//				newresp, err := topClient.Do(req)
		//				if err != nil {
		//					log.Printf("[ERROR] Failed making request: %s", err)
		//					count += 1
		//					continue
		//				}

		//				body, err := ioutil.ReadAll(newresp.Body)
		//				if err != nil {
		//					log.Printf("[ERROR] Failed reading body: %s", err)
		//					count += 1
		//					continue
		//				}

		//				if newresp.StatusCode != 200 {
		//					log.Printf("[ERROR] Bad statuscode getting subresult: %d, %s", newresp.StatusCode, string(body))
		//					count += 1
		//					continue
		//				}

		//				err = json.Unmarshal(body, &newExecution)
		//				if err != nil {
		//					log.Printf("[ERROR] Failed workflowExecution unmarshal: %s", err)
		//					count += 1
		//					continue
		//				}

		//				//log.Printf("Results: %d, status: %s, result: %s", len(newExecution.Results), newExecution.Status, newExecution.Result)
		//				if newExecution.Status == "FINISHED" || newExecution.Status == "SUCCESS" {
		//					subflowResult.Result = newExecution.Result
		//					break
		//					//subflowResults[subflowIndex].Result = workflowExecution.Result
		//					//updated = true
		//					//finished += 1
		//				}
		//			} else {
		//				tmpExecution, err := GetWorkflowExecution(ctx, subflowResult.ExecutionId)
		//				newExecution = *tmpExecution
		//				if err != nil {
		//					log.Printf("[WARNING] Error getting subflow data: %s", err)
		//				} else {
		//					//log.Printf("Results: %d, status: %s", len(newExecution.Results), newExecution.Status)
		//					if newExecution.Status == "FINISHED" || newExecution.Status == "ABORTED" {
		//						subflowResult.Result = newExecution.Result
		//						break
		//					}

		//				}
		//			}

		//			count += 1
		//		}
		//	}

		//	if len(subflowResult.Result) > 0 {
		//		newJson, err := json.Marshal(subflowResult)
		//		if err == nil {
		//			actionResult.Result = string(newJson)
		//		} else {
		//			log.Printf("[WARNING] Failed marshalling subflowresult: %s", err)
		//		}
		//	}
		//} else {
		//	log.Printf("[WARNING] Skipping subresult check!")
		//}

		// Updating in case the execution got more info
		//if project.Environment != "" {
		//	parsedExecution, err := GetWorkflowExecution(ctx, workflowExecution.ExecutionId)
		//	if err != nil {
		//		log.Printf("[ERROR] FAILED to reload execution after subflow check: %s", err)
		//	} else {
		//		log.Printf("[DEBUG] Re-updated execution after subflow check!")
		//	}

		//	workflowExecution = *parsedExecution
		//} else {
		//	if updateParam {
		//		return &workflowExecution, false, errors.New("Rerun this transaction with updated values")
		//	}

		//	log.Printf("[INFO] Skipping updateparam with %d results", len(workflowExecution.Results))
		//	// return &workflowExecution, dbSave, err
		//	//return
		//	//func ParsedExecutionResult(ctx context.Context, workflowExecution WorkflowExecution, actionResult ActionResult) (*WorkflowExecution, bool, error) {

		//	//type SubflowData struct {
		//	//	Success       bool   `json:"success"`
		//	//	ExecutionId   string `json:"execution_id"`
		//	//	Authorization string `json:"authorization"`
		//	//	Result        string `json:"result"`
		//	//}
		//	//log.Printf("[DEBUG] NOT validating updated workflowExecution because worker")
		//}

	}

	if actionResult.Status == "ABORTED" || actionResult.Status == "FAILURE" {
		IncrementCache(ctx, workflowExecution.ExecutionOrg, "app_executions_failed")

		if workflowExecution.Workflow.Configuration.SkipNotifications == false {
			// Add an else for HTTP request errors with success "false"
			// These could be "silent" issues
			if actionResult.Status == "FAILURE" {
				log.Printf("[DEBUG] Result is %s for %s (%s). Making notification.", actionResult.Status, actionResult.Action.Label, actionResult.Action.ID)
				err := CreateOrgNotification(
					ctx,
					fmt.Sprintf("Error in Workflow %#v", workflowExecution.Workflow.Name),
					fmt.Sprintf("Node %s in Workflow %s was found to have an error. Click to investigate", actionResult.Action.Label, workflowExecution.Workflow.Name),
					fmt.Sprintf("/workflows/%s?execution_id=%s&view=executions&node=%s", workflowExecution.Workflow.ID, workflowExecution.ExecutionId, actionResult.Action.ID),
					workflowExecution.ExecutionOrg,
					true,
				)

				if err != nil {
					log.Printf("[WARNING] Failed making org notification: %s", err)
				}
			}
		}

		newResults := []ActionResult{}
		childNodes := []string{}
		if workflowExecution.Workflow.Configuration.ExitOnError {
			// Find underlying nodes and add them
			log.Printf("[WARNING] Actionresult is %s for node %s (%s) in execution %s. Should set workflowExecution and exit all running functions", actionResult.Status, actionResult.Action.Label, actionResult.Action.ID, workflowExecution.ExecutionId)
			workflowExecution.Status = actionResult.Status
			workflowExecution.LastNode = actionResult.Action.ID

			if len(workflowExecution.Workflow.DefaultReturnValue) > 0 {
				workflowExecution.Result = workflowExecution.Workflow.DefaultReturnValue
			}

			IncrementCache(ctx, workflowExecution.ExecutionOrg, "workflow_executions_failed")
		} else {
			log.Printf("[WARNING] Actionresult is %s for node %s in %s. Continuing anyway because of workflow configuration.", actionResult.Status, actionResult.Action.ID, workflowExecution.ExecutionId)
			// Finds ALL childnodes to set them to SKIPPED
			// Remove duplicates
			//log.Printf("CHILD NODES: %d", len(childNodes))
			childNodes = FindChildNodes(workflowExecution, actionResult.Action.ID)
			//log.Printf("\n\nFOUND %d CHILDNODES\n\n", len(childNodes))
			for _, nodeId := range childNodes {
				if nodeId == actionResult.Action.ID {
					continue
				}

				// 1. Find the action itself
				// 2. Create an actionresult
				curAction := Action{ID: ""}
				for _, action := range workflowExecution.Workflow.Actions {
					if action.ID == nodeId {
						curAction = action
						break
					}
				}

				isTrigger := false
				if len(curAction.ID) == 0 {
					for _, trigger := range workflowExecution.Workflow.Triggers {
						//log.Printf("%s : %s", trigger.ID, nodeId)
						if trigger.ID == nodeId {
							isTrigger = true
							name := "shuffle-subflow"
							curAction = Action{
								AppName:    name,
								AppVersion: trigger.AppVersion,
								Label:      trigger.Label,
								Name:       trigger.Name,
								ID:         trigger.ID,
							}

							//log.Printf("SET NODE!!")
							break
						}
					}

					if len(curAction.ID) == 0 {
						//log.Printf("Couldn't find subnode %s", nodeId)
						continue
					}
				}

				resultExists := false
				for _, result := range workflowExecution.Results {
					if result.Action.ID == curAction.ID {
						resultExists = true
						break
					}
				}

				if !resultExists {
					// Check parents are done here. Only add it IF all parents are skipped
					skipNodeAdd := false
					for _, branch := range workflowExecution.Workflow.Branches {
						if branch.DestinationID == nodeId && !isTrigger {
							// If the branch's source node is NOT in childNodes, it's not a skipped parent
							// Checking if parent is a trigger
							parentTrigger := false
							for _, trigger := range workflowExecution.Workflow.Triggers {
								if trigger.ID == branch.SourceID {
									if trigger.AppName != "User Input" && trigger.AppName != "Shuffle Workflow" {
										parentTrigger = true
									}
								}
							}

							if parentTrigger {
								continue
							}

							sourceNodeFound := false
							for _, item := range childNodes {
								if item == branch.SourceID {
									sourceNodeFound = true
									break
								}
							}

							if !sourceNodeFound {
								// FIXME: Shouldn't add skip for child nodes of these nodes. Check if this node is parent of upcoming nodes.
								//log.Printf("\n\n NOT setting node %s to SKIPPED", nodeId)
								skipNodeAdd = true

								if !ArrayContains(visited, nodeId) && !ArrayContains(executed, nodeId) {
									nextActions = append(nextActions, nodeId)
									log.Printf("[INFO] SHOULD EXECUTE NODE %s. Next actions: %s", nodeId, nextActions)
								}
								break
							}
						}
					}

					if !skipNodeAdd {
						newResult := ActionResult{
							Action:        curAction,
							ExecutionId:   actionResult.ExecutionId,
							Authorization: actionResult.Authorization,
							Result:        `{"success": false, "reason": "Skipped because of previous node - 2"}`,
							StartedAt:     0,
							CompletedAt:   0,
							Status:        "SKIPPED",
						}

						newResults = append(newResults, newResult)

						visited = append(visited, curAction.ID)
						executed = append(executed, curAction.ID)

						UpdateExecutionVariables(ctx, workflowExecution.ExecutionId, startAction, children, parents, visited, executed, nextActions, environments, extra)
					} else {
						//log.Printf("\n\nNOT adding %s as skipaction - should add to execute?", nodeId)
						//var visited []string
						//var executed []string
						//var nextActions []string
					}
				}
			}
		}

		// Cleans up aborted, and always gives a result
		lastResult := ""
		// type ActionResult struct {
		for _, result := range workflowExecution.Results {
			if actionResult.Action.ID == result.Action.ID {
				continue
			}

			if result.Status == "EXECUTING" {
				result.Status = actionResult.Status
				result.Result = "Aborted because of error in another node (2)"
			}

			if len(result.Result) > 0 {
				lastResult = result.Result
			}

			newResults = append(newResults, result)
		}

		if workflowExecution.LastNode == "" {
			workflowExecution.LastNode = actionResult.Action.ID
		}

		workflowExecution.Result = lastResult
		workflowExecution.Results = newResults
	}

	if actionResult.Status == "SKIPPED" {
		//unfinishedNodes := []string{}
		childNodes := FindChildNodes(workflowExecution, actionResult.Action.ID)
		_ = childNodes
		//log.Printf("childnodes: %d: %#v", len(childNodes), childNodes)

		//FIXME: Should this run and fix all nodes,
		// or should it send them in as new SKIPs? Should we only handle DIRECT
		// children? I wonder.

		//log.Printf("\n\n\n[DEBUG] FROM %s - FOUND childnode %s %s (%s). exists: %#v\n\n\n", actionResult.Action.Label, curAction.ID, curAction.Name, curAction.Label, resultExists)
		// FIXME: Add triggers
		for _, branch := range workflowExecution.Workflow.Branches {
			if branch.SourceID != actionResult.Action.ID {
				continue
			}

			// Find the target & check if it has more branches. If it does, and they're not finished - continue
			foundAction := Action{}
			for _, action := range workflowExecution.Workflow.Actions {
				if action.ID == branch.DestinationID {
					foundAction = action
					break
				}
			}

			if len(foundAction.ID) == 0 {
				for _, trigger := range workflowExecution.Workflow.Triggers {
					//if trigger.AppName == "User Input" || trigger.AppName == "Shuffle Workflow" {
					if trigger.ID == branch.DestinationID {
						foundAction = Action{
							ID:      trigger.ID,
							AppName: trigger.AppName,
							Name:    trigger.AppName,
							Label:   trigger.Label,
						}

						if trigger.AppName == "Shuffle Workflow" {
							foundAction.AppName = "shuffle-subflow"
						}

						break
					}
				}

				if len(foundAction.ID) == 0 {
					continue
				}
			}

			//log.Printf("\n\n\n[WARNING] Found that %s (%s) should be skipped? Should check if it has more parents. If not, send in a skip\n\n\n", foundAction.Label, foundAction.ID)

			foundCount := 0
			skippedBranches := []string{}
			for _, checkBranch := range workflowExecution.Workflow.Branches {
				if checkBranch.DestinationID == foundAction.ID {
					foundCount += 1

					// Check if they're all skipped or not
					if checkBranch.SourceID == actionResult.Action.ID {
						skippedBranches = append(skippedBranches, checkBranch.SourceID)
						continue
					}

					// Not found = not counted yet
					for _, res := range workflowExecution.Results {
						if res.Action.ID == checkBranch.SourceID && res.Status != "SUCCESS" && res.Status != "FINISHED" {
							skippedBranches = append(skippedBranches, checkBranch.SourceID)
							break
						}
					}
				}
			}

			skippedCount := len(skippedBranches)

			//log.Printf("\n\n[DEBUG][%s] Found %d branch(es) for %s. %d skipped. If equal, make the node skipped. SKIPPED: %#v\n\n", workflowExecution.ExecutionId, foundCount, foundAction.Label, skippedCount, skippedBranches)
			if foundCount == skippedCount {
				found := false
				for _, res := range workflowExecution.Results {
					if res.Action.ID == foundAction.ID {
						found = true
					}
				}

				if !found {
					newResult := ActionResult{
						Action:        foundAction,
						ExecutionId:   actionResult.ExecutionId,
						Authorization: actionResult.Authorization,
						Result:        fmt.Sprintf(`{"success": false, "reason": "Skipped because of previous node (%s) - 1"}`, actionResult.Action.Label),
						StartedAt:     0,
						CompletedAt:   0,
						Status:        "SKIPPED",
					}

					resultData, err := json.Marshal(newResult)
					if err != nil {
						log.Printf("[ERROR] Failed skipping action")
						continue
					}

					streamUrl := fmt.Sprintf("http://localhost:5001/api/v1/streams")
					if project.Environment == "cloud" {
						streamUrl = fmt.Sprintf("https://shuffler.io/api/v1/streams")

						if len(os.Getenv("SHUFFLE_GCEPROJECT")) > 0 && len(os.Getenv("SHUFFLE_GCEPROJECT_LOCATION")) > 0 {
							streamUrl = fmt.Sprintf("https://%s.%s.r.appspot.com/api/v1/streams", os.Getenv("SHUFFLE_GCEPROJECT"), os.Getenv("SHUFFLE_GCEPROJECT_LOCATION"))
						}

						if len(os.Getenv("SHUFFLE_CLOUDRUN_URL")) > 0 {
							streamUrl = os.Getenv("SHUFFLE_CLOUDRUN_URL")
						}

						//streamUrl = fmt.Sprintf("http://localhost:5002/api/v1/streams")
					}

					req, err := http.NewRequest(
						"POST",
						streamUrl,
						bytes.NewBuffer([]byte(resultData)),
					)

					if err != nil {
						log.Printf("[ERROR] Error building SKIPPED request (%s): %s", foundAction.Label, err)
						continue
					}

					client := &http.Client{}
					newresp, err := client.Do(req)
					if err != nil {
						log.Printf("[ERROR] Error running SKIPPED request (%s): %s", foundAction.Label, err)
						continue
					}

					body, err := ioutil.ReadAll(newresp.Body)
					if err != nil {
						log.Printf("[ERROR] Failed reading body when running SKIPPED request (%s): %s", foundAction.Label, err)
						continue
					}

					//log.Printf("[DEBUG] Skipped body return from %s (%d): %s", streamUrl, newresp.StatusCode, string(body))
					if strings.Contains(string(body), "already finished") {
						log.Printf("[WARNING] Data couldn't be re-inputted for %s.", foundAction.Label)
						return &workflowExecution, true, errors.New(fmt.Sprintf("Failed updating skipped action %s", foundAction.Label))
					}
				}
			}
		}

		/*
				appendBadResults := true
				appendResults := []ActionResult{}
				for _, nodeId := range childNodes {
					if nodeId == actionResult.Action.ID {
						continue
					}

					curAction := Action{ID: ""}
					for _, action := range workflowExecution.Workflow.Actions {
						if action.ID == nodeId {
							curAction = action
							break
						}
					}

					if len(curAction.ID) == 0 {
						//log.Printf("Couldn't find subnode (0) %s as action. Checking triggers.", nodeId)
						for _, trigger := range workflowExecution.Workflow.Triggers {
							//if trigger.AppName == "User Input" || trigger.AppName == "Shuffle Workflow" {
							if trigger.ID == nodeId {
								curAction = Action{
									ID:      trigger.ID,
									AppName: trigger.AppName,
									Name:    trigger.AppName,
									Label:   trigger.Label,
								}

								if trigger.AppName == "Shuffle Workflow" {
									curAction.AppName = "shuffle-subflow"
								}

								break
							}
						}

						if len(curAction.ID) == 0 {
							//log.Printf("Couldn't find subnode (1) %s", nodeId)
							continue
						}
					}

					resultExists := false
					for _, result := range workflowExecution.Results {
						if result.Action.ID == curAction.ID {
							resultExists = true
							break
						}
					}

					if curAction.Label == "Shuffle Tools_14" {
						log.Printf("\n\n\n[DEBUG] FROM %s - FOUND childnode %s %s (%s). exists: %#v\n\n\n", actionResult.Action.Label, curAction.ID, curAction.Name, curAction.Label, resultExists)
					}

					// Finds sub-nodes to be skipped if a parent node condition fails
					skipIdCheck := false
					if !resultExists {
						// Check parents are done here. Only add it IF all parents are skipped
						skipNodeAdd := false

						// Find parent nodes that are also a child node of SKIPPED
						parentNodes := []string{}
						for _, branch := range workflowExecution.Workflow.Branches {

							// If the current node has more branches, check those
							if branch.DestinationID == curAction.ID {
								if curAction.Label == "Shuffle Tools_14" {
									log.Printf("Found branch!")
								}

								parentNodes = append(parentNodes, branch.SourceID)

									//for _, childnode := range childNodes {
									//	if childnode == branch.SourceID {
									//		parentNodes = append(parentNodes, branch.SourceID)
									//		break
									//	}
									//}
							}
						}

						//log.Printf("Parents: %#v", parentNodes)

						for _, branch := range workflowExecution.Workflow.Branches {

							// FIXME: Make this dynamic to curAction.ID's parent that we're checking from
							//if branch.SourceID == actionResult.Action.ID {
							if ArrayContains(parentNodes, branch.SourceID) {
								// Check if the node has more destinations
								// branch = old branch (original?)
								ids := []string{}
								for _, innerbranch := range workflowExecution.Workflow.Branches {
									if innerbranch.DestinationID == branch.DestinationID {
										ids = append(ids, innerbranch.SourceID)
									}

									//if innerbranch.ID == "70104246-45cf-4fa3-8b03-323d3cdf6434" {
									//	log.Printf("Branch: %#v", innerbranch)
									//}
								}

								//if curAction.Label == "Shuffle Tools_4" {
								//}

								foundIds := []string{actionResult.Action.ID}
								foundSuccess := []string{}
								foundSkipped := []string{actionResult.Action.ID}

								//log.Printf("\n\nAction: %s (%s). Branches: %d\n\n", curAction.Label, curAction.ID, len(ids))
								// If more than one source branch for the target is found;
								// Look for the result of the parent
								if len(ids) > 1 {
									for _, thisId := range ids {
										if thisId == actionResult.Action.ID {
											continue
										}

										//appendResults = append(appendResults, newResult)
										tmpResults := append(workflowExecution.Results, appendResults...)
										for _, result := range tmpResults {
											if result.Action.ID == thisId {
												log.Printf("[DEBUG] Found result for %s (%s): %s", result.Action.Label, thisId, result.Status)

												foundIds = append(foundIds, thisId)
												if result.Status == "SUCCESS" {
													foundSuccess = append(foundSuccess, thisId)
												} else {
													foundSkipped = append(foundSkipped, thisId)
												}
											}
										}
									}
								} else {
									appendBadResults = true
									skipIdCheck = true
								}

								if skipIdCheck {
									// Pass here, as it's just here to skip the next part
								} else if (len(foundSkipped) == len(foundIds)) && len(foundSkipped) == len(ids) {
									appendBadResults = true
								} else {
									//log.Printf("\n\n\nNOT appending results for %s. Try later?\n\n\n", curAction.Label)
									// appendResults = append(appendResults, newResult)
									appendBadResults = false
								}

								//if len(foundIds) == len(ids) {
								//	// Means you can continue
								//	appendBadResults = false
								//	break
								//}
							}
						}

						if !appendBadResults {
							continue
							//break
						}

						if !skipNodeAdd {
							if curAction.Label == "Shuffle Tools_14" {
								log.Printf("\n\n\n[DEBUG] Appending skip for node %s (%s - %s)\n\n\n", curAction.Name, curAction.Label, curAction.ID)
							}

							newResult := ActionResult{
								Action:        curAction,
								ExecutionId:   actionResult.ExecutionId,
								Authorization: actionResult.Authorization,
								Result:        fmt.Sprintf(`{"success": false, "reason": "Skipped because of previous node (%s) - 1"}`, actionResult.Action.Label),
								StartedAt:     0,
								CompletedAt:   0,
								Status:        "SKIPPED",
							}

							appendResults = append(appendResults, newResult)

							newExecId := fmt.Sprintf("%s_%s", workflowExecution.ExecutionId, curAction.ID)
							cacheData := []byte("1")
							err = SetCache(ctx, newExecId, cacheData)
							if err != nil {
								log.Printf("[WARNING] Failed setting cache for skipped action %s: %s", newExecId, err)
							} else {
								//log.Printf("\n\n[DEBUG] Adding %s to cache. Name: %s\n\n", newExecId, action.Name)
							}
						} else {
							//log.Printf("\n\nNOT adding %s as skipaction - should add to execute?", nodeId)
							//var visited []string
							//var executed []string
							//var nextActions []string
						}
					}
				}

			//log.Printf("Append skipped results: %#v", appendBadResults)
			if len(appendResults) > 0 {
				dbSave = true
				for _, res := range appendResults {
					workflowExecution.Results = append(workflowExecution.Results, res)
				}
			}
		*/
	}

	// Related to notifications
	if actionResult.Status == "SUCCESS" && workflowExecution.Workflow.Configuration.SkipNotifications == false {
		// Marshal default failures
		resultCheck := ResultChecker{}
		err = json.Unmarshal([]byte(actionResult.Result), &resultCheck)
		if err == nil {
			//log.Printf("Unmarshal success!")
			if resultCheck.Success == false && strings.Contains(actionResult.Result, "success") && strings.Contains(actionResult.Result, "false") {
				err = CreateOrgNotification(
					ctx,
					fmt.Sprintf("Potential error in Workflow %#v", workflowExecution.Workflow.Name),
					fmt.Sprintf("Node %s in Workflow %s failed silently. Click to see more. Reason: %#v", actionResult.Action.Label, workflowExecution.Workflow.Name, resultCheck.Reason),
					fmt.Sprintf("/workflows/%s?execution_id=%s&view=executions&node=%s", workflowExecution.Workflow.ID, workflowExecution.ExecutionId, actionResult.Action.ID),
					workflowExecution.ExecutionOrg,
					true,
				)

				if err != nil {
					log.Printf("[WARNING] Failed making org notification for %s: %s", workflowExecution.ExecutionOrg, err)
				}
			}
		} else {
			//log.Printf("[ERROR] Failed unmarshaling result into resultChecker (%s): %#v", err, actionResult)
		}

		//log.Printf("[DEBUG] Ran marshal on silent failure")
	}

	// FIXME rebuild to be like this or something
	// workflowExecution/ExecutionId/Nodes/NodeId
	// Find the appropriate action
	if len(workflowExecution.Results) > 0 {
		// FIXME
		skip := false
		found := false
		outerindex := 0
		for index, item := range workflowExecution.Results {
			if item.Action.ID == actionResult.Action.ID {
				found = true
				if item.Status == actionResult.Status {
					skip = true
				}

				outerindex = index
				break
			}
		}

		if skip {
			//log.Printf("[DEBUG] Both results are %s. Skipping this node", item.Status)
		} else if found {
			// If result exists and execution variable exists, update execution value
			//log.Printf("Exec var backend: %s", workflowExecution.Results[outerindex].Action.ExecutionVariable.Name)
			actionVarName := workflowExecution.Results[outerindex].Action.ExecutionVariable.Name
			// Finds potential execution arguments
			if len(actionVarName) > 0 {
				//log.Printf("EXECUTION VARIABLE LOCAL: %s", actionVarName)
				for index, execvar := range workflowExecution.ExecutionVariables {
					if execvar.Name == actionVarName {
						// Sets the value for the variable

						if len(actionResult.Result) > 0 {
							log.Printf("\n\n[DEBUG] SET EXEC VAR\n\n", execvar.Name)
							workflowExecution.ExecutionVariables[index].Value = actionResult.Result
						} else {
							log.Printf("\n\n[DEBUG] SKIPPING EXEC VAR\n\n")
						}

						break
					}
				}
			}

			log.Printf("[INFO] Updating %s in workflow %s from %s to %s", actionResult.Action.ID, workflowExecution.ExecutionId, workflowExecution.Results[outerindex].Status, actionResult.Status)
			workflowExecution.Results[outerindex] = actionResult
		} else {
			//log.Printf("[INFO] Setting value of %s (%s) in workflow %s to %s (%d)", actionResult.Action.Label, actionResult.Action.ID, workflowExecution.ExecutionId, actionResult.Status, len(workflowExecution.Results))
			workflowExecution.Results = append(workflowExecution.Results, actionResult)
			//if subresult.Status == "SKIPPED" subresult.Status != "FAILURE" {
		}
	} else {
		log.Printf("[INFO] Setting value of %s (INIT - %s) in workflow %s to %s (%d)", actionResult.Action.Label, actionResult.Action.ID, workflowExecution.ExecutionId, actionResult.Status, len(workflowExecution.Results))
		workflowExecution.Results = append(workflowExecution.Results, actionResult)
	}

	// FIXME: Have a check for skippednodes and their parents
	/*
		for resultIndex, result := range workflowExecution.Results {
			if result.Status != "SKIPPED" {
				continue
			}

			// Checks if all parents are skipped or failed. Otherwise removes them from the results
			for _, branch := range workflowExecution.Workflow.Branches {
				if branch.DestinationID == result.Action.ID {
					for _, subresult := range workflowExecution.Results {
						if subresult.Action.ID == branch.SourceID {
							if subresult.Status != "SKIPPED" && subresult.Status != "FAILURE" {
								log.Printf("SUBRESULT PARENT STATUS: %s", subresult.Status)
								log.Printf("Should remove resultIndex: %d", resultIndex)

								workflowExecution.Results = append(workflowExecution.Results[:resultIndex], workflowExecution.Results[resultIndex+1:]...)

								break
							}
						}
					}
				}
			}
		}
	*/
	// Auto fixing and ensuring the same isn't ran multiple times?

	extraInputs := 0
	for _, trigger := range workflowExecution.Workflow.Triggers {
		if trigger.Name == "User Input" && trigger.AppName == "User Input" {
			extraInputs += 1
		} else if trigger.Name == "Shuffle Workflow" && trigger.AppName == "Shuffle Workflow" {
			extraInputs += 1
		}
	}

	//log.Printf("EXTRA: %d", extraInputs)
	//log.Printf("LENGTH: %d - %d", len(workflowExecution.Results), len(workflowExecution.Workflow.Actions)+extraInputs)
	updateParentRan := false
	if len(workflowExecution.Results) == len(workflowExecution.Workflow.Actions)+extraInputs {
		//log.Printf("\nIN HERE WITH RESULTS %d vs %d\n", len(workflowExecution.Results), len(workflowExecution.Workflow.Actions)+extraInputs)
		finished := true
		lastResult := ""

		// Doesn't have to be SUCCESS and FINISHED everywhere anymore.
		//skippedNodes := false
		for _, result := range workflowExecution.Results {
			if result.Status == "EXECUTING" || result.Status == "WAITING" {
				finished = false
				break
			}

			// FIXME: Check if ALL parents are skipped or if its just one. Otherwise execute it
			//if result.Status == "SKIPPED" {
			//	skippedNodes = true

			//	// Checks if all parents are skipped or failed. Otherwise removes them from the results
			//	for _, branch := range workflowExecution.Workflow.Branches {
			//		if branch.DestinationID == result.Action.ID {
			//			for _, subresult := range workflowExecution.Results {
			//				if subresult.Action.ID == branch.SourceID {
			//					if subresult.Status != "SKIPPED" && subresult.Status != "FAILURE" {
			//						//log.Printf("SUBRESULT PARENT STATUS: %s", subresult.Status)
			//						//log.Printf("Should remove resultIndex: %d", resultIndex)
			//						finished = false
			//						break
			//					}
			//				}
			//			}
			//		}

			//		if !finished {
			//			break
			//		}
			//	}
			//}

			lastResult = result.Result
		}

		//log.Printf("[debug] Finished? %#v", finished)
		if finished {
			dbSave = true
			if len(workflowExecution.ExecutionParent) == 0 {
				log.Printf("[INFO] Execution of %s in workflow %s finished (not subflow).", workflowExecution.ExecutionId, workflowExecution.Workflow.ID)
			} else {
				log.Printf("[INFO] SubExecution %s of parentExecution %s in workflow %s finished (subflow).", workflowExecution.ExecutionId, workflowExecution.ExecutionParent, workflowExecution.Workflow.ID)

			}

			for actionIndex, action := range workflowExecution.Workflow.Actions {
				for parameterIndex, param := range action.Parameters {
					if param.Configuration {
						//log.Printf("Cleaning up %s in %s", param.Name, action.Name)
						workflowExecution.Workflow.Actions[actionIndex].Parameters[parameterIndex].Value = ""
					}
				}
			}

			//log.Println("Might be finished based on length of results and everything being SUCCESS or FINISHED - VERIFY THIS. Setting status to finished.")

			workflowExecution.Result = lastResult
			workflowExecution.Status = "FINISHED"
			workflowExecution.CompletedAt = int64(time.Now().Unix())
			if workflowExecution.LastNode == "" {
				workflowExecution.LastNode = actionResult.Action.ID
			}

			// 1. Check if the LAST node is FAILURE or ABORTED or SKIPPED
			// 2. If it's either of those, set the executionResult default value to DefaultReturnValue
			//log.Printf("\n\n===========\nSETTING VALUE TO %#v\n============\nPARENT: %s\n\n", lastResult, workflowExecution.ExecutionParent)
			//log.Printf("\n\n===========\nSETTING VALUE TO %#v\n============\nPARENT: %s\n\n", lastResult, workflowExecution.ExecutionParent)
			//log.Printf("%#v", workflowExecution)

			valueToReturn := ""
			if len(workflowExecution.Workflow.DefaultReturnValue) > 0 {
				valueToReturn = workflowExecution.Workflow.DefaultReturnValue
				//log.Printf("\n\nCHECKING RESULT FOR LAST NODE %s with value \"%s\". Executionparent: %s\n\n", workflowExecution.ExecutionSourceNode, workflowExecution.Workflow.DefaultReturnValue, workflowExecution.ExecutionParent)
				for _, result := range workflowExecution.Results {
					if result.Action.ID == workflowExecution.LastNode {
						if result.Status == "ABORTED" || result.Status == "FAILURE" || result.Status == "SKIPPED" {
							workflowExecution.Result = workflowExecution.Workflow.DefaultReturnValue
							if len(workflowExecution.ExecutionParent) > 0 {
								// 1. Find the parent workflow
								// 2. Find the parent's existing value

								log.Printf("[DEBUG] FOUND SUBFLOW WITH EXECUTIONPARENT %s!", workflowExecution.ExecutionParent)
							}
						} else {
							valueToReturn = workflowExecution.Result
						}

						break
					}
				}
			} else {
				valueToReturn = workflowExecution.Result
			}

			// First: handle it in backend for loops
			// 2nd: Handle it in worker for normal executions
			/*
				if len(workflowExecution.ExecutionParent) > 0 && (project.Environment == "onprem") {
					log.Printf("[DEBUG] Got the result %s for subflow of %s. Check if this should be added to loop.", workflowExecution.Result, workflowExecution.ExecutionParent)

					parentExecution, err := GetWorkflowExecution(ctx, workflowExecution.ExecutionParent)
					if err == nil {
						isLooping := false
						for _, trigger := range parentExecution.Workflow.Triggers {
							if trigger.ID == workflowExecution.ExecutionSourceNode {
								for _, param := range trigger.Parameters {
									//log.Printf("PARAM: %#v", param)
									if param.Name == "argument" && strings.Contains(param.Value, "$") && strings.Contains(param.Value, ".#") {
										isLooping = true
										break
									}
								}

								break
							}
						}

						if isLooping {
							log.Printf("[DEBUG] Parentexecutions' subflow IS looping.")
						}
					}

				} else
			*/
			if len(workflowExecution.ExecutionParent) > 0 && len(workflowExecution.ExecutionSourceAuth) > 0 && len(workflowExecution.ExecutionSourceNode) > 0 {
				log.Printf("[DEBUG] Found execution parent %s for workflow %#v", workflowExecution.ExecutionParent, workflowExecution.Workflow.Name)

				err = updateExecutionParent(ctx, workflowExecution.ExecutionParent, valueToReturn, workflowExecution.ExecutionSourceAuth, workflowExecution.ExecutionSourceNode, workflowExecution.ExecutionId)
				if err != nil {
					log.Printf("[ERROR] Failed running update execution parent: %s", err)
				} else {
					updateParentRan = true
				}
			}
		}
	}

	// Had to move this to run AFTER "updateExecutionParent()", as it's controlling whether a subflow should be updated or not
	if actionResult.Status == "SUCCESS" && actionResult.Action.AppName == "shuffle-subflow" && !updateParentRan {
		runCheck := false
		for _, param := range actionResult.Action.Parameters {
			if param.Name == "check_result" {
				//log.Printf("[INFO] RESULT: %#v", param)
				if param.Value == "true" {
					runCheck = true
				}

				break
			}
		}

		//if runCheck && project.Environment != "" && project.Environment != "worker" {
		if runCheck {
			// err = updateExecutionParent(workflowExecution.ExecutionParent, valueToReturn, workflowExecution.ExecutionSourceAuth, workflowExecution.ExecutionSourceNode)

			var subflowData SubflowData
			jsonerr := json.Unmarshal([]byte(actionResult.Result), &subflowData)

			// Big blob to check cache & backend for more results
			if jsonerr == nil && len(subflowData.Result) == 0 && !strings.Contains(actionResult.Result, "\"result\"") {
				if project.Environment != "cloud" {

					//Check cache for whether the execution actually finished or not
					// FIXMe: May need to get this from backend

					cacheKey := fmt.Sprintf("workflowexecution-%s", subflowData.ExecutionId)
					if value, found := requestCache.Get(cacheKey); found {
						parsedValue := WorkflowExecution{}
						cacheData := []byte(value.([]uint8))
						err = json.Unmarshal(cacheData, &parsedValue)
						if err == nil {
							log.Printf("[INFO][%s] Found subflow result (1) %s for subflow %s in recheck from cache with %d results and result %#v", workflowExecution.ExecutionId, parsedValue.Status, subflowData.ExecutionId, len(parsedValue.Results), parsedValue.Result)

							if len(parsedValue.Result) > 0 {
								subflowData.Result = parsedValue.Result
							} else if parsedValue.Status == "FINISHED" {
								subflowData.Result = "Subflow finished (PS: This is from worker autofill - happens if no actual result in subflow exec)"
							}
						}

						// Check backend
						//log.Printf("[INFO][%s] Found subflow result %s for subflow %s in recheck from cache with %d results and result %#v", workflowExecution.ExecutionId, parsedValue.Status, subflowData.ExecutionId, len(parsedValue.Results), parsedValue.Result)
						if len(subflowData.Result) == 0 && !strings.Contains(actionResult.Result, "\"result\"") {
							log.Printf("[INFO][%s] No subflow result found in cache for subflow %s. Checking backend next", workflowExecution.ExecutionId, subflowData.ExecutionId)
							if len(subflowData.ExecutionId) > 0 {
								parsedValue, err := GetBackendexecution(ctx, subflowData.ExecutionId, subflowData.Authorization)
								if err != nil {
									log.Printf("[WARNING] Failed getting subflow execution from backend to verify: %s", err)
								} else {
									log.Printf("[INFO][%s] Found subflow result (2) %s for subflow %s in backend with %d results and result %#v", workflowExecution.ExecutionId, parsedValue.Status, subflowData.ExecutionId, len(parsedValue.Results), parsedValue.Result)
									if len(parsedValue.Result) > 0 {
										subflowData.Result = parsedValue.Result
									} else if parsedValue.Status == "FINISHED" {
										subflowData.Result = "Subflow finished (PS: This is from worker autofill - happens if no actual result in subflow exec)"
									}
								}
							}
						}
					}
				}
			}

			log.Printf("[WARNING] Sinkholing request of %#v IF the subflow-result DOESNT have result. Value: %s", actionResult.Action.Label, actionResult.Result)
			if jsonerr == nil && len(subflowData.Result) == 0 && !strings.Contains(actionResult.Result, "\"result\"") {
				//func updateExecutionParent(executionParent, returnValue, parentAuth, parentNode string) error {
				log.Printf("[INFO][%s] NO RESULT FOR SUBFLOW RESULT - SETTING TO EXECUTING. Results: %d. Trying to find subexec in cache onprem\n\n", workflowExecution.ExecutionId, len(workflowExecution.Results))

				// Finding the result, and removing it if it exists. "Sinkholing"
				workflowExecution.Status = "EXECUTING"
				newResults := []ActionResult{}
				for _, result := range workflowExecution.Results {
					if result.Action.ID == actionResult.Action.ID {
						continue
					}

					newResults = append(newResults, result)
				}

				workflowExecution.Results = newResults

				//for _, result := range
			} else {
				var subflowDataList []SubflowData
				err = json.Unmarshal([]byte(actionResult.Result), &subflowDataList)
				if err != nil || len(subflowDataList) == 0 {
					log.Printf("\n\nNOT sinkholed")
					for resultIndex, result := range workflowExecution.Results {
						if result.Action.ID == actionResult.Action.ID {
							workflowExecution.Results[resultIndex] = actionResult
							break
						}
					}

				} else {
					log.Printf("\n\nLIST NOT sinkholed (%d) - Should apply list setup for same as subflow without result! Set the execution back to EXECUTING and the action to WAITING, as it's already running. Waiting for each individual result to add to the list.\n\n", len(subflowDataList))

					// Set to executing, as the point is for the subflows themselves to update this part. This does NOT happen in the subflow, but in the parent workflow, which is waiting for results to be ingested, hence it's set to EXECUTING
					workflowExecution.Status = "EXECUTING"

					// Setting to waiting, as it should be updated by child executions
					actionResult.Status = "WAITING"
					for resultIndex, result := range workflowExecution.Results {
						if result.Action.ID == actionResult.Action.ID {
							workflowExecution.Results[resultIndex] = actionResult
							break
						}
					}

					/*
						for _, subflowItem := range subflowDataList {
							log.Printf("%s == %s", subflowItem.ExecutionId, workflowExecution.ExecutionId)

							if len(subflowItem.Result) == 0 {
								subflowItem.Result = workflowExecution.Result

								//if subflowItem.ExecutionId == workflowExecution.ExecutionId {
								//	log.Printf("FOUND EXECUTION ID IN SUBFLOW: %s", subflowItem.ExecutionId)
								//tmpJson, err := json.Marshal(workflowExecution)
								//if strings.Contains(
							}
						}
					*/
				}

				dbSave = true
			}
		}
	}

	workflowExecution, newDbSave := compressExecution(ctx, workflowExecution, "mid-cleanup")
	if !dbSave {
		dbSave = newDbSave
	}

	// Should only apply a few seconds after execution, otherwise it's bascially spam.
	//log.Printf("Timestamps: %d vs now: %d", workflowExecution.StartedAt, time.Now().Unix())

	// FIXME: May be better to do this by rerunning the workflow
	// after 20 seconds to re-check it
	// Don't want to run from the get-go

	if time.Now().Unix()-workflowExecution.StartedAt > 5 {
		_, _, _, _, _, newExecuted, _, _ := GetExecutionVariables(ctx, workflowExecution.ExecutionId)
		foundNotExecuted := []string{}
		for _, executedItem := range newExecuted {
			if executedItem == actionResult.Action.ID {
				continue
			}

			found := false
			for _, result := range workflowExecution.Results {
				if result.Action.ID == executedItem {
					found = true
					break
				}
			}

			if !found {
				foundNotExecuted = append(foundNotExecuted, executedItem)
			}
		}

		if len(foundNotExecuted) > 0 {
			// Running them right away?
			validateFinishedExecution(ctx, workflowExecution, foundNotExecuted, retries)
		} else {
			//log.Printf("\n\n[WARNING] Rerunning checks for whether the execution is done at all.\n\n")

			// FIXME: Doesn't take into accoutn subflows and user input trigger
			allActions := workflowExecution.Workflow.Actions
			for _, trigger := range workflowExecution.Workflow.Triggers {
				//log.Printf("Appname trigger (0): %s", trigger.AppName)
				if trigger.AppName == "User Input" || trigger.AppName == "Shuffle Workflow" {
					allActions = append(allActions, Action{
						ID:      trigger.ID,
						Name:    trigger.Name,
						AppName: trigger.AppName,
					})
				}
			}

			for _, action := range allActions {
				found := false
				for _, result := range workflowExecution.Results {
					if result.Action.ID == action.ID {
						found = true
						break
					}
				}

				if found {
					continue
				}

				//log.Printf("[DEBUG] Maybe not handled yet: %s", action.ID)
				cacheId := fmt.Sprintf("%s_%s_result", workflowExecution.ExecutionId, action.ID)
				cache, err := GetCache(ctx, cacheId)
				if err != nil {
					//log.Printf("[WARNING] Couldn't find in fix exec %s (2): %s", cacheId, err)
					continue
				}

				actionResult := ActionResult{}
				cacheData := []byte(cache.([]uint8))

				// Just ensuring the data is good
				err = json.Unmarshal(cacheData, &actionResult)
				if err != nil {
					log.Printf("[WARNING] Failed unmarshal in fix exec %s (2): %s", cacheId, err)
					continue
				}

				log.Printf("[DEBUG] Should rerun (1)? %s (%s - %s)", action.Label, action.Name, action.ID)
				// If reruns, make sure it waits a bit for the next executions?
				// This may cause one action that actually finished to get its result sent AFTER the next one, leading to missing information in subsequent nodes.
				if len(actionResult.Action.ExecutionVariable.Name) > 0 && (actionResult.Status == "SUCCESS" || actionResult.Status == "FINISHED") {

					setExecVar := true
					//log.Printf("\n\n[DEBUG] SETTING ExecVar RESULTS: %#v", actionResult.Result)
					if strings.Contains(actionResult.Result, "\"success\":") {
						type SubflowMapping struct {
							Success bool `json:"success"`
						}

						var subflowData SubflowMapping
						err := json.Unmarshal([]byte(actionResult.Result), &subflowData)
						if err != nil {
							log.Printf("[ERROR] Failed to map in set execvar name with success: %s", err)
							setExecVar = false
						} else {
							if subflowData.Success == false {
								setExecVar = false
							}
						}
					}

					if len(actionResult.Result) == 0 {
						setExecVar = false
					}

					if setExecVar {
						log.Printf("[DEBUG] Updating exec variable %s with new value of length %d (1)", actionResult.Action.ExecutionVariable.Name, len(actionResult.Result))

						if len(workflowExecution.Results) > 0 {
							lastResult := workflowExecution.Results[len(workflowExecution.Results)-1].Result
							_ = lastResult
							//log.Printf("LAST: %s", lastResult)
						}

						actionResult.Action.ExecutionVariable.Value = actionResult.Result

						foundIndex := -1
						for i, executionVariable := range workflowExecution.ExecutionVariables {
							if executionVariable.Name == actionResult.Action.ExecutionVariable.Name {
								foundIndex = i
								break
							}
						}

						if foundIndex >= 0 {
							workflowExecution.ExecutionVariables[foundIndex] = actionResult.Action.ExecutionVariable
						} else {
							workflowExecution.ExecutionVariables = append(workflowExecution.ExecutionVariables, actionResult.Action.ExecutionVariable)
						}
					} else {
						log.Printf("[DEBUG] NOT updating exec variable %s with new value of length %d. Checkp revious errors, or if action was successful (success: true)", actionResult.Action.ExecutionVariable.Name, len(actionResult.Result))
					}
				}

				workflowExecution.Results = append(workflowExecution.Results, actionResult)
				if os.Getenv("SHUFFLE_SWARM_CONFIG") == "run" && (project.Environment == "" || project.Environment == "worker") {
					go ResendActionResult(cacheData, 0)
				} else {
					workflowExecution.Results = append(workflowExecution.Results, actionResult)
				}
			}
		}
	}

	if !skipExecutionCount && workflowExecution.Status == "FINISHED" {
		IncrementCache(ctx, workflowExecution.ExecutionOrg, "workflow_executions_finished")
	}

	// Should this be able to return errors?
	//return &workflowExecution, dbSave, err
	return &workflowExecution, dbSave, nil
}

// Finds execution results and parameters that are too large to manage and reduces them / saves data partly
func compressExecution(ctx context.Context, workflowExecution WorkflowExecution, saveLocationInfo string) (WorkflowExecution, bool) {

	//GetApp(ctx context.Context, id string, user User) (*WorkflowApp, error) {
	//return workflowExecution, false
	dbSave := false
	tmpJson, err := json.Marshal(workflowExecution)
	if err == nil {
		if project.DbType != "elasticsearch" {
			if len(tmpJson) >= 1000000 {
				// Clean up results' actions

				dbSave = true
				log.Printf("[WARNING] Result length is too long (%d) when running %s! Need to reduce result size. Attempting auto-compression by saving data to disk.", len(tmpJson), saveLocationInfo)
				actionId := "execution_argument"

				//gs://shuffler.appspot.com/extra_specs/0373ed696a3a2cba0a2b6838068f2b80
				//log.Printf("[WARNING] Couldn't find  for %s. Should check filepath gs://%s/%s (size too big)", innerApp.ID, internalBucket, fullParsedPath)

				// Result        string `json:"result" datastore:"result,noindex"`
				// Arbitrary reduction size
				maxSize := 50000
				bucketName := "shuffler.appspot.com"

				if len(workflowExecution.ExecutionArgument) > maxSize {
					itemSize := len(workflowExecution.ExecutionArgument)
					baseResult := fmt.Sprintf(`{
								"success": False,
								"reason": "Result too large to handle (https://github.com/frikky/shuffle/issues/171)."
								"size": %d,
								"extra": "",
								"id": "%s_%s"
							}`, itemSize, workflowExecution.ExecutionId, actionId)

					fullParsedPath := fmt.Sprintf("large_executions/%s/%s_%s", workflowExecution.ExecutionOrg, workflowExecution.ExecutionId, actionId)
					log.Printf("[DEBUG] Saving value of %s to storage path %s", actionId, fullParsedPath)
					bucket := project.StorageClient.Bucket(bucketName)
					obj := bucket.Object(fullParsedPath)
					w := obj.NewWriter(ctx)
					if _, err := fmt.Fprint(w, workflowExecution.ExecutionArgument); err != nil {
						log.Printf("[WARNING] Failed writing new exec file: %s", err)
						workflowExecution.ExecutionArgument = baseResult
						//continue
					} else {
						// Close, just like writing a file.
						if err := w.Close(); err != nil {
							log.Printf("[WARNING] Failed closing new exec file: %s", err)
							workflowExecution.ExecutionArgument = baseResult
						} else {
							workflowExecution.ExecutionArgument = fmt.Sprintf(`{
								"success": False,
								"reason": "Result too large to handle (https://github.com/frikky/shuffle/issues/171).",
								"size": %d,
								"extra": "replace",
								"id": "%s_%s"
							}`, itemSize, workflowExecution.ExecutionId, actionId)
						}
					}
				}

				newResults := []ActionResult{}
				//shuffle-large-executions
				for _, item := range workflowExecution.Results {
					if len(item.Result) > maxSize {

						itemSize := len(item.Result)
						baseResult := fmt.Sprintf(`{
								"success": False,
								"reason": "Result too large to handle (https://github.com/frikky/shuffle/issues/171)."
								"size": %d,
								"extra": "",
								"id": "%s_%s"
							}`, itemSize, workflowExecution.ExecutionId, item.Action.ID)

						// 1. Get the value and set it instead if it exists
						// 2. If it doesn't exist, add it
						_, err := getExecutionFileValue(ctx, workflowExecution, item)
						if err == nil {
							//log.Printf("[DEBUG] Found execution locally for %s. Not saving another.", item.Action.Label)
						} else {
							fullParsedPath := fmt.Sprintf("large_executions/%s/%s_%s", workflowExecution.ExecutionOrg, workflowExecution.ExecutionId, item.Action.ID)
							log.Printf("[DEBUG] Saving value of %s to storage path %s", item.Action.ID, fullParsedPath)
							bucket := project.StorageClient.Bucket(bucketName)
							obj := bucket.Object(fullParsedPath)
							w := obj.NewWriter(ctx)
							//log.Printf("RES: ", item.Result)
							if _, err := fmt.Fprint(w, item.Result); err != nil {
								log.Printf("[WARNING] Failed writing new exec file: %s", err)
								item.Result = baseResult
								newResults = append(newResults, item)
								continue
							}

							// Close, just like writing a file.
							if err := w.Close(); err != nil {
								log.Printf("[WARNING] Failed closing new exec file: %s", err)
								item.Result = baseResult
								newResults = append(newResults, item)
								continue
							}
						}

						item.Result = fmt.Sprintf(`{
								"success": False,
								"reason": "Result too large to handle (https://github.com/frikky/shuffle/issues/171).",
								"size": %d,
								"extra": "replace",
								"id": "%s_%s"
							}`, itemSize, workflowExecution.ExecutionId, item.Action.ID)
						// Setting an arbitrary decisionpoint to get it
						// Backend will use this ID + action ID to get the data back
						//item.Result = fmt.Sprintf("EXECUTION=%s", workflowExecution.ExecutionId)
					}

					newResults = append(newResults, item)
				}

				workflowExecution.Results = newResults
			}

			jsonString, err := json.Marshal(workflowExecution)
			if err == nil {
				//log.Printf("Execution size: %d", len(jsonString))
				if len(jsonString) > 1000000 {
					//for _, action := range workflowExecution.Workflow.Actions {
					//	actionData, err := json.Marshal(action)
					//	if err == nil {
					//		//log.Printf("[DEBUG] Action Size for %s (%s - %s): %d", action.Label, action.Name, action.ID, len(actionData))
					//	}
					//}

					for resultIndex, result := range workflowExecution.Results {
						//resultData, err := json.Marshal(result)
						//_ = resultData
						actionData, err := json.Marshal(result.Action)
						if err == nil {
							//log.Printf("Result Size (%s - action: %d): %d. Value size: %d", result.Action.Label, len(resultData), len(actionData), len(result.Result))
						}

						if len(actionData) > 10000 {
							for paramIndex, param := range result.Action.Parameters {
								if len(param.Value) > 10000 {
									workflowExecution.Results[resultIndex].Action.Parameters[paramIndex].Value = "Size too large. Removed."
								}
							}
						}
					}
				}
			}
		}
	}

	return workflowExecution, dbSave
}

func GetExecutionbody(body []byte) string {
	parsedBody := string(body)

	// Specific weird newline issues
	if strings.Contains(parsedBody, "choice") {
		if strings.Count(parsedBody, `\\n`) > 2 {
			parsedBody = strings.Replace(parsedBody, `\\n`, "", -1)
		}
		if strings.Count(parsedBody, `\u0022`) > 2 {
			parsedBody = strings.Replace(parsedBody, `\u0022`, `"`, -1)
		}
		if strings.Count(parsedBody, `\\"`) > 2 {
			parsedBody = strings.Replace(parsedBody, `\\"`, `"`, -1)
		}

		if strings.Contains(parsedBody, `"extra": "{`) {
			parsedBody = strings.Replace(parsedBody, `"extra": "{`, `"extra": {`, 1)
			parsedBody = strings.Replace(parsedBody, `}"}`, `}}`, 1)
		}
	}

	// Replaces dots in string when it's key specifically has a dot
	// FIXME: Do this with key recursion and key replacements only
	pattern := regexp.MustCompile(`\"(\w+)\.(\w+)\":`)
	found := pattern.FindAllString(parsedBody, -1)
	for _, item := range found {
		newItem := strings.Replace(item, ".", "_", -1)
		parsedBody = strings.Replace(parsedBody, item, newItem, -1)
	}

	if !strings.HasPrefix(parsedBody, "{") && !strings.HasPrefix(parsedBody, "[") && strings.Contains(parsedBody, "=") {
		log.Printf("[DEBUG] Trying to make string %s to json (skipping if XML)", parsedBody)

		// Dumb XML handler
		if strings.HasPrefix(strings.TrimSpace(parsedBody), "<") && strings.HasSuffix(strings.TrimSpace(parsedBody), ">") {
			log.Printf("[DEBUG] XML detected. Not parsing anyything.")
			return parsedBody
		}

		newbody := map[string]string{}
		for _, item := range strings.Split(parsedBody, "&") {
			//log.Printf("Handling item: %s", item)

			if !strings.Contains(item, "=") {
				newbody[item] = ""
				continue
			}

			bodySplit := strings.Split(item, "=")
			if len(bodySplit) == 2 {
				newbody[bodySplit[0]] = bodySplit[1]
			} else {
				newbody[item] = ""
			}
		}

		jsonString, err := json.Marshal(newbody)
		if err != nil {
			log.Printf("[ERROR] Failed marshaling queries: %#v: %s", newbody, err)
		} else {
			parsedBody = string(jsonString)
		}
		//fmt.Println(err)
		//log.Printf("BODY: %#v", newbody)
	}

	// Check bad characters in keys
	// FIXME: Re-enable this when it's safe.
	//log.Printf("Input: %s", parsedBody)
	parsedBody = string(FixBadJsonBody([]byte(parsedBody)))
	//log.Printf("Output: %s", parsedBody)

	return parsedBody
}

/*
func CleanupExecutions(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[INFO] Api authentication failed in cleanup executions: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "message": "Not authenticated"}`))
		return
	}

	if user.Role != "admin" {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "message": "Insufficient permissions"}`))
		return
	}

	ctx := context.Background()

	// Removes three months from today
	timestamp := int64(time.Now().AddDate(0, -2, 0).Unix())
	log.Println(timestamp)
	q := datastore.NewQuery("workflowexecution").Filter("started_at <", timestamp)
	var workflowExecutions []WorkflowExecution
	_, err = project.Dbclient.GetAll(ctx, q, &workflowExecutions)
	if err != nil {
		log.Printf("Error getting workflowexec (cleanup): %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Failed getting all workflowexecutions"}`)))
		return
	}

	resp.WriteHeader(200)
	resp.Write([]byte(`{"success": true}`))
}
*/

// Checks if data is sent from Worker >0.8.51, which sends a full execution
// instead of individial results
func ValidateNewWorkerExecution(body []byte) error {
	ctx := context.Background()
	var execution WorkflowExecution
	err := json.Unmarshal(body, &execution)
	if err != nil {
		log.Printf("[WARNING] Failed execution unmarshaling: %s", err)
		if strings.Contains(fmt.Sprintf("%s", err), "array into") {
			log.Printf("Array unmarshal error: %s", string(body))
		}

		return err
	}
	//log.Printf("\n\nGOT EXEC WITH RESULT %#v (%d)\n\n", execution.Status, len(execution.Results))

	baseExecution, err := GetWorkflowExecution(ctx, execution.ExecutionId)
	if err != nil {
		log.Printf("[ERROR] Failed getting execution (workflowqueue) %s: %s", execution.ExecutionId, err)
		return err
	}

	if baseExecution.Authorization != execution.Authorization {
		return errors.New("Bad authorization when validating execution")
	}

	// used to validate if it's actually the right marshal
	if len(baseExecution.Workflow.Actions) != len(execution.Workflow.Actions) {
		return errors.New(fmt.Sprintf("Bad length of actions (probably normal app): %d", len(execution.Workflow.Actions)))
	}

	if len(baseExecution.Workflow.Triggers) != len(execution.Workflow.Triggers) {
		return errors.New(fmt.Sprintf("Bad length of trigger: %d (probably normal app)", len(execution.Workflow.Triggers)))
	}

	//if len(baseExecution.Results) >= len(execution.Results) {
	if len(baseExecution.Results) > len(execution.Results) {
		return errors.New(fmt.Sprintf("Can't have less actions in a full execution than what exists: %d (old) vs %d (new)", len(baseExecution.Results), len(execution.Results)))
	}

	//if baseExecution.Status != "WAITING" && baseExecution.Status != "EXECUTING" {
	//	return errors.New(fmt.Sprintf("Workflow is already finished or failed. Can't update"))
	//}

	if execution.Status == "EXECUTING" {
		//log.Printf("[INFO] Inside executing.")
		extra := 0
		for _, trigger := range execution.Workflow.Triggers {
			//log.Printf("Appname trigger (0): %s", trigger.AppName)
			if trigger.AppName == "User Input" || trigger.AppName == "Shuffle Workflow" {
				extra += 1
			}
		}

		if len(execution.Workflow.Actions)+extra == len(execution.Results) {
			execution.Status = "FINISHED"
		}
	}

	// Finds if subflow HAS a value when it should, otherwise it's not being set
	//log.Printf("\n\nUpdating worker execution info")
	for _, result := range execution.Results {
		//log.Printf("%s = %s", result.Action.AppName, result.Status)
		if result.Action.AppName == "shuffle-subflow" {
			if result.Status == "SKIPPED" {
				continue
			}

			//log.Printf("\n\nFound SUBFLOW in full result send \n\n")
			for _, trigger := range baseExecution.Workflow.Triggers {
				if trigger.ID == result.Action.ID {
					//log.Printf("Found SUBFLOW id: %s", trigger.ID)

					for _, param := range trigger.Parameters {
						if param.Name == "check_result" && param.Value == "true" {
							//log.Printf("Found check as true!")

							var subflowData SubflowData
							err = json.Unmarshal([]byte(result.Result), &subflowData)
							if err != nil {
								log.Printf("Failed unmarshal in subflow check for %s: %s", result.Result, err)
							} else if len(subflowData.Result) == 0 {
								log.Printf("There is no result yet. Don't save?")
							} else {
								//log.Printf("There is a result: %s", result.Result)
							}

							break
						}
					}

					break
				}
			}
		}
	}

	// FIXME: Add extra here
	//executionLength := len(baseExecution.Workflow.Actions)
	//if executionLength != len(execution.Results) {
	//	return errors.New(fmt.Sprintf("Bad length of actions vs results: want: %d have: %d", executionLength, len(execution.Results)))
	//}

	err = SetWorkflowExecution(ctx, execution, true)
	executionSet := true
	if err == nil {
		log.Printf("[INFO] Set workflowexecution based on new worker (>0.8.53) for execution %s. Actions: %d, Triggers: %d, Results: %d, Status: %s", execution.ExecutionId, len(execution.Workflow.Actions), len(execution.Workflow.Triggers), len(execution.Results), execution.Status) //, execution.Result)
		executionSet = true
	} else {
		log.Printf("[WARNING] Failed setting the execution for new worker (>0.8.53) - retrying once: %s. ExecutionId: %s, Actions: %d, Triggers: %d, Results: %d, Status: %s", err, execution.ExecutionId, len(execution.Workflow.Actions), len(execution.Workflow.Triggers), len(execution.Results), execution.Status)
		// Retrying
		time.Sleep(5 * time.Second)
		err = SetWorkflowExecution(ctx, execution, true)
		if err != nil {
			log.Printf("[ERROR] Failed setting the execution for new worker (>0.8.53) - 2nd attempt: %s. ExecutionId: %s, Actions: %d, Triggers: %d, Results: %d, Status: %s", err, execution.ExecutionId, len(execution.Workflow.Actions), len(execution.Workflow.Triggers), len(execution.Results), execution.Status)
		} else {
			executionSet = true
		}
	}

	// Long convoluted way of validating and setting the value of a subflow that is also a loop
	// FIXME: May cause errors in worker that runs it all instantly due to
	// timing issues / non-queues
	if executionSet {
		RunFixParentWorkflowResult(ctx, execution)
	}

	return nil
}


func RunFixParentWorkflowResult(ctx context.Context, execution WorkflowExecution) error {
	//log.Printf("IS IT SUBFLOW?")
	if len(execution.ExecutionParent) > 0 && execution.Status != "EXECUTING" && (project.Environment == "onprem" || project.Environment == "cloud") {
		log.Printf("[DEBUG] Got the result %s for subflow of %s. Check if this should be added to loop.", execution.Result, execution.ExecutionParent)

		parentExecution, err := GetWorkflowExecution(ctx, execution.ExecutionParent)
		if err == nil {
			isLooping := false
			setExecution := true
			shouldSetValue := false
			for _, trigger := range parentExecution.Workflow.Triggers {
				if trigger.ID == execution.ExecutionSourceNode {
					for _, param := range trigger.Parameters {
						if param.Name == "workflow" && param.Value != execution.Workflow.ID {
							setExecution = false
						}

						//log.Printf("PARAM: %#v", param)
						if param.Name == "argument" && strings.Contains(param.Value, "$") && strings.Contains(param.Value, ".#") {
							isLooping = true
						}

						if param.Name == "check_result" && param.Value == "true" {
							shouldSetValue = true
						}
					}

					break
				}
			}

			if !isLooping && setExecution && shouldSetValue && parentExecution.Status == "EXECUTING" {
				//log.Printf("[DEBUG] Its NOT looping. Should set?")
				return nil
			} else if isLooping && setExecution && shouldSetValue && parentExecution.Status == "EXECUTING" {
				log.Printf("[DEBUG] Parentexecutions' subflow IS looping and is correct workflow. Should find correct answer in the node's result. Length of results: %d", len(parentExecution.Results))
				// 1. Find the action's existing result
				// 2. ONLY update it if the action status is WAITING and workflow status is EXECUTING
				// 3. IF all parts of the subflow execution are finished, set it to FINISHED
				// 4. If result length == length of actions + extra, set it to FINISHED
				// 5. Before setting parent execution, make sure to grab the latest version of the workflow again, in case processing time is slow
				resultIndex := -1
				updateIndex := -1
				for parentResultIndex, result := range parentExecution.Results {
					if result.Action.ID != execution.ExecutionSourceNode {
						continue
					}
					log.Printf("[DEBUG] Found action %s' results: %s", result.Action.ID, result.Result)
					if result.Status != "WAITING" {
						break
					}

					//result.Result
					var subflowDataLoop []SubflowData
					err = json.Unmarshal([]byte(result.Result), &subflowDataLoop)
					if err != nil {
						log.Printf("[DEBUG] Failed unmarshaling in set parent data: %s", err)
						break
					}

					for subflowIndex, subflowResult := range subflowDataLoop {
						if subflowResult.ExecutionId != execution.ExecutionId {
							continue
						}

						log.Printf("[DEBUG] Found right execution on index %d. Result: %s", subflowIndex, subflowResult.Result)
						if len(subflowResult.Result) == 0 {
							updateIndex = subflowIndex
						}

						resultIndex = parentResultIndex
						break
					}
				}

				// FIXME: MAY cause transaction issues.
				if updateIndex >= 0 && resultIndex >= 0 {
					log.Printf("[DEBUG] Should update index %d in resultIndex %d with new result %s", updateIndex, resultIndex, execution.Result)
					// FIXME: Are results ordered? Hmmmmm
					// Again, get the result, just in case, and update that exact value instantly
					newParentExecution, err := GetWorkflowExecution(ctx, execution.ExecutionParent)
					if err == nil {

						var subflowDataLoop []SubflowData
						err = json.Unmarshal([]byte(newParentExecution.Results[resultIndex].Result), &subflowDataLoop)
						if err == nil {
							subflowDataLoop[updateIndex].Result = execution.Result
							subflowDataLoop[updateIndex].ResultSet = true

							marshalledSubflow, err := json.Marshal(subflowDataLoop)
							if err == nil {
								newParentExecution.Results[resultIndex].Result = string(marshalledSubflow)
								err = SetWorkflowExecution(ctx, *newParentExecution, true)
								if err != nil {
									log.Printf("[WARNING] Error saving parent execution in subflow setting: %s", err)
								} else {
									log.Printf("[DEBUG] Updated index %d in subflow result %d with value of length %d. IDS HAVE TO MATCH: %s vs %s", updateIndex, resultIndex, len(execution.Result), subflowDataLoop[updateIndex].ExecutionId, execution.ExecutionId)
								}
							}

							// Validating if all are done and setting back to executing
							allFinished := true
							for _, parentResult := range newParentExecution.Results {
								if parentResult.Action.ID != execution.ExecutionSourceNode {
									continue
								}

								var subflowDataLoop []SubflowData
								err = json.Unmarshal([]byte(parentResult.Result), &subflowDataLoop)
								if err == nil {
									for _, subflowResult := range subflowDataLoop {
										if subflowResult.ResultSet != true {
											allFinished = false
											break
										}
									}

									break
								} else {
									allFinished = false
									break
								}
							}

							// FIXME: This will break if subflow with loop is last node in two workflows in a row (main workflow -> []subflow -> []subflow)
							// Should it send the whole thing back as a result to itself to be handled manually? :thinking:
							if allFinished {
								newParentExecution.Results[resultIndex].Status = "SUCCESS"

								extra := 0
								for _, trigger := range newParentExecution.Workflow.Triggers {
									//log.Printf("Appname trigger (0): %s", trigger.AppName)
									if trigger.AppName == "User Input" || trigger.AppName == "Shuffle Workflow" {
										extra += 1
									}
								}

								if len(newParentExecution.Workflow.Actions)+extra == len(newParentExecution.Results) {
									newParentExecution.Status = "FINISHED"
								}

								err = SetWorkflowExecution(ctx, *newParentExecution, true)
								if err != nil {
									log.Printf("[ERROR] Failed updating setExecution to FINISHED and SUCCESS: %s", err)
								}
							}
						} else {
							log.Printf("[WARNING] Failed to unmarshal result in set parent subflow: %s", err)
						}

						//= newValue
					} else {
						log.Printf("[WARNING] Failed to update parent, because execution %s couldn't be found: %s", execution.ExecutionParent, err)
					}
				}
			}
		}
	}

	return nil
}

//// New execution with firestore
func PrepareWorkflowExecution(ctx context.Context, workflow Workflow, request *http.Request, maxExecutionDepth int64) (WorkflowExecution, ExecInfo, string, error) {

	workflowBytes, err := json.Marshal(workflow)
	if err != nil {
		log.Printf("Failed workflow unmarshal in execution: %s", err)
		return WorkflowExecution{}, ExecInfo{}, "", err
	}

	//log.Println(workflow)
	var workflowExecution WorkflowExecution
	err = json.Unmarshal(workflowBytes, &workflowExecution.Workflow)
	if err != nil {
		log.Printf("[WARNING] Failed prepare execution unmarshaling: %s", err)
		return WorkflowExecution{}, ExecInfo{}, "Failed unmarshal during execution", err
	}

	makeNew := true
	start, startok := request.URL.Query()["start"]
	if request.Method == "POST" {
		body, err := ioutil.ReadAll(request.Body)
		if err != nil {
			log.Printf("[ERROR] Failed request POST read: %s", err)
			return WorkflowExecution{}, ExecInfo{}, "Failed getting body", err
		}

		// This one doesn't really matter.
		log.Printf("[INFO] Running POST execution with body of length %d for workflow %s", len(string(body)), workflowExecution.Workflow.ID)

		if len(body) >= 4 {
			if body[0] == 34 && body[len(body)-1] == 34 {
				body = body[1 : len(body)-1]
			}
			if body[0] == 34 && body[len(body)-1] == 34 {
				body = body[1 : len(body)-1]
			}
		}

		sourceAuth, sourceAuthOk := request.URL.Query()["source_auth"]
		if sourceAuthOk {
			//log.Printf("\n\n\nSETTING SOURCE WORKFLOW AUTH TO %s!!!\n\n\n", sourceAuth[0])
			workflowExecution.ExecutionSourceAuth = sourceAuth[0]
		} else {
			//log.Printf("Did NOT get source workflow")
		}

		sourceNode, sourceNodeOk := request.URL.Query()["source_node"]
		if sourceNodeOk {
			//log.Printf("\n\n\nSETTING SOURCE WORKFLOW NODE TO %s!!!\n\n\n", sourceNode[0])
			workflowExecution.ExecutionSourceNode = sourceNode[0]
		} else {
			//log.Printf("Did NOT get source workflow")
		}

		//workflowExecution.ExecutionSource = "default"
		sourceWorkflow, sourceWorkflowOk := request.URL.Query()["source_workflow"]
		if sourceWorkflowOk {
			//log.Printf("Got source workflow %s", sourceWorkflow)
			workflowExecution.ExecutionSource = sourceWorkflow[0]
		} else {
			//log.Printf("Did NOT get source workflow")
		}

		sourceExecution, sourceExecutionOk := request.URL.Query()["source_execution"]
		parentExecution := &WorkflowExecution{}
		if sourceExecutionOk {
			//log.Printf("[INFO] Got source execution%s", sourceExecution)
			workflowExecution.ExecutionParent = sourceExecution[0]

			// FIXME: Get the execution and check count
			//workflowExecution.SubExecutionCount += 1

			//log.Printf("\n\n[INFO] PARENT!!: %#v\n\n", workflowExecution.ExecutionParent)
			parentExecution, err = GetWorkflowExecution(ctx, workflowExecution.ExecutionParent)
			if err == nil {
				workflowExecution.SubExecutionCount = parentExecution.SubExecutionCount + 1
			}

			// Subflow are JUST lower than manual executions
			if workflowExecution.Priority == 0 {
				workflowExecution.Priority = 9
			}
		} else {
			//log.Printf("Did NOT get source execution")
		}

		// Checks whether the subflow has been ran before based on parent execution ID + parent execution node ID (always unique)
		// Used to deduplicate runs
		if len(workflowExecution.ExecutionParent) > 0 && len(workflowExecution.ExecutionSourceNode) > 0 {
			// Check if it should be looping:
			// 1. Get workflowExecution.ExecutionParent's workflow
			// 2. Find the ExecutionSourceNode
			// 3. Check if the value of it is looping
			var parentErr error
			if len(parentExecution.ExecutionId) == 0 {
				parentExecution, parentErr = GetWorkflowExecution(ctx, workflowExecution.ExecutionParent)
			}

			allowContinuation := false
			if parentErr == nil {
				for _, trigger := range parentExecution.Workflow.Triggers {
					if trigger.ID != workflowExecution.ExecutionSourceNode {
						continue
					}

					//$Get_Offenses.# -> Allow to run more
					for _, param := range trigger.Parameters {
						if param.Name == "argument" {
							if strings.Contains(param.Value, "$") && strings.Contains(param.Value, ".#") {
								allowContinuation = true
								break
							}
						}
					}

					if allowContinuation {
						break
					}
				}
			}

			if allowContinuation == false {
				newExecId := fmt.Sprintf("%s_%s_%s", workflowExecution.ExecutionParent, workflowExecution.ExecutionId, workflowExecution.ExecutionSourceNode)
				cache, err := GetCache(ctx, newExecId)
				if err == nil {
					cacheData := []byte(cache.([]uint8))

					newexec := WorkflowExecution{}
					log.Printf("[WARNING] Subflow exec %s already found - returning", newExecId)

					// Returning to be used in worker
					err = json.Unmarshal(cacheData, &newexec)
					if err == nil {
						return newexec, ExecInfo{}, fmt.Sprintf("Subflow for %s has already been executed", newExecId), errors.New(fmt.Sprintf("Subflow for %s has already been executed", newExecId))
					}

					return workflowExecution, ExecInfo{}, fmt.Sprintf("Subflow for %s has already been executed", newExecId), errors.New(fmt.Sprintf("Subflow for %s has already been executed", newExecId))
				}

				cacheData := []byte("1")
				err = SetCache(ctx, newExecId, cacheData)
				if err != nil {
					log.Printf("[WARNING] Failed setting cache for action %s: %s", newExecId, err)
				} else {
					//log.Printf("\n\n[DEBUG] Adding %s to cache.\n\n", newExecId)
				}
			}
		}

		if len(string(body)) < 50 {
			log.Printf("[DEBUG] Body: %#v", string(body))
		}

		var execution ExecutionRequest
		err = json.Unmarshal(body, &execution)
		if err != nil {
			//log.Printf("[WARNING] Failed execution POST unmarshaling - continuing anyway: %s", err)
			//return WorkflowExecution{}, "", err
		}

		// Ensuring it works even if startpoint isn't defined
		if execution.Start == "" && len(body) > 0 && len(execution.ExecutionSource) == 0 {
			execution.ExecutionArgument = string(body)
		}

		// FIXME - this should have "execution_argument" from executeWorkflow frontend
		//log.Printf("EXEC: %#v", execution)
		if len(execution.ExecutionArgument) > 0 {
			workflowExecution.ExecutionArgument = execution.ExecutionArgument
		}

		if len(execution.ExecutionSource) > 0 {
			workflowExecution.ExecutionSource = execution.ExecutionSource

			if workflowExecution.Priority == 0 {
				workflowExecution.Priority = 5
			}
		}

		//log.Printf("Execution data: %#v", execution)
		if len(execution.Start) == 36 && len(workflow.Actions) > 0 {
			log.Printf("[INFO] Should start execution on node %s", execution.Start)
			workflowExecution.Start = execution.Start

			found := false
			newStartnode := ""
			for _, action := range workflow.Actions {
				if action.ID == execution.Start {
					found = true
					break
				}

				if action.IsStartNode {
					newStartnode = action.ID
				}
			}

			if !found {
				if len(newStartnode) > 0 {
					execution.Start = newStartnode
				} else {
					log.Printf("[ERROR] Action %s was NOT found, and no other startnode found! Exiting execution.", execution.Start)
					return WorkflowExecution{}, ExecInfo{}, fmt.Sprintf("Startnode %s was not found in actions", workflow.Start), errors.New(fmt.Sprintf("Startnode %s was not found in actions", workflow.Start))
				}
			}
		} else if len(execution.Start) > 0 {
			//return WorkflowExecution{}, fmt.Sprintf("Startnode %s was not found in actions", execution.Start), errors.New(fmt.Sprintf("Startnode %s was not found in actions", execution.Start))
		}

		if len(execution.ExecutionId) == 36 {
			workflowExecution.ExecutionId = execution.ExecutionId
		} else {
			sessionToken := uuid.NewV4()
			workflowExecution.ExecutionId = sessionToken.String()
		}
	} else {
		// Check for parameters of start and ExecutionId
		// This is mostly used for user input trigger

		answer, answerok := request.URL.Query()["answer"]
		referenceId, referenceok := request.URL.Query()["reference_execution"]
		if answerok && referenceok {
			// If answer is false, reference execution with result
			//log.Printf("[INFO] Answer is OK AND reference is OK!")
			if answer[0] == "false" {
				log.Printf("Should update reference and return, no need for further execution!")

				// Get the reference execution
				oldExecution, err := GetWorkflowExecution(ctx, referenceId[0])
				if err != nil {
					log.Printf("Failed getting execution (execution) %s: %s", referenceId[0], err)
					return WorkflowExecution{}, ExecInfo{}, fmt.Sprintf("Failed getting execution ID %s because it doesn't exist.", referenceId[0]), err
				}

				if oldExecution.Workflow.ID != workflow.ID {
					log.Println("Wrong workflowid!")
					return WorkflowExecution{}, ExecInfo{}, fmt.Sprintf("Bad ID %s", referenceId), errors.New("Bad ID")
				}

				newResults := []ActionResult{}
				//log.Printf("%#v", oldExecution.Results)
				for _, result := range oldExecution.Results {
					log.Printf("%s - %s", result.Action.ID, start[0])
					if result.Action.ID == start[0] {
						note, noteok := request.URL.Query()["note"]
						if noteok {
							result.Result = fmt.Sprintf("User note: %s", note[0])
						} else {
							result.Result = fmt.Sprintf("User clicked %s", answer[0])
						}

						// Stopping the whole thing
						result.CompletedAt = int64(time.Now().Unix())
						result.Status = "ABORTED"
						oldExecution.Status = result.Status
						oldExecution.Result = result.Result
						oldExecution.LastNode = result.Action.ID
					}

					newResults = append(newResults, result)
				}

				oldExecution.Results = newResults
				err = SetWorkflowExecution(ctx, *oldExecution, true)
				if err != nil {
					log.Printf("Error saving workflow execution actionresult setting: %s", err)
					return WorkflowExecution{}, ExecInfo{}, fmt.Sprintf("Failed setting workflowexecution actionresult in execution: %s", err), err
				}

				return WorkflowExecution{}, ExecInfo{}, "", nil
			}
		}

		if referenceok {
			log.Printf("[DEBUG] Handling an old execution continuation! Start: %#v", start)

			// Will use the old name, but still continue with NEW ID
			oldExecution, err := GetWorkflowExecution(ctx, referenceId[0])
			if err != nil {
				log.Printf("Failed getting execution (execution) %s: %s", referenceId[0], err)
				return WorkflowExecution{}, ExecInfo{}, fmt.Sprintf("Failed getting execution ID %s because it doesn't exist.", referenceId[0]), err
			}

			if oldExecution.Status != "WAITING" {
				return WorkflowExecution{}, ExecInfo{}, "", errors.New("Workflow is no longer with status waiting. Can't continue.")
			}

			if startok {
				for _, result := range oldExecution.Results {
					if result.Action.ID == start[0] {
						if result.Status == "SUCCESS" || result.Status == "FINISHED" {
							// Disabling this to allow multiple continuations
							//return WorkflowExecution{}, ExecInfo{}, "", errors.New("This workflow has already been continued")
						}
						//log.Printf("Start: %#v", result.Status)
					}
				}
			}

			workflowExecution = *oldExecution

			// A previously stopped workflow. Same priority as subflow.
			workflowExecution.Priority = 9
		}

		if len(workflowExecution.ExecutionId) == 0 {
			sessionToken := uuid.NewV4()
			workflowExecution.ExecutionId = sessionToken.String()
		} else {
			log.Printf("[DEBUG] Using the same executionId as before: %s", workflowExecution.ExecutionId)
			makeNew = false
		}

		// Don't override workflow defaults
	}

	if workflowExecution.SubExecutionCount == 0 {
		workflowExecution.SubExecutionCount = 1
	}

	//log.Printf("\n\nExecution count: %d", workflowExecution.SubExecutionCount)
	if workflowExecution.SubExecutionCount >= maxExecutionDepth {
		return WorkflowExecution{}, ExecInfo{}, fmt.Sprintf("Max subflow of %d reached"), err
	}

	if workflowExecution.Priority == 0 {
		//log.Printf("\n\n[DEBUG] Set priority to 10 as it's manual?\n\n")
		workflowExecution.Priority = 10
	}

	if startok {
		//log.Printf("\n\n[INFO] Setting start to %s based on query!\n\n", start[0])
		//workflowExecution.Workflow.Start = start[0]
		workflowExecution.Start = start[0]
	}

	// FIXME - regex uuid, and check if already exists?
	if len(workflowExecution.ExecutionId) != 36 {
		log.Printf("Invalid uuid: %s", workflowExecution.ExecutionId)
		return WorkflowExecution{}, ExecInfo{}, "Invalid uuid", err
	}

	// FIXME - find owner of workflow
	// FIXME - get the actual workflow itself and build the request
	// MAYBE: Don't send the workflow within the pubsub, as this requires more data to be sent
	// Check if a worker already exists for company, else run one with:
	// locations, project IDs and subscription names

	// When app is executed:
	// Should update with status execution (somewhere), which will trigger the next node
	// IF action.type == internal, we need the internal watcher to be running and executing
	// This essentially means the WORKER has to be the responsible party for new actions in the INTERNAL landscape
	// Results are ALWAYS posted back to cloud@execution_id?
	if makeNew {
		workflowExecution.Type = "workflow"
		//workflowExecution.Stream = "tmp"
		//workflowExecution.WorkflowQueue = "tmp"
		//workflowExecution.SubscriptionNameNodestream = "testcompany-nodestream"
		//workflowExecution.Locations = []string{"europe-west2"}
		//workflowExecution.ProjectId = gceProject
		workflowExecution.WorkflowId = workflow.ID
		workflowExecution.StartedAt = int64(time.Now().Unix())
		workflowExecution.CompletedAt = 0
		workflowExecution.Authorization = uuid.NewV4().String()

		// Status for the entire workflow.
		workflowExecution.Status = "EXECUTING"
	}

	if len(workflowExecution.ExecutionSource) == 0 {
		log.Printf("[INFO] No execution source (trigger) specified. Setting to default")
		workflowExecution.ExecutionSource = "default"
	} else {
		log.Printf("[INFO] Execution source is %s for execution ID %s in workflow %s", workflowExecution.ExecutionSource, workflowExecution.ExecutionId, workflowExecution.Workflow.ID)
	}

	workflowExecution.ExecutionVariables = workflow.ExecutionVariables
	if len(workflowExecution.Start) == 0 && len(workflowExecution.Workflow.Start) > 0 {
		workflowExecution.Start = workflowExecution.Workflow.Start
	}

	startnodeFound := false
	newStartnode := ""
	for _, item := range workflowExecution.Workflow.Actions {
		if item.ID == workflowExecution.Start {
			startnodeFound = true
		}

		if item.IsStartNode {
			newStartnode = item.ID
		}
	}

	if !startnodeFound {
		log.Printf("[WARNING] Couldn't find startnode %#v among %d actions. Remapping to %#v", workflowExecution.Start, len(workflowExecution.Workflow.Actions), newStartnode)

		if len(newStartnode) > 0 {
			workflowExecution.Start = newStartnode
		} else {
			return WorkflowExecution{}, ExecInfo{}, fmt.Sprintf("Startnode couldn't be found"), errors.New("Startnode isn't defined in this workflow..")
		}
	}

	childNodes := FindChildNodes(workflowExecution, workflowExecution.Start)

	//topic := "workflows"
	startFound := false
	// FIXME - remove this?
	newActions := []Action{}
	defaultResults := []ActionResult{}

	if project.Environment == "cloud" {
		//apps, err := GetPrioritizedApps(ctx, user)
		//if err != nil {
		//	log.Printf("[WARNING] Error: Failed getting apps during setup: %s", err)
		//}
	}

	allAuths := []AppAuthenticationStorage{}
	for _, action := range workflowExecution.Workflow.Actions {
		//action.LargeImage = ""
		if action.ID == workflowExecution.Start {
			startFound = true
		}

		// Fill in apikey?
		if project.Environment == "cloud" {

			if (action.AppName == "Shuffle Tools" || action.AppName == "email") && action.Name == "send_email_shuffle" || action.Name == "send_sms_shuffle" {
				for paramKey, param := range action.Parameters {
					// Autoreplace in general, even if there is a key. Overwrite previous configs to ensure this becomes the norm. Frontend also matches.
					if param.Name == "apikey" {
						//log.Printf("Autoreplacing apikey")

						// This will be in cache after running once or twice AKA fast
						org, err := GetOrg(ctx, workflowExecution.Workflow.OrgId)
						if err != nil {
							log.Printf("[ERROR] Error getting org in APIkey replacement: %s", err)
							continue
						}

						// Make sure to find one that's belonging to the org
						// Picking random last user if

						backupApikey := ""
						for _, user := range org.Users {
							if len(user.ApiKey) == 0 {
								continue
							}

							if user.Role != "org-reader" {
								backupApikey = user.ApiKey
							}

							if len(user.Orgs) == 1 || user.ActiveOrg.Id == workflowExecution.Workflow.OrgId {
								//log.Printf("Choice: %s, %#v - %s", user.Username, user.Id, user.ApiKey)
								action.Parameters[paramKey].Value = user.ApiKey
								break
							}
						}

						if len(action.Parameters[paramKey].Value) == 0 {
							log.Printf("[WARNING] No apikey user found. Picking first random user")
							action.Parameters[paramKey].Value = backupApikey
						}

						break
					}
				}
			}
		}

		if action.Environment == "" {
			return WorkflowExecution{}, ExecInfo{}, fmt.Sprintf("Environment is not defined for %s", action.Name), errors.New("Environment not defined!")
		}

		// FIXME: Authentication parameters
		if len(action.AuthenticationId) > 0 {
			if len(allAuths) == 0 {
				allAuths, err = GetAllWorkflowAppAuth(ctx, workflow.ExecutingOrg.Id)
				if err != nil {
					log.Printf("Api authentication failed in get all app auth: %s", err)
					return WorkflowExecution{}, ExecInfo{}, fmt.Sprintf("Api authentication failed in get all app auth: %s", err), err
				}
			}

			curAuth := AppAuthenticationStorage{Id: ""}
			authIndex := -1
			for innerIndex, auth := range allAuths {
				if auth.Id == action.AuthenticationId {
					authIndex = innerIndex
					curAuth = auth
					break
				}
			}

			if len(curAuth.Id) == 0 {
				return WorkflowExecution{}, ExecInfo{}, fmt.Sprintf("Auth ID %s doesn't exist", action.AuthenticationId), errors.New(fmt.Sprintf("Auth ID %s doesn't exist", action.AuthenticationId))
			}

			if curAuth.Encrypted {
				setField := true
				newFields := []AuthenticationStore{}
				for _, field := range curAuth.Fields {
					parsedKey := fmt.Sprintf("%s_%d_%s_%s", curAuth.OrgId, curAuth.Created, curAuth.Label, field.Key)
					newValue, err := HandleKeyDecryption([]byte(field.Value), parsedKey)
					if err != nil {
						log.Printf("[ERROR] Failed decryption for %s: %s", field.Key, err)
						setField = false
						break
					}

					// Remove / at end of urls
					// TYPICALLY shouldn't use them.
					if field.Key == "url" {
						//log.Printf("Value2 (%s): %s", field.Key, string(newValue))
						if strings.HasSuffix(string(newValue), "/") {
							newValue = []byte(string(newValue)[0 : len(newValue)-1])
						}

						//log.Printf("Value2 (%s): %s", field.Key, string(newValue))
					}

					field.Value = string(newValue)
					newFields = append(newFields, field)
				}

				if setField {
					curAuth.Fields = newFields
				}
			} else {
				//log.Printf("[INFO] AUTH IS NOT ENCRYPTED - attempting auto-encrypting if key is set!")
				err = SetWorkflowAppAuthDatastore(ctx, curAuth, curAuth.Id)
				if err != nil {
					log.Printf("[WARNING] Failed running encryption during execution: %s", err)
				}
			}

			newParams := []WorkflowAppActionParameter{}
			if strings.ToLower(curAuth.Type) == "oauth2" {
				//log.Printf("[DEBUG] Should replace auth parameters (Oauth2)")

				runRefresh := false
				refreshUrl := ""
				for _, param := range curAuth.Fields {
					if param.Key == "expiration" {
						val, err := strconv.Atoi(param.Value)
						timeNow := int64(time.Now().Unix())
						if err == nil {
							//log.Printf("Checking expiration vs timenow: %d %d. Err: %s", timeNow, int64(val)+120, err)
							if timeNow >= int64(val)+120 {
								log.Printf("[DEBUG] Should run refresh of Oauth2 for %s!!", curAuth.Id)
								runRefresh = true
							}

						}

						continue
					}

					if param.Key == "refresh_url" {
						refreshUrl = param.Value
						continue
					}

					if param.Key != "url" && param.Key != "access_token" {
						//log.Printf("Skipping key %s", param.Key)
						continue
					}

					newParams = append(newParams, WorkflowAppActionParameter{
						Name:  param.Key,
						Value: param.Value,
					})
				}

				runRefresh = true
				if runRefresh {
					user := User{
						Username: "refresh",
						ActiveOrg: OrgMini{
							Id: curAuth.OrgId,
						},
					}

					if len(refreshUrl) == 0 {
						log.Printf("[ERROR] No Oauth2 request to run, as no refresh url is set!")
					} else {
						log.Printf("[INFO] Running Oauth2 request with URL %s", refreshUrl)

						newAuth, err := RunOauth2Request(ctx, user, curAuth, true)
						if err != nil {
							log.Printf("[ERROR] Failed running oauth request to refresh oauth2 tokens: %s", err)
						} else {
							log.Printf("[DEBUG] Setting new auth to index: %d and curauth", authIndex)
							allAuths[authIndex] = newAuth

							// Does the oauth2 replacement
							newParams = []WorkflowAppActionParameter{}
							for _, param := range newAuth.Fields {
								//log.Printf("FIELD: %s", param.Key, param.Value)
								if param.Key != "url" && param.Key != "access_token" {
									//log.Printf("Skipping key %s (2)", param.Key)
									continue
								}

								newParams = append(newParams, WorkflowAppActionParameter{
									Name:  param.Key,
									Value: param.Value,
								})
							}
						}
					}
				}

				for _, param := range action.Parameters {
					//log.Printf("Param: %#v", param)
					if param.Configuration {
						continue
					}

					newParams = append(newParams, param)
				}
			} else {
				// Rebuild params with the right data. This is to prevent issues on the frontend
				for _, param := range action.Parameters {

					for _, authparam := range curAuth.Fields {
						if param.Name == authparam.Key {
							param.Value = authparam.Value
							//log.Printf("Name: %s - value: %s", param.Name, param.Value)
							//log.Printf("Name: %s - value: %s\n", param.Name, param.Value)
							break
						}
					}

					newParams = append(newParams, param)
				}
			}

			action.Parameters = newParams
		}

		action.LargeImage = ""
		if len(action.Label) == 0 {
			action.Label = action.ID
		}
		//log.Printf("LABEL: %s", action.Label)
		newActions = append(newActions, action)

		// If the node is NOT found, it's supposed to be set to SKIPPED,
		// as it's not a childnode of the startnode
		// This is a configuration item for the workflow itself.
		if len(workflowExecution.Results) > 0 {
			extra := 0
			for _, trigger := range workflowExecution.Workflow.Triggers {
				//log.Printf("Appname trigger (0): %s", trigger.AppName)
				if trigger.AppName == "User Input" || trigger.AppName == "Shuffle Workflow" {
					extra += 1
				}
			}

			defaultResults = []ActionResult{}
			for _, result := range workflowExecution.Results {
				if result.Status == "WAITING" {
					result.Status = "SUCCESS"
					result.Result = `{"success": true, "reason": "Continuing from user input"}`

					log.Printf("Actions + extra = %d. Results = %d", len(workflowExecution.Workflow.Actions)+extra, len(workflowExecution.Results))
					if len(workflowExecution.Results) >= len(workflowExecution.Workflow.Actions)+extra {
						workflowExecution.Status = "FINISHED"
					} else {
						workflowExecution.Status = "EXECUTING"
					}
				}

				defaultResults = append(defaultResults, result)
			}
		} else if len(workflowExecution.Results) == 0 && !workflowExecution.Workflow.Configuration.StartFromTop {
			found := false
			for _, nodeId := range childNodes {
				if nodeId == action.ID {
					//log.Printf("Found %s", action.ID)
					found = true
				}
			}

			if !found {
				if action.ID == workflowExecution.Start {
					continue
				}

				//log.Printf("[WARNING] Set %s to SKIPPED as it's NOT a childnode of the startnode.", action.ID)
				curaction := Action{
					AppName:    action.AppName,
					AppVersion: action.AppVersion,
					Label:      action.Label,
					Name:       action.Name,
					ID:         action.ID,
				}
				//action
				//curaction.Parameters = []
				defaultResults = append(defaultResults, ActionResult{
					Action:        curaction,
					ExecutionId:   workflowExecution.ExecutionId,
					Authorization: workflowExecution.Authorization,
					Result:        `{"success": false, "reason": "Skipped because it's not under the startnode (1)"}`,
					StartedAt:     0,
					CompletedAt:   0,
					Status:        "SKIPPED",
				})
			}
		}
	}

	// Added fixes for e.g. URL's ending in /
	fixes := []string{"url"}
	for actionIndex, action := range workflowExecution.Workflow.Actions {
		if strings.ToLower(action.AppName) == "http" {
			continue
		}

		for paramIndex, param := range action.Parameters {
			if !param.Configuration {
				continue
			}

			if ArrayContains(fixes, strings.ToLower(param.Name)) {
				if strings.HasSuffix(param.Value, "/") {
					workflowExecution.Workflow.Actions[actionIndex].Parameters[paramIndex].Value = param.Value[0 : len(param.Value)-1]
				}
			}
		}
	}

	// Not necessary with comments at all
	workflowExecution.Workflow.Comments = []Comment{}
	removeTriggers := []string{}
	for triggerIndex, trigger := range workflowExecution.Workflow.Triggers {
		//log.Printf("[INFO] ID: %s vs %s", trigger.ID, workflowExecution.Start)
		if trigger.ID == workflowExecution.Start {
			if trigger.AppName == "User Input" {
				startFound = true
				break
			}
		}

		if trigger.AppName == "User Input" || trigger.AppName == "Shuffle Workflow" {
			found := false
			for _, node := range childNodes {
				if node == trigger.ID {
					found = true
					break
				}
			}

			if !found {
				//log.Printf("SHOULD SET TRIGGER %s TO BE SKIPPED", trigger.ID)

				curaction := Action{
					AppName:    "shuffle-subflow",
					AppVersion: trigger.AppVersion,
					Label:      trigger.Label,
					Name:       trigger.Name,
					ID:         trigger.ID,
				}

				found := false
				for _, res := range defaultResults {
					if res.Action.ID == trigger.ID {
						found = true
						break
					}
				}

				if !found {
					defaultResults = append(defaultResults, ActionResult{
						Action:        curaction,
						ExecutionId:   workflowExecution.ExecutionId,
						Authorization: workflowExecution.Authorization,
						Result:        `{"success": false, "reason": "Skipped because it's not under the startnode (2)"}`,
						StartedAt:     0,
						CompletedAt:   0,
						Status:        "SKIPPED",
					})
				}
			} else {
				// Replaces trigger with the subflow
				//if trigger.AppName == "Shuffle Workflow" {
				//	replaceActions := false
				//	workflowAction := ""
				//	for _, param := range trigger.Parameters {
				//		if param.Name == "argument" && !strings.Contains(param.Value, ".#") {
				//			replaceActions = true
				//		}

				//		if param.Name == "startnode" {
				//			workflowAction = param.Value
				//		}
				//	}

				//	if replaceActions {
				//		replacementNodes, newBranches, lastnode := GetReplacementNodes(ctx, workflowExecution, trigger, trigger.Label)
				//		log.Printf("REPLACEMENTS: %d, %d", len(replacementNodes), len(newBranches))
				//		if len(replacementNodes) > 0 {
				//			for _, action := range replacementNodes {
				//				found := false

				//				for subActionIndex, subaction := range newActions {
				//					if subaction.ID == action.ID {
				//						found = true
				//						//newActions[subActionIndex].Name = action.Name
				//						newActions[subActionIndex].Label = action.Label
				//						break
				//					}
				//				}

				//				if !found {
				//					action.SubAction = true
				//					newActions = append(newActions, action)
				//				}

				//				// Check if it's already set to have a value
				//				for resultIndex, result := range defaultResults {
				//					if result.Action.ID == action.ID {
				//						defaultResults = append(defaultResults[:resultIndex], defaultResults[resultIndex+1:]...)
				//						break
				//					}
				//				}
				//			}

				//			for _, branch := range newBranches {
				//				workflowExecution.Workflow.Branches = append(workflowExecution.Workflow.Branches, branch)
				//			}

				//			// Append branches:
				//			// parent -> new inner node (FIRST one)
				//			for branchIndex, branch := range workflowExecution.Workflow.Branches {
				//				if branch.DestinationID == trigger.ID {
				//					log.Printf("REPLACE DESTINATION WITH %s!!", workflowAction)
				//					workflowExecution.Workflow.Branches[branchIndex].DestinationID = workflowAction
				//				}

				//				if branch.SourceID == trigger.ID {
				//					log.Printf("REPLACE SOURCE WITH LASTNODE %s!!", lastnode)
				//					workflowExecution.Workflow.Branches[branchIndex].SourceID = lastnode
				//				}
				//			}

				//			// Remove the trigger
				//			removeTriggers = append(removeTriggers, workflowExecution.Workflow.Triggers[triggerIndex].ID)
				//		}

				//		log.Printf("NEW ACTION LENGTH %d, RESULT: %d, Triggers: %d, BRANCHES: %d", len(newActions), len(defaultResults), len(workflowExecution.Workflow.Triggers), len(workflowExecution.Workflow.Branches))
				//	}
				//}
				_ = triggerIndex
			}
		}
	}

	//newTriggers := []Trigger{}
	//for _, trigger := range workflowExecution.Workflow.Triggers {
	//	found := false
	//	for _, triggerId := range removeTriggers {
	//		if trigger.ID == triggerId {
	//			found = true
	//			break
	//		}
	//	}

	//	if found {
	//		log.Printf("[WARNING] Removed trigger %s during execution", trigger.ID)
	//		continue
	//	}

	//	newTriggers = append(newTriggers, trigger)
	//}
	//workflowExecution.Workflow.Triggers = newTriggers
	_ = removeTriggers

	if !startFound {
		if len(workflowExecution.Start) == 0 && len(workflowExecution.Workflow.Start) > 0 {
			workflowExecution.Start = workflow.Start
		} else if len(workflowExecution.Workflow.Actions) > 0 {
			workflowExecution.Start = workflowExecution.Workflow.Actions[0].ID
		} else {
			log.Printf("[ERROR] Startnode %s doesn't exist!!", workflowExecution.Start)
			return WorkflowExecution{}, ExecInfo{}, fmt.Sprintf("Workflow action %s doesn't exist in workflow", workflowExecution.Start), errors.New(fmt.Sprintf(`Workflow start node "%s" doesn't exist. Exiting!`, workflowExecution.Start))
		}
	}

	//log.Printf("EXECUTION START: %s", workflowExecution.Start)

	// Verification for execution environments
	workflowExecution.Results = defaultResults
	workflowExecution.Workflow.Actions = newActions
	onpremExecution := true

	environments := []string{}
	if len(workflowExecution.ExecutionOrg) == 0 && len(workflow.ExecutingOrg.Id) > 0 {
		workflowExecution.ExecutionOrg = workflow.ExecutingOrg.Id
	}

	var allEnvs []Environment
	if len(workflowExecution.ExecutionOrg) > 0 {
		//log.Printf("[INFO] Executing ORG: %s", workflowExecution.ExecutionOrg)

		allEnvironments, err := GetEnvironments(ctx, workflowExecution.ExecutionOrg)
		if err != nil {
			log.Printf("Failed finding environments: %s", err)
			return WorkflowExecution{}, ExecInfo{}, fmt.Sprintf("Workflow environments not found for this org"), errors.New(fmt.Sprintf("Workflow environments not found for this org"))
		}

		for _, curenv := range allEnvironments {
			if curenv.Archived {
				continue
			}

			allEnvs = append(allEnvs, curenv)
		}
	} else {
		log.Printf("[ERROR] No org identified for execution of %s. Returning", workflowExecution.Workflow.ID)
		return WorkflowExecution{}, ExecInfo{}, "No org identified for execution", errors.New("No org identified for execution")
	}

	if len(allEnvs) == 0 {
		log.Printf("[ERROR] No active environments found for org: %s", workflowExecution.ExecutionOrg)
		return WorkflowExecution{}, ExecInfo{}, "No active environments found", errors.New(fmt.Sprintf("No active env found for org %s", workflowExecution.ExecutionOrg))
	}

	// Check if the actions are children of the startnode?
	imageNames := []string{}
	cloudExec := false
	for _, action := range workflowExecution.Workflow.Actions {

		// Verify if the action environment exists and append
		found := false
		for _, env := range allEnvs {
			if env.Name == action.Environment {
				found = true

				if env.Type == "cloud" {
					cloudExec = true
				} else if env.Type == "onprem" {
					onpremExecution = true
				} else {
					log.Printf("[ERROR] No handler for environment type %s", env.Type)
					return WorkflowExecution{}, ExecInfo{}, "No active environments found", errors.New(fmt.Sprintf("No handler for environment type %s", env.Type))
				}
				break
			}
		}

		if !found {
			if strings.ToLower(action.Environment) == "cloud" && project.Environment == "cloud" {
				log.Printf("[DEBUG] Couldn't find environment %s in cloud for some reason.", action.Environment)
			} else {
				log.Printf("[WARNING] Couldn't find environment %s. Maybe it's inactive?", action.Environment)
				return WorkflowExecution{}, ExecInfo{}, "Couldn't find the environment", errors.New(fmt.Sprintf("Couldn't find env %s in org %s", action.Environment, workflowExecution.ExecutionOrg))
			}
		}

		found = false
		for _, env := range environments {
			if env == action.Environment {
				found = true
				break
			}
		}

		// Check if the app exists?
		newName := action.AppName
		newName = strings.Replace(newName, " ", "-", -1)
		imageNames = append(imageNames, fmt.Sprintf("%s:%s_%s", baseDockerName, newName, action.AppVersion))

		if !found {
			environments = append(environments, action.Environment)
		}
	}

	//b, err := json.Marshal(workflowExecution)
	//if err == nil {
	//	log.Printf("LEN: %d", len(string(b)))
	//	//workflowExecution.ExecutionOrg.SyncFeatures = Org{}
	//}

	workflowExecution.Workflow.ExecutingOrg = OrgMini{
		Id: workflowExecution.Workflow.ExecutingOrg.Id,
	}
	workflowExecution.Workflow.Org = []OrgMini{
		workflowExecution.Workflow.ExecutingOrg,
	}

	// Means executing a subflow is happening
	if len(workflowExecution.ExecutionParent) > 0 {
		IncrementCache(ctx, workflowExecution.ExecutionOrg, "subflow_executions")
	}

	return workflowExecution, ExecInfo{OnpremExecution: onpremExecution, Environments: environments, CloudExec: cloudExec, ImageNames: imageNames}, "", nil
}


func GetBackendexecution(ctx context.Context, executionId, authorization string) (WorkflowExecution, error) {
	exec := WorkflowExecution{}
	resultUrl := fmt.Sprintf("%s/api/v1/streams/results", os.Getenv("BASE_URL"))

	topClient := &http.Client{
		Transport: &http.Transport{
			Proxy: nil,
		},
	}

	httpProxy := os.Getenv("HTTP_PROXY")
	httpsProxy := os.Getenv("HTTPS_PROXY")
	if len(httpProxy) > 0 || len(httpsProxy) > 0 {
		topClient = &http.Client{}
	} else {
		if len(httpProxy) > 0 {
			log.Printf("Running with HTTP proxy %s (env: HTTP_PROXY)", httpProxy)
		}
		if len(httpsProxy) > 0 {
			log.Printf("Running with HTTPS proxy %s (env: HTTPS_PROXY)", httpsProxy)
		}
	}

	requestData := ActionResult{
		ExecutionId:   executionId,
		Authorization: authorization,
	}

	data, err := json.Marshal(requestData)
	if err != nil {
		log.Printf("[WARNING] Failed parent init marshal: %s", err)
		return exec, err
	}

	req, err := http.NewRequest(
		"POST",
		resultUrl,
		bytes.NewBuffer([]byte(data)),
	)

	newresp, err := topClient.Do(req)
	if err != nil {
		log.Printf("[ERROR] Failed making subflow request (1): %s. Is URL valid: %s", err, resultUrl)
		return exec, err
	}

	body, err := ioutil.ReadAll(newresp.Body)
	if err != nil {
		log.Printf("[ERROR] Failed reading parent body: %s", err)
		return exec, err
	}
	//log.Printf("BODY (%d): %s", newresp.StatusCode, string(body))

	if newresp.StatusCode != 200 {
		log.Printf("[ERROR] Bad statuscode setting subresult with URL %s: %d, %s", resultUrl, newresp.StatusCode, string(body))
		return exec, errors.New(fmt.Sprintf("Bad statuscode: %s", newresp.StatusCode))
	}

	err = json.Unmarshal(body, &exec)
	if err != nil {
		log.Printf("[WARNING] Failed unmarshalling execution: %s", err)
		return exec, err
	}

	if exec.Status == "FINISHED" || exec.Status == "FAILURE" {
		cacheKey := fmt.Sprintf("workflowexecution-%s", executionId)
		err = SetCache(ctx, cacheKey, body)
		if err != nil {
			log.Printf("[WARNING] Failed setting cache for workflowexec key %s: %s", cacheKey, err)
		}
	}

	return exec, nil
}