package shuffle

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	uuid "github.com/satori/go.uuid"
)

// Pipeline is a sequence of stages that are executed in order.
// We will deploy the pipeline to run something from Orborus by adding it to the Orborus queue to be handled
func HandleNewPipelineRegister(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	// Removed check here as it may be a public workflow
	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[AUDIT] Api authentication failed in getting specific workflow: %s. Continuing because it may be public.", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if user.Role == "org-reader" {
		resp.WriteHeader(403)
		resp.Write([]byte(`{"success": false, "reason": "You do not have permission to register a new pipeline."}`))
		return
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Printf("[WARNING] Error with body read in new pipeline: %s", err)
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	var pipeline PipelineRequest
	err = json.Unmarshal(body, &pipeline)
	if err != nil {
		log.Printf("[WARNING] Failed new pipeline unmarshal: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	log.Printf("[AUDIT] User %s in org %s (%s) is creating a new pipeline with command '%s' in environment '%s'", user.Username, user.ActiveOrg.Name, user.ActiveOrg.Id, pipeline.Type, pipeline.Environment)

	if len(pipeline.Name) < 1 {
		log.Printf("[WARNING] Name is required for new pipelines")
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false, "reason": "Name is required"}`))
		return
	}

	if len(pipeline.Environment) < 1 {
		log.Printf("[WARNING] Environment is required for new pipelines")
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false, "reason": "Environment is required"}`))
		return
	}

	pipeline.Environment = strings.TrimSpace(pipeline.Environment)
	if strings.ToLower(pipeline.Environment) == "cloud" {
		log.Printf("[WARNING] Cloud is not a valid environment")
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false, "reason": "Cloud is not a valid environment. Choose one of your Organizations' environments."}`))
		return
	}

	ctx := GetContext(request)
	environments, err := GetEnvironments(ctx, user.ActiveOrg.Id)
	if err != nil {
		log.Printf("[WARNING] Error getting environments: %s", err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	envFound := false
	for _, env := range environments {
		if env.Name == pipeline.Environment {
			envFound = true
			break
		}
	}

	if !envFound {
		log.Printf("[WARNING] Environment '%s' is not available", pipeline.Environment)
		resp.WriteHeader(400)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Environment '%s' is not available. Please make it, or change the environment you want to deploy to."}`, pipeline.Environment)))
		return
	}

	availableCommands := []string{
		"create", "delete", "start", "stop",
	}

	matchingCommand := ""
	for _, command := range availableCommands {
		if strings.HasPrefix(strings.ToLower(pipeline.Type), command) {
			matchingCommand = command
			break
		}
	}

	if len(matchingCommand) == 0 {
		log.Printf("[WARNING] Command Type '%s' is not available for %s (%s)", pipeline.Type, user.ActiveOrg.Name, user.ActiveOrg.Id)
		resp.WriteHeader(400)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Command type '%s' is not available"}`, pipeline.Type)))
		return
	}

	// 1. Add to trigger list
	/* TBD */

	// Look for PIPELINE_ command that exists in the queue already
	startCommand := strings.ToUpper(strings.Split(pipeline.Type, " ")[0])
	//parsedId := fmt.Sprintf("%s_%s", strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(pipeline.Environment, " ", "-"), "_", "-")), user.ActiveOrg.Id)
	parsedId := strings.ToLower(pipeline.Environment)
	formattedType := fmt.Sprintf("PIPELINE_%s", startCommand)
	existingQueue, err := GetWorkflowQueue(ctx, parsedId, 10)
	for _, queue := range existingQueue.Data {
		if strings.HasPrefix(queue.Type, "PIPELINE") {
			log.Printf("[WARNING] Pipeline type already exists: %s", formattedType)
			resp.WriteHeader(400)
			resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": "Pipeline type already exists. Please wait for existing Pipeline request to be fullfilled by Orborus (could take a few seconds)."}`)))
			return
		}
	}

	log.Printf("[INFO] Pipeline type: %s", formattedType)

	// 2. Send to environment queue
	execRequest := ExecutionRequest{
		Type:              formattedType,
		ExecutionId:       uuid.NewV4().String(),
		ExecutionSource:   pipeline.TriggerId,
		ExecutionArgument: pipeline.Command,
		Priority:          11,
	}

	if startCommand == "CREATE" {

		pipelineData := Pipeline{}
		pipelineData.Name = pipeline.Name
		pipelineData.Type = startCommand
		pipelineData.Command = pipeline.Command
		pipelineData.Environment = pipeline.Environment
		pipelineData.WorkflowId = pipeline.WorkflowId
		pipelineData.OrgId = user.ActiveOrg.Id
		pipelineData.Status = "uninitialized"
		pipelineData.TriggerId = pipeline.TriggerId

		err = savePipelineData(ctx, pipelineData)
		if err != nil {
			log.Printf("[ERROR] Failed to save the pipeline with trigger id: %s into the db: %s", pipeline.TriggerId, err)
			resp.WriteHeader(500)
			resp.Write([]byte(`{"success": false}`))
			return
		}
		log.Printf("[INFO] Successfully saved the pipeline info")
	}

	err = SetWorkflowQueue(ctx, execRequest, parsedId)
	if err != nil {
		log.Printf("[ERROR] Failed setting workflow queue for env: %s", err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	resp.WriteHeader(200)
	resp.Write([]byte(fmt.Sprintf(`{"success": true, "reason": "Pipeline will be created"}`)))
}
