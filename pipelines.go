package shuffle

import (
	"encoding/json"
	"errors"
	"context"
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

	if !envFound && pipeline.Type != "delete"{
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

	// Look for PIPELINE_ command that exists in the queue already
	startCommand := strings.ToUpper(strings.Split(pipeline.Type, " ")[0])

	//check if this is the first time creating the pipeline
	pipelineInfo, err := GetPipeline(ctx, pipeline.TriggerId)
	if err != nil {
		if (startCommand == "DELETE" || startCommand == "STOP") && err.Error() == "pipeline doesn't exist" {
			log.Printf("[WARNING] Failed getting pipeline %s, reason: %s", pipeline.TriggerId, err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		} else if startCommand == "START" && err.Error() == "pipeline doesn't exist" {
			startCommand = "CREATE"
		}
	} else if startCommand == "CREATE" {
		startCommand = "START"
	}

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

	pipelineData := Pipeline{}

	if startCommand == "DELETE" {

		err := deletePipeline(ctx, *pipelineInfo)
		if err != nil {
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Failed deleting the pipeline."}`))
			return
		}

	} else if startCommand == "STOP" {

		pipelineInfo.Status = "stopped"
		err = setPipelineTrigger(ctx, *pipelineInfo)
		if err != nil {
			log.Printf("[ERROR] Failed to stop the pipeline with trigger id: %s, reason: %s", pipelineInfo.TriggerId, err)
			resp.WriteHeader(500)
			resp.Write([]byte(`{"success": false}`))
			return
		}
		log.Printf("[INFO] Stopped the pipeline %s sucessfully", pipelineInfo.TriggerId)
	} else {

		pipelineData.Name = pipeline.Name
		pipelineData.Type = startCommand
		pipelineData.Command = pipeline.Command
		pipelineData.Environment = pipeline.Environment
		pipelineData.WorkflowId = pipeline.WorkflowId
		pipelineData.OrgId = user.ActiveOrg.Id
		pipelineData.Owner = user.Id
		pipelineData.Status = "running"
		pipelineData.TriggerId = pipeline.TriggerId
		pipelineData.StartNode = pipeline.StartNode

		err = setPipelineTrigger(ctx, pipelineData)
		if err != nil {
			log.Printf("[ERROR] Failed to create the pipeline with trigger id: %s, reason: %s", pipeline.TriggerId, err)
			resp.WriteHeader(500)
			resp.Write([]byte(`{"success": false}`))
			return
		}
		log.Printf("[INFO] Set up pipeline with trigger ID %s and environment %s", pipeline.TriggerId, pipeline.Environment)
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


func setPipelineTrigger(ctx context.Context, pipeline Pipeline) error{

	input := pipeline.Command
	index := strings.Index(input, "to ")

	if index == -1 {
		return errors.New("url not found")
	}
	extractedURL := input[index+len("to "):]
	extractedURL = strings.TrimSpace(extractedURL)

	pipeline.Url =  extractedURL
	err := savePipelineData(ctx, pipeline)

	if err != nil  {
		return err
	}

   return nil
}

func deletePipeline(ctx context.Context, pipeline Pipeline) error {

	pipeline.Status = "stopped"
	err := savePipelineData(ctx, pipeline)
	if err != nil {
		log.Printf("[WARNING] Failed saving pipeline: %s", err)
		return err
	}

	err = DeleteKey(ctx, "pipelines", pipeline.TriggerId)
	if err != nil {
		log.Printf("[WARNING] Error deleting pipeline %s, reason: %s", pipeline.TriggerId)
		return err
	}

	log.Printf("[INFO] Successfully deleted pipeline %s", pipeline.TriggerId)
	return nil
}