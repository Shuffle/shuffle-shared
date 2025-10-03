package shuffle

import (
	"encoding/json"
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	
	"github.com/google/uuid"
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
		pipeline.Name = pipeline.Command

		/*
		log.Printf("[WARNING] Name is required for new pipelines")
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false, "reason": "Name is required"}`))
		return
		*/
	}

	ctx := GetContext(request)
	environments, err := GetEnvironments(ctx, user.ActiveOrg.Id)
	if err != nil {
		log.Printf("[WARNING] Error getting environments: %s", err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	if len(pipeline.Environment) < 1 {
		for _, env := range environments {
			if env.Archived {
				continue
			}

			if strings.ToLower(env.Type) == "cloud" {
				continue
			}

			pipeline.Environment = env.Name
			if env.DataLake.Enabled {
				break
			}
		}

		if len(pipeline.Environment) < 1 {
			log.Printf("[WARNING] Environment is required for new pipelines")
			resp.WriteHeader(400)
			resp.Write([]byte(`{"success": false, "reason": "No environment found"}`))
			return
		}
	}

	pipeline.Environment = strings.TrimSpace(pipeline.Environment)
	if strings.ToLower(pipeline.Environment) == "cloud" {
		log.Printf("[WARNING] Cloud is not a valid environment")
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false, "reason": "Cloud is not a valid environment. Choose one of your Organizations' environments."}`))
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
		"create", "start", "stop", "delete", 
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

	if len(pipeline.ID) == 0 && len(pipeline.TriggerId) > 0 {
		pipeline.ID = pipeline.TriggerId
	}

	//check if this is the first time creating the pipeline
	//pipelineInfo, err := GetPipeline(ctx, pipeline.TriggerId)
	pipelineInfo, err := GetPipeline(ctx, pipeline.ID)
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

	if len(pipelineInfo.ID) == 0 && len(pipeline.ID) > 0 {
		pipelineInfo = &Pipeline{
			ID: pipeline.ID,
			Name: pipeline.Name,
			Type: pipeline.Type,
			OrgId: user.ActiveOrg.Id,
			Command: pipeline.Command,
			Environment: pipeline.Environment,

			PipelineId: pipeline.PipelineId,
		}
	}

	if len(pipelineInfo.PipelineId) == 0 && len(pipelineInfo.ID) > 0 {
		pipelineInfo.PipelineId = pipelineInfo.ID
	}

	//parsedId := fmt.Sprintf("%s_%s", strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(pipeline.Environment, " ", "-"), "_", "-")), user.ActiveOrg.Id)
	parsedEnv := fmt.Sprintf("%s_%s", strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(pipeline.Environment, " ", "-"), "_", "-")), user.ActiveOrg.Id)
	if project.Environment != "cloud" {
		parsedEnv = strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(pipeline.Environment, " ", "-"), "_", "-"))
	}

	formattedType := fmt.Sprintf("PIPELINE_%s", startCommand)
	existingQueue, _ := GetWorkflowQueue(ctx, parsedEnv, 10)
	for _, queue := range existingQueue.Data {
		if strings.HasPrefix(queue.Type, "PIPELINE") {
			//log.Printf("[WARNING] Pipeline type already exists: %s", formattedType)
			//resp.WriteHeader(400)
			//resp.Write([]byte(`{"success": false, "reason": "Pipeline type already exists. Please wait for existing Pipeline request to be fullfilled by Orborus (could take a few seconds)."}`))
			//return
		}
	}

	if len(pipeline.TriggerId) < 1 {
		pipeline.TriggerId = uuid.New().String()
	}

	// 2. Send to environment queue
	execRequest := ExecutionRequest{
		Type:              formattedType,
		ExecutionId:       pipeline.ID,
		ExecutionSource:   pipeline.Name,
		ExecutionArgument: pipeline.Command,
		Priority:          11,
	}

	//log.Printf("EXECREQUEST: Type: %s, Source: %s, Argument: %s", execRequest.Type, execRequest.ExecutionSource, execRequest.ExecutionArgument)

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
		err = savePipelineData(ctx, *pipelineInfo)
		if err != nil {
			log.Printf("[ERROR] Failed to stop the pipeline with trigger id: %s, reason: %s", pipelineInfo.TriggerId, err)
			resp.WriteHeader(500)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		log.Printf("[INFO] Successfully sent stop request for the pipeline '%s' in environment '%s'. This does NOT mean that it will disappear right away. Check Orborus logs for more details.", pipelineInfo.ID, pipelineInfo.Environment)
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
		pipelineData.Url = pipeline.Url

		err = savePipelineData(ctx, pipelineData)
		if err != nil {
			log.Printf("[ERROR] Failed to create the pipeline with trigger id: %s, reason: %s", pipeline.TriggerId, err)
			resp.WriteHeader(500)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		log.Printf("[INFO] Set up pipeline '%s' with trigger ID '%s' and environment '%s'", pipeline.Command, pipeline.TriggerId, pipeline.Environment)
	}

	err = SetWorkflowQueue(ctx, execRequest, parsedEnv)
	if err != nil {
		log.Printf("[ERROR] Failed setting workflow queue for env: %s", err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	resp.WriteHeader(200)
	resp.Write([]byte(fmt.Sprintf(`{"success": true, "reason": "Pipeline queued to be deployed in environment '%s'."}`, pipeline.Environment)))
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
		log.Printf("[WARNING] Error deleting pipeline %s, reason: %s", pipeline.TriggerId, err)
		return err
	}

	log.Printf("[INFO] Successfully deleted pipeline %s", pipeline.TriggerId)
	return nil
}
