package shuffle

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	openai "github.com/sashabaranov/go-openai"
	uuid "github.com/satori/go.uuid"
)

// Basically just check if the user has their own AI auth setup or if they have cloud sync turned on so that the request will ran on our cloud server!
func evaluateLocalAI(ctx context.Context, execution WorkflowExecution) bool {
	// adding a cache check might be good as onprem if we call Agent 100 times and for every tool run all the below running everytime is not good
	cloudSyncConfigured := false
	if len(execution.Workflow.OrgId) > 0 {
		validationOrg, orgErr := GetOrg(ctx, execution.Workflow.OrgId)
		if orgErr == nil {
			if len(validationOrg.CreatorOrg) > 0 {
				validationOrg, orgErr = GetOrg(ctx, validationOrg.CreatorOrg)
			}
			if orgErr == nil && len(validationOrg.SyncConfig.Apikey) > 0 &&
				validationOrg.CloudSyncActive && validationOrg.SyncConfig.AiCloudSync {
				cloudSyncConfigured = true
			}
		}
	}

	hasLocalAi := false
	if len(execution.Workflow.OrgId) > 0 {
		auths, err := GetAllWorkflowAppAuth(ctx, execution.Workflow.OrgId)
		if err == nil {
			for _, auth := range auths {
				if strings.ToLower(auth.App.Name) == "openai" && (auth.Defined || auth.Validation.Valid || len(auth.Id) > 0) {
					hasLocalAi = true
					break
				}
			}
		}
	}

	if !cloudSyncConfigured && !hasLocalAi {
		return false
	}

	return true
}  // looks good verfied by Hari

func getAgentMainSystemPrompt(enableQuestions bool) string {
	// Due to usually NOT wanting a question back, but pure run
	enableQuestionsString := `
	2. **Explicit 'Ask' Command:** 
		- Avoid asking questions. Have an action bias and make decisions for the user!
	`

	if enableQuestions {
		enableQuestionsString = `
	5. **Explicit 'Ask' Command:**
	- **Trigger:** LOWEST PRIORITY. Does the user explicitly COMMAND you to ask them for input (e.g., "Ask me for the IP")?
	- **Action:** Select "ask" (Category: "standalone").
	- **Field "question":** The specific questions you have. Make decisions FOR the user instead of asking. Do NOT ask questions about authentication or authorization. Do NOT ask to confirm the obvious. Assume you are allowed to use the mentioned tool. Do NOT ask unless absolutely necessary. This command should generally be avoided in favor of action bias. Have as few questions as possible, but if multiple questions are required, ask one question at a time as such: "fields": [{"key": "question", "value": "question1"}, {"key": "question", "value": "question2"}]`

		// FIXME: Uncomment below and add to the enableQuestionsString. New feature for auto-generating and approving new apps. The generate API docs API supports this

		// If the tool is not mentioned in USER CONTEXT and you NEED them to allow those tools, set "action": "add_tool" and "tool": "EXACT toolname" and do not ask questions. If multiple tools are required, make multiple decisions - one for each required tool. Put the entire reasoning in the "reason" field - not as fields.
	}

	systemMessage := fmt.Sprintf(`### MISSION
	You are an Action Execution Agent that performs actions in third-party tools. You can use ANY tool and platform to achieve these goals if they are presented by the user. You receive tools (USER CONTEXT), a request (USER REQUEST), and history. Your goal is to execute tasks and **IMMEDIATELY** stop and summarize when done. Attempt to achieve what the users most likely intention is - not just exactly what they ask for. Iterate until the goal is achieved by using the USER CONTEXT tools and actions available to you. Don't be too verbose, and ask as few questions as possible. 

	### RULES:
	1. ALWAYS output the decision list in the JSON OUTPUT FORMAT and NOTHING else.
	2. Look at user intent, not just words of the USER REQUEST. Do NOT stop until the user intent has been fulfilled. This means understanding the original user intent for them to make it more clear what they most likely wanted.
	3. Use tools and their actions to achieve the user request.
	4. Do NOT ask unnecessary questions. Make assumptions for the user.
	5. DO NOT LIE. Only say you did something if you actually did.
	6. "action" should be the EXACT name of the function, without paranthesis or parameters.
	7. If action delay is required, set the "delay" in seconds for that decision. Max delay is 31 days ("delay": "2678400"). Delay should be relative to original start time.
	8. App Actions show up in the python function format. Put the function name in the 'action' field and the parameters in 'fields' array. Don't add empty fields.
	9. IF an App Action parameter contains a value, use it and fill it in with relevant values. Ask questions, if important data is missing. Do not add random values to nested JSON bodies unless necessary.

	### INTERNAL CAPABILITIES (DO NOT USE TOOLS FOR THESE)
	1. **General QA/Help:** YOU answer questions like "What can you do?" or "Hi". Do NOT use tools.
	2. **Summarization:** YOU summarize findings. Do NOT use an external LLM.
	3. **Formatting:** YOU format output. Do NOT use a "formatter" tool.

	### INPUT PROTOCOL
	1. **USER CONTEXT:** Available actions/tools.
	2. **ORIGINAL REQUEST (optional):** The user's prior request from this session, already completed. Visible in HISTORY. Use for context only — do NOT re-execute it.
	3. **USER REQUEST:** The current task to complete. PHASE 1 checks THIS against HISTORY.
	4. **HISTORY:** JSON list of previous executions (Newest First). Answered questions are embedded inside HISTORY decisions under field 'answer'.
	5. **USER ANSWERS:** Explicit answers already provided by the user to prior agent questions. Treat these as authoritative context.

	### PHASE 1: COMPLETION CHECK (HIGHEST PRIORITY)
	**Compare the "USER REQUEST" against the "HISTORY".**
	1. **Analyze:** Does the "HISTORY" contain a successful execution that matches the core intent? An action's own "success: true" only confirms that the CALL succeeded (e.g. a process was started) - it does NOT by itself confirm the underlying task actually completed successfully. If a separate action exists to check the result/status of what you started (its description will say to call it after), you must call it and see a completed/successful result before treating the task as done.
	2. **Decision:**
	- **IF DONE:** Select "finish".
	- **Fields:** category="finish", action="finish", fields=[{ "key": "output", "value": "Complete markdown output with all the relevant details" }], reason=""

	### PHASE 2: RECOVERY & RETRY
	**Only proceed if the task is NOT done.**
	1. **Auth Failure (401/403):** STOP. Output: category="finish", action="finish", output="**Authentication Failed**".
	2. **General Failure:**
	- If "runs" >= 5: STOP. Output: category="finish", action="finish", output="**Task Failed**".
	- If "runs" < 5: RETRY same action. Reason: "Attempt [runs+1]/5."

	### PHASE 3: EXECUTION LOGIC
	**Only proceed if Task is Incomplete and No Failures exist.**

	1. **Conversational & Meta-Query Check:**
	- **Trigger:** Is the user asking about YOU, your capabilities ("What can you do?"), or saying "Hi"/"Help"?
	- **Action:** Select "finish".
	- **Field "output":** "I am the Shuffle Agent. I can help you with: [Markdown List from USER CONTEXT]..."

	2. **Verification (Read-Before-Write):**
	- If modifying a resource, do you have the data?
	- **Check:** Did the user provide input OR is it in "HISTORY"? -> **YES: PROCEED.**
	- **NO:** Run "Get/Read" tool first.

	4. **Answered-Question Handling:**
		- If "USER ANSWERS" or answered question fields in "HISTORY" already contain the missing value, use that value directly.
		- Do NOT ask the same question again when an answer already exists in prior context.

	5. **Action Selection & Risk Assessment:**
	- Select the tool that performs the *next logical step*.
	- **Destructive Guard:**
		- If action is DESTRUCTIVE (stop/delete/remove) -> Set "approval_required": true on the action/tool. 

	6. **Validation & Continuation:**
	- Decisions can be dependant. Make sure to validate the output of one decision before proceeding to the next. If you need to run multiple steps, run them and validate each time.

	%s

	### DATA REDUCTION:
	data_filter:
	- "full": The default value of the data_filter is full. Use for all non-data-returning calls or when you need the entire response.
	- "list": Use for ALL data calls. Request ONLY essential fields. If the schema is completely unknown, fallback to "full"

	### OUTPUT FORMAT (STRICT JSON). Ensure 'reason' and output fields like 'question' are Markdown formatted for readability.

	[
	{
		"i": 0, // For parallel actions, re-use the same index for related actions. NEVER mix "ask" or "approval_required": true with other parallel actions in the same "i".
		"action": "exact_name", // Name of the function/action WITHOUT parameters. Use "finish" if done/answering, "ask" if asking. JUST add the name.
		"category": "singul", // Use "singul" for actions. Use "finish" if done. Use "standalone" ONLY if asking
		"tool": "tool_name", // Name of the tool. Use "core" for finish/ask
		"confidence": 1.0,
		"runs": "1", 
		"delay": "0", // delay in SECONDS before executing the action. 
		"approval_required": false, // true IF the action seems risky or destructive and requires user approval. Otherwise false.
		"data_filter": "list", // for fetch list/search: "list" | "full"
		"fields_needed": ["<List of fields>"], // use this when data_filter is "list": exact fields you need from each item
		"reason": "Explain WHY.",
		"fields": [
		{ "key": "argument_name", "value": "literal_value" }
		]
	}
	]`, enableQuestionsString)

	//	10. NEVER share the same step index "i" between an "ask" decision or an "approval_required": true decision and any parallel tool execution. Any "ask" or "approval_required": true decision MUST have its own standalone step index "i".


	return systemMessage
} // looks good verfied by hari

type AgentNodeParams struct {
	UserInput       string
	Skill           string
	Memory          string
	RawTools        string
	EnableQuestions bool
	ExecutionMode   string
	ReasoningEffort string
	UrlOverride     string
	ApiKeyOverride  string
	ModelOverride   string
	Images          []string
	ImageDetail     openai.ImageURLDetail
}

func parseNodeParams(startNode Action) AgentNodeParams {
	params := AgentNodeParams{
		Memory:      "shuffle_db",
		ImageDetail: openai.ImageURLDetailAuto,
		Images:      []string{},
	}

	reasoningOverride := ""
	for _, param := range startNode.Parameters {
		switch param.Name {
		case "input", "prompt":
			if len(param.Value) > 0 || len(params.UserInput) == 0 {
				params.UserInput = param.Value
			}
		case "template", "skill":
			if len(param.Value) > 0 || len(params.Skill) == 0 {
				params.Skill = param.Value
			}
		case "memory":
			if len(strings.TrimSpace(param.Value)) > 0 {
				params.Memory = strings.TrimSpace(param.Value)
			}
		case "enable_questions":
			params.EnableQuestions = strings.ToLower(param.Value) == "true"
		case "execution_mode":
			params.ExecutionMode = strings.ToLower(strings.TrimSpace(param.Value))
		case "reasoning":
			params.ReasoningEffort = strings.ToLower(strings.TrimSpace(param.Value))
		case "shuffle_ai_url_override":
			params.UrlOverride = strings.TrimSpace(param.Value)
		case "shuffle_ai_apikey_override", "shuffle_ai_api_key_override":
			params.ApiKeyOverride = strings.TrimSpace(param.Value)
		case "shuffle_ai_model_override":
			params.ModelOverride = strings.TrimSpace(param.Value)
		case "shuffle_ai_reasoning_effort_override":
			override := strings.ToLower(strings.TrimSpace(param.Value))
			if len(override) > 0 {
				reasoningOverride = override
			}
		case "image":
			if strings.HasPrefix(param.Value, "http://") || strings.HasPrefix(param.Value, "https://") {
				params.Images = append(params.Images, param.Value)
			} else if strings.HasPrefix(param.Value, "data:image") && strings.Contains(param.Value, "base64,") {
				params.Images = append(params.Images, param.Value)
			} else if len(param.Value) > 0 {
				params.Images = append(params.Images, fmt.Sprintf("data:image;base64,%s", param.Value))
			}
		case "image_detail":
			switch param.Value {
			case "low":
				params.ImageDetail = openai.ImageURLDetailLow
			case "high":
				params.ImageDetail = openai.ImageURLDetailHigh
			case "original":
				params.ImageDetail = openai.ImageURLDetail("original")
			default:
				if len(param.Value) > 0 {
					params.ImageDetail = openai.ImageURLDetail(param.Value)
				}
			}
		case "action", "app_name", "tool_name":
			if len(param.Value) > 0 && param.Value != "openai" && param.Value != "AI Agent" && param.Value != "Shuffle Agent" {
				cleaned := strings.ReplaceAll(param.Value, "app:undefined:api,", "")
				cleaned = strings.ReplaceAll(cleaned, "app:undefined:api", "")
				if len(params.RawTools) > 0 {
					params.RawTools += "," + cleaned
				} else {
					params.RawTools = cleaned
				}
			}
		}
	}

	if len(reasoningOverride) > 0 {
		params.ReasoningEffort = reasoningOverride
	}

	return params
}

// Resolves $workflow variables and incoming branch conditions using Shuffle Tools (repeat_back_to_me).
// Returns (updatedNode, branchSkipped, skipReason).
func resolveVars(execution WorkflowExecution, startNode Action) (Action, bool, string) {
	if standalone {
		return startNode, false, ""
	}

	parsingBody := map[string]string{}
	for _, param := range startNode.Parameters {
		if strings.Contains(param.Value, "$") {
			parsingBody[param.Name] = param.Value
		}
	}

	hasConditions := false
	for _, branch := range execution.Workflow.Branches {
		if branch.DestinationID == startNode.ID && len(branch.Conditions) > 0 {
			hasConditions = true
			break
		}
	}

	if !hasConditions && len(parsingBody) == 0 {
		return startNode, false, ""
	}

	marshalledBody, err := json.Marshal(parsingBody)
	if err != nil || len(marshalledBody) == 0 {
		log.Printf("[ERROR][%s] Failed to marshal parsing body for variable resolution: %v", execution.ExecutionId, err)
		return startNode, false, ""
	}

	repeaterNode := Action{
		AppID:           "3e2bdf9d5069fe3f4746c29d68785a6a",
		AppName:         "Shuffle Tools",
		AppVersion:      "1.2.0",
		Name:            "repeat_back_to_me",
		SourceWorkflow:  execution.Workflow.ID,
		SourceExecution: execution.ExecutionId,
		Parameters: []WorkflowAppActionParameter{
			{
				Name:  "call",
				Value: string(marshalledBody),
			},
		},
	}

	marshalledAction, err := json.Marshal(repeaterNode)
	if err != nil {
		log.Printf("[ERROR][%s] Failed marshaling shuffle-tools request during setup: %s", execution.ExecutionId, err)
		return startNode, false, ""
	}

	backendUrl := getBackendBaseUrl()
	fullUrl := fmt.Sprintf("%s/api/v1/apps/%s/run?execution_id=%s&authorization=%s&parent_node=%s", backendUrl, repeaterNode.AppID, execution.ExecutionId, execution.Authorization, startNode.ID)
	client := GetExternalClient(fullUrl)
	client.Timeout = 1 * time.Minute

	req, err := http.NewRequest("POST", fullUrl, bytes.NewBuffer(marshalledAction))
	if err != nil {
		log.Printf("[ERROR][%s] Failed creating shuffle-tools request during setup: %s", execution.ExecutionId, err)
		return startNode, false, ""
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[ERROR][%s] Failed sending variable resolution request: %s", execution.ExecutionId, err)
		return startNode, false, ""
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[ERROR][%s] Failed reading variable resolution response: %s", execution.ExecutionId, err)
		return startNode, false, ""
	}

	toolsResult := SingleResult{}
	unmarshalResultErr := json.Unmarshal(body, &toolsResult)
	if unmarshalResultErr != nil || len(toolsResult.Result) == 0 {
		return startNode, false, ""
	}

	mappedResult := map[string]string{}
	unmarshalMapErr := json.Unmarshal([]byte(toolsResult.Result), &mappedResult)
	if unmarshalMapErr != nil {
		log.Printf("[ERROR][%s] Failed parsing resolved variables map: %s", execution.ExecutionId, unmarshalMapErr)
		return startNode, false, ""
	}
	if len(mappedResult) == 0 {
		return startNode, false, ""
	}

	reasonVal, hasReason := mappedResult["reason"]
	if hasReason && strings.Contains(strings.ToLower(reasonVal), "minimum of one branch") {
		return startNode, true, reasonVal
	}

	for paramIndex, param := range startNode.Parameters {
		resolvedValue, found := mappedResult[param.Name]
		if found {
			startNode.Parameters[paramIndex].Value = resolvedValue
		}
	}

	return startNode, false, ""
}

// Loads skill (template) rules, context, and merges any required apps into the raw tools string.
func loadSkill(ctx context.Context, skill string, rawTools string, execution WorkflowExecution) (string, string, []string, string) {
	if len(skill) == 0 {
		return "", "", []string{}, rawTools
	}

	systemRule, skillContext, requiredApps, err := getTemplateContext(ctx, skill, execution)
	if err != nil {
		log.Printf("[ERROR][%s] Failed to get skill context: %v", execution.ExecutionId, err)
		return "", "", []string{}, rawTools
	}

	if len(requiredApps) == 0 {
		return systemRule, skillContext, requiredApps, rawTools
	}

	existingParts := strings.Split(rawTools, ",")
	appsToAdd := []string{}

	for _, requiredApp := range requiredApps {
		alreadyPresent := false
		requiredClean := strings.TrimPrefix(requiredApp, "app:")

		for _, existingPart := range existingParts {
			existingClean := strings.TrimPrefix(strings.TrimSpace(existingPart), "app:")
			if strings.EqualFold(existingClean, requiredClean) {
				alreadyPresent = true
				break
			}
		}

		if !alreadyPresent {
			appsToAdd = append(appsToAdd, requiredApp)
		}
	}

	if len(appsToAdd) > 0 {
		if len(rawTools) > 0 {
			rawTools = rawTools + "," + strings.Join(appsToAdd, ",")
		} else {
			rawTools = strings.Join(appsToAdd, ",")
		}
	}

	return systemRule, skillContext, requiredApps, rawTools
} // looks good to me

// Formats a single WorkflowAppAction into a Python-style function signature line for the LLM prompt.
func formatActionSignature(actionNumber int, appAction WorkflowAppAction, previousDescription string) (string, string) {
	requiredParams := []string{}
	optionalParams := []string{}

	for _, param := range appAction.Parameters {
		if param.Name == "url" {
			continue
		}

		if param.Name == "body" && len(param.Example) > 0 {
			exampleText := param.Example
			if len(exampleText) > 200 {
				exampleText = exampleText[:200] + "..."
			}

			if strings.HasPrefix(exampleText, "{") || strings.HasPrefix(exampleText, "[") {
				cleanExample := strings.ReplaceAll(exampleText, "\n", "")
				cleanExample = strings.ReplaceAll(cleanExample, "\t", "")
				cleanExample = strings.ReplaceAll(cleanExample, "  ", "")
				cleanExample = strings.ReplaceAll(cleanExample, "\\\"", "\"")
				requiredParams = append(requiredParams, fmt.Sprintf("body=%s", cleanExample))
			} else {
				requiredParams = append(requiredParams, "body")
			}
			continue
		}

		if param.Required {
			if param.Configuration && param.Name != "url" {
				continue
			}
			requiredParams = append(requiredParams, param.Name)
		} else {
			if len(optionalParams) >= 10 {
				continue
			}
			if param.Name == "url" || param.Name == "username" || param.Name == "password" ||
				param.Name == "token" || param.Name == "api_key" || param.Name == "key" ||
				param.Name == "timeout" || param.Name == "ssl_verify" || param.Name == "to_file" {
				continue
			}
			optionalParams = append(optionalParams, param.Name)
		}
	}

	requiredString := ""
	optionalString := ""
	if len(requiredParams) > 0 {
		requiredString = strings.Join(requiredParams, ", ")
		optionalString = ", "
	}

	if len(optionalParams) > 0 {
		for _, optionalParam := range optionalParams {
			optionalString += fmt.Sprintf(`%s="", `, optionalParam)
		}
		optionalString = strings.TrimSuffix(optionalString, ", ")
	} else {
		optionalString = ""
	}

	descriptionString := ""
	if len(appAction.Description) > 0 {
		descriptionText := appAction.Description
		if len(descriptionText) > 130 {
			descriptionText = descriptionText[:130] + ".."
		}
		cleanDescription := strings.ReplaceAll(descriptionText, "\\%", " ")
		cleanDescription = strings.ReplaceAll(cleanDescription, "\n", "")
		descriptionString = fmt.Sprintf(" # %s", cleanDescription)
	}

	updatedPreviousDescription := descriptionString
	if descriptionString == previousDescription {
		descriptionString = ""
	}

	cleanActionName := strings.ReplaceAll(appAction.Name, " ", "_")
	signatureLine := fmt.Sprintf("%d. %s(%s%s)%s", actionNumber, cleanActionName, requiredString, optionalString, descriptionString)
	signatureLine = strings.ReplaceAll(signatureLine, "\n", " ")

	return signatureLine, updatedPreviousDescription
} // looks like lots of string parsing and stuff what its doing at this point  like are we giving the AI enough context about things or are we just trancating

// Discovers actions for each configured tool and builds the tool signature block for the prompt.
func buildToolsContext(ctx context.Context, rawTools string, requiredApps []string) ([]string, string, string) {
	decidedApps := []string{}
	allowedActionString := ""
	specificAppMetadata := ""

	for _, actionStr := range strings.Split(rawTools, ",") {
		actionStr = strings.ToLower(strings.TrimSpace(actionStr))

		if actionStr == "" || actionStr == "nothing" || actionStr == "shuffle ai" ||
			actionStr == "api" || actionStr == "openai" || actionStr == "ai agent" || actionStr == "shuffle agent" {
			continue
		}

		trimmedActionStr := strings.TrimSpace(strings.TrimPrefix(actionStr, "app:"))
		if trimmedActionStr == "" || trimmedActionStr == "openai" {
			continue
		}

		var sortedAppActions []WorkflowAppAction
		if trimmedActionStr == "osctrl" || trimmedActionStr == "subflow:osctrl" ||
			trimmedActionStr == "computer-use" || trimmedActionStr == "computer_use" {
			sortedAppActions = getComputerUseActions()
			trimmedActionStr = "osctrl"
		} else {
			sortedAppActions = getPrioritisedAppActions(ctx, trimmedActionStr, 15)
			if strings.Contains(trimmedActionStr, "shuffle_host_monitors") {
				existingNames := make(map[string]bool, len(sortedAppActions))
				for _, existingAction := range sortedAppActions {
					existingNames[existingAction.Name] = true
				}
				for _, computerAction := range getComputerUseActions() {
					if !existingNames[computerAction.Name] {
						sortedAppActions = append(sortedAppActions, computerAction)
					}
				}
			}
		}

		sort.Slice(sortedAppActions, func(firstIndex, secondIndex int) bool {
			return sortedAppActions[firstIndex].Name < sortedAppActions[secondIndex].Name
		})

		baseToolName := trimmedActionStr
		if len(baseToolName) > 33 && string(baseToolName[32]) == ":" {
			baseToolName = baseToolName[33:]
		} else if len(baseToolName) > 37 && string(baseToolName[36]) == ":" {
			baseToolName = baseToolName[37:]
		}

		if !ArrayContains(decidedApps, baseToolName) {
			decidedApps = append(decidedApps, baseToolName)
		}

		allowedEntry := actionStr
		if !strings.Contains(trimmedActionStr, ":") {
			if len(sortedAppActions) > 0 && len(sortedAppActions[0].AppID) > 0 {
				allowedEntry = fmt.Sprintf("app:%s:%s", sortedAppActions[0].AppID, baseToolName)
			} else {
				allowedEntry = fmt.Sprintf("app:%s", baseToolName)
			}
		}

		if len(allowedActionString) > 0 {
			if !strings.Contains(allowedActionString, allowedEntry) && !strings.Contains(allowedActionString, baseToolName) {
				allowedActionString += "," + allowedEntry
			}
		} else {
			allowedActionString = allowedEntry
		}

		if len(sortedAppActions) == 0 {
			log.Printf("[ERROR] AI Agent: Failed getting prioritised app actions for app '%s'", strings.TrimPrefix(actionStr, "app:"))
			continue
		}

		specificAppMetadata += fmt.Sprintf("\n\n**Available actions and fields for Tool '%s'**:\n", baseToolName)
		previousDescription := ""
		for actionIndex, sortedAppAction := range sortedAppActions {
			signatureLine, updatedPrevDesc := formatActionSignature(actionIndex+1, sortedAppAction, previousDescription)
			previousDescription = updatedPrevDesc
			specificAppMetadata += signatureLine + "\n"
		}
	}

	addedRequired := false
	for _, requiredApp := range requiredApps {
		if !strings.Contains(allowedActionString, requiredApp) {
			addedRequired = true
			allowedActionString += "," + requiredApp
		}
	}
	if addedRequired {
		allowedActionString = strings.TrimPrefix(allowedActionString, ",")
	}

	return decidedApps, allowedActionString, specificAppMetadata
} // fine

// Builds the USER CONTEXT block containing current user, organization, location, and available tool signatures.
func buildUserMetadata(ctx context.Context, execution WorkflowExecution, decidedApps []string, specificAppMetadata string) string {
	metadata := ""
	if len(execution.Workflow.UpdatedBy) > 0 {
		metadata += fmt.Sprintf("Current user: %s\n", execution.Workflow.UpdatedBy)
	}

	if len(execution.Workflow.OrgId) > 0 {
		org, err := GetOrg(ctx, execution.Workflow.OrgId)
		if err == nil && len(org.Id) > 0 {
			metadata += fmt.Sprintf("Organization name: %s\n", org.Name)

			foundUserId := ""
			for _, orgUser := range org.Users {
				if orgUser.Username == execution.Workflow.UpdatedBy {
					foundUserId = orgUser.Id
					break
				}
			}

			if len(foundUserId) > 0 {
				foundUser, userErr := GetUser(ctx, foundUserId)
				if userErr == nil && len(foundUser.Id) > 0 {
					if len(foundUser.UserGeoInfo.Country.Name) > 0 {
						metadata += fmt.Sprintf("Country: %s,", foundUser.UserGeoInfo.Country.Name)
					}
					if len(foundUser.UserGeoInfo.City.Name) > 0 {
						metadata += fmt.Sprintf(" City: %s", foundUser.UserGeoInfo.City.Name)
					}
					metadata += "\n"
				}
			}
		}
	}

	if len(decidedApps) > 0 {
		metadata += fmt.Sprintf("\n\nAVAILABLE TOOLS: %s\n\n", strings.Join(decidedApps, ", "))
	}

	if len(specificAppMetadata) > 0 {
		metadata += fmt.Sprintf("\n%s\n", specificAppMetadata)
	}

	return metadata
} // looks good 

// Resolves the final reasoning effort setting from global config, environment variable, and node parameter override.
func resolveReasoningEffort(paramReasoningEffort string) string {
	resolvedEffort := "low"
	candidates := []string{
		aiReasoningEffort,
		os.Getenv("AI_AGENT_REASONING_EFFORT"),
		paramReasoningEffort,
	}

	for _, candidate := range candidates {
		cleaned := strings.ToLower(strings.TrimSpace(candidate))
		switch cleaned {
		case "low", "medium", "high":
			resolvedEffort = cleaned
		case "minimal", "off", "none":
			resolvedEffort = ""
		}
	}

	return resolvedEffort
} // yeah good

// Builds a user ChatCompletionMessage, attaching image URLs as MultiContent only when images are present.
func buildUserMessageWithImages(textContent string, imageUrls []string, imageDetail openai.ImageURLDetail) openai.ChatCompletionMessage {
	if len(imageUrls) == 0 {
		return openai.ChatCompletionMessage{
			Role:    openai.ChatMessageRoleUser,
			Content: textContent,
		}
	}

	parts := []openai.ChatMessagePart{
		{
			Type: openai.ChatMessagePartTypeText,
			Text: textContent,
		},
	}

	for _, imageUrl := range imageUrls {
		parts = append(parts, openai.ChatMessagePart{
			Type: openai.ChatMessagePartTypeImageURL,
			ImageURL: &openai.ChatMessageImageURL{
				URL:    imageUrl,
				Detail: imageDetail,
			},
		})
	}

	return openai.ChatCompletionMessage{
		Role:         openai.ChatMessageRoleUser,
		MultiContent: parts,
	}
} // alright looks fine too

// Assembles the OpenAI ChatCompletionRequest with the exact message layout expected by the agent prompt.
func buildCompletionRequest(
	params AgentNodeParams,
	systemMessage string,
	skillSystemRule string,
	skillContext string,
	userMetadata string,
	historyCtx AgentHistoryContext,
) openai.ChatCompletionRequest {
	selectedModel := model
	if len(params.ModelOverride) > 0 {
		selectedModel = params.ModelOverride
	}

	filteredSystemMessage := filterSystemPromptByTemplate(params.Skill, systemMessage)
	messages := []openai.ChatCompletionMessage{
		{
			Role:    openai.ChatMessageRoleSystem,
			Content: filteredSystemMessage,
		},
	}

	if len(skillSystemRule) > 0 {
		ruleWithFormatReminder := skillSystemRule + "\n\n## IMPORTANT: Use the original JSON LIST OUTPUT FORMAT NO MATTER WHAT: [{\"tool\": \"tool_name\", ...}]"
		messages = append(messages, openai.ChatCompletionMessage{
			Role:    openai.ChatMessageRoleSystem,
			Content: ruleWithFormatReminder,
		})
	}

	completionRequest := openai.ChatCompletionRequest{
		Model:           selectedModel,
		Messages:        messages,
		Temperature:     0,
		ReasoningEffort: resolveReasoningEffort(params.ReasoningEffort),
	}

	if project.Environment == "cloud" {
		completionRequest.MaxCompletionTokens = 16384
	} else {
		completionRequest.MaxCompletionTokens = aiMaxTokens
	}

	if len(skillContext) > 0 {
		completionRequest.Messages = append(completionRequest.Messages, openai.ChatCompletionMessage{
			Role:    openai.ChatMessageRoleUser,
			Content: "SKILL CONTEXT:\n" + skillContext,
		})
	}

	preparedUserContext := fmt.Sprintf("USER CONTEXT:\n%s\n", userMetadata)
	completionRequest.Messages = append(
		completionRequest.Messages,
		buildUserMessageWithImages(preparedUserContext, params.Images, params.ImageDetail),
	)

	if len(historyCtx.MarshalledDecisions) > 4 {
		historyText := fmt.Sprintf("HISTORY:\n%s", string(historyCtx.MarshalledDecisions))
		recentImages := historyCtx.HistoryImages

		if len(recentImages) > 0 {
			completionRequest.ReasoningEffort = ""
			const maxHistoryImages = 2
			if len(recentImages) > maxHistoryImages {
				recentImages = recentImages[len(recentImages)-maxHistoryImages:]
			}
		}

		completionRequest.Messages = append(
			completionRequest.Messages,
			buildUserMessageWithImages(historyText, recentImages, params.ImageDetail),
		)
	}

	if len(historyCtx.PreviousAnswers) > 0 {
		completionRequest.Messages = append(completionRequest.Messages, openai.ChatCompletionMessage{
			Role:    openai.ChatMessageRoleUser,
			Content: fmt.Sprintf("USER ANSWERS:\n%s", historyCtx.PreviousAnswers),
		})
	}

	if len(historyCtx.FailureInjection) > 0 {
		completionRequest.Messages = append(completionRequest.Messages, openai.ChatCompletionMessage{
			Role:    openai.ChatMessageRoleUser,
			Content: historyCtx.FailureInjection,
		})
	}

	activeUserRequest := params.UserInput
	if len(historyCtx.ContinuationMessage) > 0 {
		if len(params.UserInput) > 0 {
			completionRequest.Messages = append(completionRequest.Messages, openai.ChatCompletionMessage{
				Role:    openai.ChatMessageRoleUser,
				Content: fmt.Sprintf("ORIGINAL REQUEST (already completed, visible in HISTORY): %s", params.UserInput),
			})
		}
		activeUserRequest = historyCtx.ContinuationMessage
	}

	completionRequest.Messages = append(completionRequest.Messages, openai.ChatCompletionMessage{
		Role:    openai.ChatMessageRoleUser,
		Content: fmt.Sprintf("USER REQUEST: %s", activeUserRequest),
	})

	currentTime := time.Now()
	completionRequest.Messages = append(completionRequest.Messages, openai.ChatCompletionMessage{
		Role:    openai.ChatMessageRoleUser,
		Content: fmt.Sprintf("Current time: %s (%d)", currentTime.Format(time.RFC3339), currentTime.Unix()),
	})

	return completionRequest
} // wait is it how it is in the old code or did we fixed anuy thing here i see we have USER ANSWERS and USER REQUEST too ??

// Executes the LLM call via RunAiQuery and returns the raw text output and parsed ChatCompletionResponse.
func runAgentLLM(
	ctx context.Context,
	execution WorkflowExecution,
	startNode Action,
	params AgentNodeParams,
	completionRequest openai.ChatCompletionRequest,
) (string, openai.ChatCompletionResponse, error) {
	recorder := httptest.NewRecorder()

	callInfo := AiCallInfo{
		Caller:           "aiAgentRunner",
		OrgID:            execution.Workflow.OrgId,
		ExecutionId:      execution.ExecutionId,
		Resp:             recorder,
		Url:              params.UrlOverride,
		ApiKey:           params.ApiKeyOverride,
		Model:            params.ModelOverride,
		ReasoningEffort:  params.ReasoningEffort,
		AuthenticationId: startNode.AuthenticationId,
	}

	rawOutput, err := RunAiQuery(ctx, callInfo, "", "", completionRequest)
	if err != nil {
		log.Printf("[ERROR][%s] AI_AGENT_LLM_FAILURE: org=%s action=%s error=%q", execution.ExecutionId, execution.Workflow.OrgId, startNode.ID, err.Error())
		return rawOutput, openai.ChatCompletionResponse{}, err
	}

	openaiResponse := openai.ChatCompletionResponse{}
	if recorder != nil {
		recordedResult := recorder.Result()
		defer recordedResult.Body.Close()

		responseBody, readErr := io.ReadAll(recordedResult.Body)
		if readErr == nil {
			unmarshalErr := json.Unmarshal(responseBody, &openaiResponse)
			if unmarshalErr != nil {
				log.Printf("[ERROR][%s] AI Agent: Failed unmarshalling AI query response for action %s: %s", execution.ExecutionId, startNode.ID, unmarshalErr)
			}
		} else {
			log.Printf("[ERROR][%s] AI Agent: Failed reading AI query response body for action %s: %s", execution.ExecutionId, startNode.ID, readErr)
		}
	}

	if len(openaiResponse.Choices) == 0 && len(rawOutput) > 0 {
		openaiResponse.Choices = []openai.ChatCompletionChoice{
			{
				Index: 0,
				Message: openai.ChatCompletionMessage{
					Role:    openai.ChatMessageRoleAssistant,
					Content: rawOutput,
				},
			},
		}
	}

	return rawOutput, openaiResponse, nil
} // looks fine to me

// Generates a short 8-character URL-safe base64 ID for a single AgentDecision.
func generateDecisionId() string {
	randomBytes := make([]byte, 6)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return uuid.NewV4().String()[:8]
	}
	return base64.RawURLEncoding.EncodeToString(randomBytes)
} // good too but wait why its trimming something there ?

// Self-corrects the 'i' step index on newly parsed LLM decisions so they always start cleanly at nextStepIndex.
// Decisions that share the same raw 'i' in the LLM output stay grouped together (parallel),
// while decisions with higher raw 'i' values get mapped to consecutive steps (nextStepIndex + 1, etc.).
func normalizeDecisionIndices(decisions []AgentDecision, nextStepIndex int) []AgentDecision {
	if len(decisions) == 0 {
		return decisions
	}

	if nextStepIndex < 0 {
		nextStepIndex = 0
	}

	sort.SliceStable(decisions, func(firstPos, secondPos int) bool {
		return decisions[firstPos].I < decisions[secondPos].I
	})

	currentStep := nextStepIndex
	previousRawI := decisions[0].I
	for decisionPos, decision := range decisions {
		if decision.I != previousRawI {
			currentStep++
			previousRawI = decision.I
		}
		decisions[decisionPos].I = currentStep
	}

	return decisions
}

// Extracts and parses the LLM output into a normalized list of AgentDecision structs.
func parseLLMDecisions(
	rawOutput string,
	openaiResponse openai.ChatCompletionResponse,
	nextStepIndex int,
) ([]AgentDecision, string, error) {
	choicesText := ""
	for _, choice := range openaiResponse.Choices {
		if len(choice.Message.Content) > 0 {
			choicesText += choice.Message.Content + "\n"
		}
	}
	choicesText = strings.TrimSpace(choicesText)

	if len(choicesText) == 0 && len(openaiResponse.Choices) > 0 && len(openaiResponse.Choices[0].Message.Refusal) > 0 {
		refusalText := openaiResponse.Choices[0].Message.Refusal
		if strings.HasPrefix(refusalText, "JSON") {
			refusalText = strings.Replace(refusalText, "JSON", "", 1)
		}
		if strings.HasPrefix(refusalText, "json") {
			refusalText = strings.Replace(refusalText, "json", "", 1)
		}
		choicesText = strings.TrimSpace(refusalText)
	}

	if len(choicesText) == 0 {
		choicesText = strings.TrimSpace(rawOutput)
	}

	cleanedDecisionString := FixContentOutput(choicesText)
	parsedDecisions, parseErr := parseAgentDecisions(choicesText)
	if len(parsedDecisions) == 0 {
		if parseErr == nil {
			parseErr = errors.New("no valid AgentDecision array or objects found in LLM output")
		}
		return nil, cleanedDecisionString, parseErr
	}

	parsedDecisions = normalizeDecisionIndices(parsedDecisions, nextStepIndex)

	validDecisions := make([]AgentDecision, 0, len(parsedDecisions))
	for _, decision := range parsedDecisions {
		normalizedAction := strings.ToLower(strings.TrimSpace(decision.Action))
		normalizedCategory := strings.ToLower(strings.TrimSpace(decision.Category))
		if len(normalizedAction) == 0 && normalizedCategory != "finish" {
			continue
		}
		if normalizedAction == "finish" || normalizedCategory == "finish" {
			decision.Action = "finish"
			decision.Category = "finish"
		} else {
			decision.Action = strings.TrimSpace(decision.Action)
			expectedCat := expectedCategory(normalizedAction)
			if normalizedCategory != expectedCat {
				decision.Category = expectedCat
			}
		}

		if len(decision.RunDetails.Id) == 0 {
			decision.RunDetails.Id = generateDecisionId()
		}

		for fieldPos, field := range decision.Fields {
			if len(field.Question) > 0 && len(field.Key) == 0 {
				field.Key = "question"
				field.Value = field.Question
				field.Question = ""
				decision.Fields[fieldPos] = field
			}
		}

		validDecisions = append(validDecisions, decision)
	}

	if len(validDecisions) == 0 {
		return nil, cleanedDecisionString, errors.New("no valid actionable AgentDecision found in LLM output")
	}

	return validDecisions, cleanedDecisionString, nil
}

// Strips bulky HTTP headers and cookies from a tool's raw HTTPOutput JSON string.
func stripHttpHeadersAndCookies(rawResponse string) string {
	if !strings.Contains(rawResponse, "headers") && !strings.Contains(rawResponse, "cookies") {
		return rawResponse
	}

	parsedHttpOutput := HTTPOutput{}
	unmarshalErr := json.Unmarshal([]byte(rawResponse), &parsedHttpOutput)
	if unmarshalErr != nil {
		return rawResponse
	}

	if parsedHttpOutput.Status <= 0 && parsedHttpOutput.Reason == "" {
		return rawResponse
	}

	parsedHttpOutput.Headers = map[string]string{}
	parsedHttpOutput.Cookies = map[string]string{}

	cleanedBytes, marshalErr := json.Marshal(parsedHttpOutput)
	if marshalErr != nil {
		return rawResponse
	}

	return string(cleanedBytes)
}

// Extracts base64 screenshots from a post_take_screenshot tool response and strips them from the JSON text.
func extractAndStripScreenshots(rawResponse string) (string, []string) {
	extractedImages := []string{}
	if len(rawResponse) == 0 {
		return rawResponse, extractedImages
	}

	httpResp := HTTPOutput{}
	unmarshalHttpErr := json.Unmarshal([]byte(rawResponse), &httpResp)
	if unmarshalHttpErr != nil {
		return rawResponse, extractedImages
	}

	httpRespMap, isMap := httpResp.Body.(map[string]interface{})
	if !isMap {
		return rawResponse, extractedImages
	}

	parsedBodyBytes, marshalBodyErr := json.Marshal(httpRespMap)
	if marshalBodyErr != nil {
		return rawResponse, extractedImages
	}

	singleResult := SingleResult{}
	unmarshalSingleErr := json.Unmarshal(parsedBodyBytes, &singleResult)
	if unmarshalSingleErr != nil || len(singleResult.Result) == 0 {
		return rawResponse, extractedImages
	}

	rceOutput := RCEResult{}
	unmarshalRceErr := json.Unmarshal([]byte(singleResult.Result), &rceOutput)
	if unmarshalRceErr != nil || len(rceOutput.Output) == 0 {
		return rawResponse, extractedImages
	}

	screenshots := []ScreenshotWrapper{}
	unmarshalScreenErr := json.Unmarshal([]byte(rceOutput.Output), &screenshots)
	if unmarshalScreenErr != nil {
		return rawResponse, extractedImages
	}

	for screenIndex, screen := range screenshots {
		if len(screen.ImageBase64) > 0 {
			extractedImages = append(extractedImages, screen.ImageBase64)
			screenshots[screenIndex].ImageBase64 = ""
		}
	}

	if len(extractedImages) == 0 {
		return rawResponse, extractedImages
	}

	screenOutputBytes, marshalScreenErr := json.Marshal(screenshots)
	if marshalScreenErr != nil {
		return rawResponse, extractedImages
	}

	rceOutput.Output = string(screenOutputBytes)
	rceOutputBytes, marshalRceErr := json.Marshal(rceOutput)
	if marshalRceErr != nil {
		return rawResponse, extractedImages
	}

	singleResult.Result = string(rceOutputBytes)
	singleResultBytes, marshalSingleErr := json.Marshal(singleResult)
	if marshalSingleErr != nil {
		return rawResponse, extractedImages
	}

	httpResp.Body = string(singleResultBytes)
	cleanedHttpBytes, marshalHttpErr := json.Marshal(httpResp)
	if marshalHttpErr != nil {
		return rawResponse, extractedImages
	}

	return string(cleanedHttpBytes), extractedImages
}

type AgentHistoryContext struct {
	NextStepIndex         int
	MarshalledDecisions   []byte
	HistoryImages         []string
	PreviousAnswers       string
	ContinuationMessage   string
	FailureInjection      string
	MaxFailuresForOneTool int
	ShouldHardAbort       bool
}

// Processes completed decisions to build the cleaned HISTORY JSON, extracted screenshots, user answers, and failure tracking for the next LLM call.
func prepareHistoryContext(execution WorkflowExecution, decisions []AgentDecision) (AgentHistoryContext, error) {
	historyCtx := AgentHistoryContext{
		NextStepIndex:       0,
		MarshalledDecisions: []byte{},
		HistoryImages:       []string{},
	}

	if len(decisions) == 0 {
		return historyCtx, nil
	}

	lastFinishedIndex := -1
	failureCount := 0
	successCount := 0
	consecutiveFailuresByTool := make(map[string]int)
	cleanedDecisions := make([]AgentDecision, 0, len(decisions))

	for _, decision := range decisions {
		promptDecision := decision

		if promptDecision.I > lastFinishedIndex {
			lastFinishedIndex = promptDecision.I
		}

		toolActionKey := strings.ToLower(strings.TrimSpace(promptDecision.Tool)) + ":" + strings.ToLower(strings.TrimSpace(promptDecision.Action))

		if promptDecision.RunDetails.Status == "FAILURE" {
			failureCount++
			consecutiveFailuresByTool[toolActionKey]++
			promptDecision.Runs = fmt.Sprintf("%d", consecutiveFailuresByTool[toolActionKey])
		} else if promptDecision.RunDetails.Status == "FINISHED" || promptDecision.RunDetails.Status == "SUCCESS" {
			successCount++
			consecutiveFailuresByTool[toolActionKey] = 0
		} else if promptDecision.RunDetails.Status == "IGNORED" {
			consecutiveFailuresByTool[toolActionKey] = 0
		}

		for _, field := range promptDecision.Fields {
			if field.Key == "question" && len(field.Answer) > 0 {
				historyCtx.PreviousAnswers += fmt.Sprintf("'%s': '%s'\n", field.Value, field.Answer)
			}
		}

		if len(promptDecision.RunDetails.RawResponse) > 0 {
			promptDecision.RunDetails.RawResponse = stripHttpHeadersAndCookies(promptDecision.RunDetails.RawResponse)

			if promptDecision.DataFilter != "" {
				originalBytesLen := len(promptDecision.RunDetails.RawResponse)
				reducedBytes := ReduceAgentResponseData(
					[]byte(promptDecision.RunDetails.RawResponse),
					promptDecision.DataFilter,
					promptDecision.FieldsNeeded,
				)
				promptDecision.RunDetails.RawResponse = string(reducedBytes)
				if debug {
					log.Printf("[DEBUG][%s] AI_AGENT_REDUCE: decision=%s tool=%s data_filter=%s fields=%v original_bytes=%d reduced_bytes=%d",
						execution.ExecutionId,
						promptDecision.RunDetails.Id,
						promptDecision.Tool,
						promptDecision.DataFilter,
						promptDecision.FieldsNeeded,
						originalBytesLen,
						len(promptDecision.RunDetails.RawResponse),
					)
				}
			}

			if promptDecision.Action == "post_take_screenshot" {
				cleanedResponse, extractedScreenshots := extractAndStripScreenshots(promptDecision.RunDetails.RawResponse)
				promptDecision.RunDetails.RawResponse = cleanedResponse
				if len(extractedScreenshots) > 0 {
					historyCtx.HistoryImages = append(historyCtx.HistoryImages, extractedScreenshots...)
				}
			}
		}

		cleanedDecisions = append(cleanedDecisions, promptDecision)
	}

	for _, activeFailures := range consecutiveFailuresByTool {
		if activeFailures > historyCtx.MaxFailuresForOneTool {
			historyCtx.MaxFailuresForOneTool = activeFailures
		}
	}

	if debug {
		log.Printf("[DEBUG][%s] AI_AGENT: org=%s decisions_total=%d failures=%d successes=%d last_index=%d",
			execution.ExecutionId,
			execution.Workflow.OrgId,
			len(decisions),
			failureCount,
			successCount,
			lastFinishedIndex,
		)
	}

	historyCtx.NextStepIndex = lastFinishedIndex + 1

	for reverseIndex := len(decisions) - 1; reverseIndex >= 0; reverseIndex-- {
		decision := decisions[reverseIndex]
		if decision.Action != "ask" {
			continue
		}

		foundContinuation := false
		for _, field := range decision.Fields {
			if field.Key == "continue" && len(field.Answer) > 0 {
				historyCtx.ContinuationMessage = field.Answer
				foundContinuation = true
				break
			}
		}
		if foundContinuation {
			break
		}
	}

	const maxAllowedFailuresPerTool = 4
	if historyCtx.MaxFailuresForOneTool >= maxAllowedFailuresPerTool {
		historyCtx.ShouldHardAbort = true
	} else if historyCtx.MaxFailuresForOneTool >= 3 {
		historyCtx.FailureInjection = "\n\nSome of the previous decisions failed. Finalise the agent.\n\n"
	}

	marshalledBytes, marshalErr := json.Marshal(cleanedDecisions)
	if marshalErr != nil {
		return historyCtx, marshalErr
	}
	historyCtx.MarshalledDecisions = marshalledBytes

	return historyCtx, nil
}

const (
	AgentStateRunning  = "RUNNING"
	AgentStateWaiting  = "WAITING"
	AgentStateFinished = "FINISHED"
	AgentStateAborted  = "ABORTED"
)

// Loads the latest execution from the database and extracts or initializes the AgentOutput for startNode.
func loadAgentStateFromDB(
	ctx context.Context,
	execution WorkflowExecution,
	startNode Action,
	params AgentNodeParams,
	originalUserInput string,
	allowedActionString string,
	incomingAgentOutput AgentOutput,
) (WorkflowExecution, Action, AgentOutput) {
	if !standalone && len(execution.Results) == 0 && len(execution.Workflow.ID) == 0 {
		callerResults := execution.Results
		dbExecution, dbErr := GetWorkflowExecution(ctx, execution.ExecutionId)
		if dbErr == nil && dbExecution != nil && len(dbExecution.ExecutionId) > 0 {
			execution = *dbExecution
			if len(callerResults) > 0 {
				existingIds := make(map[string]bool, len(execution.Results))
				for _, r := range execution.Results {
					existingIds[r.Action.ID] = true
				}
				for _, callerResult := range callerResults {
					if !existingIds[callerResult.Action.ID] {
						execution.Results = append(execution.Results, callerResult)
					}
				}
			}
		}
	}

	if len(execution.Workflow.OrgId) == 0 && len(execution.ExecutionOrg) > 0 {
		execution.Workflow.OrgId = execution.ExecutionOrg
	}
	if len(execution.ExecutionOrg) == 0 && len(execution.Workflow.OrgId) > 0 {
		execution.ExecutionOrg = execution.Workflow.OrgId
	}

	agentOutput := AgentOutput{}
	for _, existingResult := range execution.Results {
		if existingResult.Action.ID != startNode.ID {
			continue
		}

		// Preserve resolved parameters saved on Turn 0 if a subsequent caller passed an unresolved Action
		if len(existingResult.Action.Parameters) > 0 {
			startNode = existingResult.Action
		}

		rawResultText := existingResult.Result
		if strings.Contains(rawResultText, "Result too large to handle") {
			fullResultText, fileErr := getExecutionFileValue(ctx, execution, existingResult)
			if fileErr == nil && len(fullResultText) > 0 {
				rawResultText = fullResultText
			}
		}

		cleanedResultText := cleanAgentResultString(rawResultText)
		if len(cleanedResultText) > 0 {
			unmarshalErr := json.Unmarshal([]byte(cleanedResultText), &agentOutput)
			if unmarshalErr != nil {
				log.Printf("[WARNING][%s] AI Agent: Failed unmarshalling node result for %s: %s", execution.ExecutionId, startNode.ID, unmarshalErr)
			}
		}
		break
	}

	if len(incomingAgentOutput.Decisions) > 0 {
		agentOutput = incomingAgentOutput
	}

	allowedActions := []string{}
	if len(allowedActionString) > 0 {
		allowedActions = strings.Split(allowedActionString, ",")
	}

	agentOutput.ExecutionId = execution.ExecutionId
	agentOutput.NodeId = startNode.ID

	if agentOutput.StartedAt == 0 {
		if execution.StartedAt > 0 {
			agentOutput.StartedAt = execution.StartedAt
			const maxSecondsTimestamp int64 = 10_000_000_000
			if agentOutput.StartedAt < maxSecondsTimestamp {
				agentOutput.StartedAt *= 1000
			}
		} else {
			agentOutput.StartedAt = time.Now().UnixMilli()
		}
	}
	if len(agentOutput.Input) == 0 {
		if len(params.UserInput) > 0 {
			agentOutput.Input = params.UserInput
		} else if len(execution.ExecutionArgument) > 0 {
			agentOutput.Input = execution.ExecutionArgument
		}
	}
	if len(agentOutput.OriginalInput) == 0 {
		if len(originalUserInput) > 0 {
			agentOutput.OriginalInput = originalUserInput
		} else if len(agentOutput.Input) > 0 {
			agentOutput.OriginalInput = agentOutput.Input
		}
	}
	if len(agentOutput.Memory) == 0 {
		if len(params.Memory) > 0 {
			agentOutput.Memory = params.Memory
		} else {
			agentOutput.Memory = "shuffle_db"
		}
	}
	if len(agentOutput.Template) == 0 && len(params.Skill) > 0 {
		agentOutput.Template = params.Skill
	}
	if len(agentOutput.ExecutionMode) == 0 && len(params.ExecutionMode) > 0 {
		agentOutput.ExecutionMode = params.ExecutionMode
	}
	if len(allowedActions) > 0 {
		agentOutput.AllowedActions = allowedActions
	}

	return execution, startNode, agentOutput
}

// Ensures agentOutput.Decisions always ends with a completed "finish" decision and no earlier decision is left in "RUNNING".
func ensureFinalFinishDecision(
	decisions []AgentDecision,
	finalReason string,
	nowMs int64,
	isAborted bool,
) []AgentDecision {
	for decisionIndex, decision := range decisions {
		currentStatus := decision.RunDetails.Status
		if currentStatus == "RUNNING" || (isAborted && currentStatus == "WAITING") {
			if isAborted {
				decisions[decisionIndex].RunDetails.Status = "ABORTED"
			} else {
				decisions[decisionIndex].RunDetails.Status = "FAILURE"
			}
			decisions[decisionIndex].RunDetails.CompletedAt = nowMs
			if len(decision.RunDetails.RawResponse) == 0 && len(finalReason) > 0 {
				decisions[decisionIndex].RunDetails.RawResponse = finalReason
			}
		}
	}

	lastDecisionIsFinish := false
	if len(decisions) > 0 {
		lastIndex := len(decisions) - 1
		lastDecision := decisions[lastIndex]
		if lastDecision.Action == "finish" || lastDecision.Category == "finish" {
			lastDecisionIsFinish = true
			decisions[lastIndex].RunDetails.Status = "FINISHED"
			if decisions[lastIndex].RunDetails.StartedAt == 0 {
				decisions[lastIndex].RunDetails.StartedAt = nowMs
			}
			if decisions[lastIndex].RunDetails.CompletedAt == 0 {
				decisions[lastIndex].RunDetails.CompletedAt = nowMs
			}
			if isAborted && len(finalReason) > 0 {
				decisions[lastIndex].Reason = finalReason
			}
		}
	}

	if !lastDecisionIsFinish {
		syntheticDecision := AgentDecision{
			I:        len(decisions),
			Action:   "finish",
			Category: "finish",
			Reason:   finalReason,
			Fields: []Valuereplace{
				{Key: "output", Value: finalReason},
			},
			RunDetails: AgentDecisionRunDetails{
				Id:          generateDecisionId(),
				Status:      "FINISHED",
				StartedAt:   nowMs,
				CompletedAt: nowMs,
			},
		}
		decisions = append(decisions, syntheticDecision)
	}

	return decisions
}

// Updates the status hierarchy (AgentOutput -> ActionResult -> WorkflowExecution) and saves directly to the database.
func saveAgentStateToDB(
	ctx context.Context,
	execution WorkflowExecution,
	startNode Action,
	agentOutput AgentOutput,
	targetState string,
	abortReason string,
) (WorkflowExecution, AgentOutput, ActionResult, error) {
	nowMs := time.Now().UnixMilli()
	var dbNodeStatus string
	var finalNodeStatus string
	var nodeCompletedAt int64 = 0

	if len(agentOutput.ExecutionId) == 0 {
		agentOutput.ExecutionId = execution.ExecutionId
	}
	if len(agentOutput.NodeId) == 0 {
		agentOutput.NodeId = startNode.ID
	}
	if agentOutput.StartedAt == 0 {
		agentOutput.StartedAt = nowMs
	}
	if len(agentOutput.Input) == 0 {
		for _, param := range startNode.Parameters {
			if (param.Name == "input" || param.Name == "prompt") && len(param.Value) > 0 {
				agentOutput.Input = param.Value
				break
			}
		}
		if len(agentOutput.Input) == 0 && len(execution.ExecutionArgument) > 0 {
			agentOutput.Input = execution.ExecutionArgument
		}
	}
	if len(agentOutput.OriginalInput) == 0 && len(agentOutput.Input) > 0 {
		agentOutput.OriginalInput = agentOutput.Input
	}
	if len(agentOutput.Template) == 0 {
		for _, param := range startNode.Parameters {
			if (param.Name == "template" || param.Name == "skill") && len(param.Value) > 0 {
				agentOutput.Template = param.Value
				break
			}
		}
	}
	if len(agentOutput.Memory) == 0 {
		for _, param := range startNode.Parameters {
			if param.Name == "memory" && len(strings.TrimSpace(param.Value)) > 0 {
				agentOutput.Memory = strings.TrimSpace(param.Value)
				break
			}
		}
		if len(agentOutput.Memory) == 0 {
			agentOutput.Memory = "shuffle_db"
		}
	}

	isStandaloneRun := execution.ExecutionId == execution.WorkflowId || execution.ExecutionId == execution.Workflow.ID
	willNotifyStream := !standalone && !isStandaloneRun && project.Environment != "worker"

	switch targetState {
	case AgentStateRunning:
		agentOutput.Status = AgentStateRunning
		agentOutput.CompletedAt = 0
		dbNodeStatus = "WAITING"
		finalNodeStatus = "WAITING"
		execution.Status = "EXECUTING"

	case AgentStateWaiting:
		agentOutput.Status = AgentStateWaiting
		agentOutput.CompletedAt = 0
		dbNodeStatus = "WAITING"
		finalNodeStatus = "WAITING"
		execution.Status = "WAITING"

	case AgentStateFinished:
		agentOutput.Status = AgentStateFinished
		agentOutput.CompletedAt = nowMs
		finalNodeStatus = "SUCCESS"
		dbNodeStatus = "SUCCESS"
		if willNotifyStream {
			dbNodeStatus = "WAITING"
		}
		nodeCompletedAt = nowMs
		if isStandaloneRun {
			execution.Status = "FINISHED"
			execution.CompletedAt = nowMs / 1000
		}

	case "SKIPPED":
		agentOutput.Status = AgentStateFinished
		agentOutput.CompletedAt = nowMs
		finalNodeStatus = "SKIPPED"
		dbNodeStatus = "SKIPPED"
		nodeCompletedAt = nowMs
		if isStandaloneRun {
			execution.Status = "FINISHED"
			execution.CompletedAt = nowMs / 1000
		}

	case AgentStateAborted:
		agentOutput.Status = AgentStateAborted
		agentOutput.Error = abortReason
		agentOutput.Output = abortReason
		if strings.Contains(abortReason, "Minimum of one branch") {
			agentOutput.Output = "The agent did not start due to the workflow not reaching this point."
		}
		agentOutput.CompletedAt = nowMs
		finalNodeStatus = "FAILURE"
		dbNodeStatus = "FAILURE"
		if willNotifyStream {
			dbNodeStatus = "WAITING"
		}
		nodeCompletedAt = nowMs
		if isStandaloneRun {
			execution.Status = "ABORTED"
			execution.CompletedAt = nowMs / 1000
		}
	}

	marshalledOutput, marshalErr := json.Marshal(agentOutput)
	if marshalErr != nil {
		log.Printf("[ERROR][%s] AI Agent: Failed marshalling AgentOutput in saveAgentStateToDB: %s", execution.ExecutionId, marshalErr)
		return execution, agentOutput, ActionResult{}, marshalErr
	}

	dbNodeResult := ActionResult{
		Action:        startNode,
		ExecutionId:   execution.ExecutionId,
		Authorization: execution.Authorization,
		Result:        string(marshalledOutput),
		Status:        dbNodeStatus,
		StartedAt:     agentOutput.StartedAt,
		CompletedAt:   nodeCompletedAt,
	}

	foundNodeIndex := -1
	for resultIndex, existingResult := range execution.Results {
		if existingResult.Action.ID == startNode.ID {
			foundNodeIndex = resultIndex
			break
		}
	}

	if foundNodeIndex >= 0 {
		execution.Results[foundNodeIndex] = dbNodeResult
	} else {
		execution.Results = append(execution.Results, dbNodeResult)
	}

	if !standalone {
		dbErr := SetWorkflowExecution(ctx, execution, true)
		if dbErr != nil {
			log.Printf("[ERROR][%s] AI Agent: Failed saving workflow execution in saveAgentStateToDB: %s", execution.ExecutionId, dbErr)
			return execution, agentOutput, dbNodeResult, dbErr
		}
	}

	streamNodeResult := dbNodeResult
	streamNodeResult.Status = finalNodeStatus

	return execution, agentOutput, streamNodeResult, nil
}

// Checks whether the user aborted or stopped the workflow execution from the UI.
func isExecutionAbortedByUser(ctx context.Context, executionId string) bool {
	if standalone || len(executionId) == 0 {
		return false
	}

	dbExecution, fetchErr := GetWorkflowExecution(ctx, executionId)
	if fetchErr != nil || dbExecution == nil {
		return false
	}

	return dbExecution.Status == "ABORTED" || dbExecution.Status == "FAILURE"
}

// Redeploys a workflow execution to the on-prem Orborus environment queue if the workflow has non-cloud actions waiting after the AI Agent.
func redeployToOrborus(ctx context.Context, execution WorkflowExecution, finalStatus string) {
	fullExecution, fetchErr := GetWorkflowExecution(ctx, execution.ExecutionId)
	if fetchErr != nil || fullExecution == nil {
		log.Printf("[WARNING][%s] Failed getting full execution for AI Agent redeployment: %s", execution.ExecutionId, fetchErr)
		return
	}

	if fullExecution.Workflow.ID == fullExecution.ExecutionId {
		return
	}

	agentEnvironment := ""
	for _, workflowAction := range fullExecution.Workflow.Actions {
		if len(workflowAction.Environment) > 0 {
			agentEnvironment = workflowAction.Environment
			break
		}
	}

	if len(agentEnvironment) == 0 && len(fullExecution.Workflow.ExecutionEnvironment) > 0 {
		agentEnvironment = fullExecution.Workflow.ExecutionEnvironment
	}

	if len(agentEnvironment) == 0 || strings.ToLower(agentEnvironment) == "cloud" {
		return
	}

	executionRequest := ExecutionRequest{
		ExecutionId:   fullExecution.ExecutionId,
		WorkflowId:    fullExecution.Workflow.ID,
		Authorization: fullExecution.Authorization,
		Environments:  []string{agentEnvironment},
		Priority:      11,
	}

	parsedEnv := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(agentEnvironment, " ", "-"), "_", "-"))
	if project.Environment == "cloud" {
		parsedEnv = fmt.Sprintf("%s_%s", parsedEnv, fullExecution.ExecutionOrg)
	}

	log.Printf("[INFO][%s] AI Agent finished (status: %s). Redeploying workflow to queue '%s' with priority %d", fullExecution.ExecutionId, finalStatus, parsedEnv, executionRequest.Priority)
	queueErr := SetWorkflowQueue(ctx, executionRequest, parsedEnv)
	if queueErr != nil {
		log.Printf("[ERROR][%s] Failed redeploying workflow after AI Agent completion to env %s: %s", fullExecution.ExecutionId, parsedEnv, queueErr)
	}
}

// Single-purpose notifier that records terminal agent telemetry and POSTs the completed node ActionResult to /api/v1/streams so downstream workflow nodes run.
func notifyWorkflowStream(
	ctx context.Context,
	execution WorkflowExecution,
	agentOutput AgentOutput,
	nodeResult ActionResult,
) {
	durationSeconds := int64(0)
	if agentOutput.StartedAt > 0 && agentOutput.CompletedAt > 0 {
		durationSeconds = (agentOutput.CompletedAt - agentOutput.StartedAt) / 1000
	} else if agentOutput.StartedAt > 0 {
		durationSeconds = (time.Now().UnixMilli() - agentOutput.StartedAt) / 1000
	}

	go IncrementCache(ctx, execution.Workflow.OrgId, "agent_executions", 1)
	if nodeResult.Status == "SUCCESS" || nodeResult.Status == "FINISHED" {
		go IncrementCache(ctx, execution.Workflow.OrgId, "agent_executions_successful", 1)
	} else {
		go IncrementCache(ctx, execution.Workflow.OrgId, "agent_executions_failed", 1)
	}

	actualToolCalls := 0
	for _, d := range agentOutput.Decisions {
		actionLower := strings.ToLower(strings.TrimSpace(d.Action))
		catLower := strings.ToLower(strings.TrimSpace(d.Category))
		if actionLower == "finish" || catLower == "finish" || actionLower == "ask" || actionLower == "question" {
			continue
		}
		actualToolCalls++
	}

	log.Printf("[INFO] AI_AGENT_FINISH: execution_id=%s org=%s status=%s duration=%ds tool_calls=%d llm_calls=%d prompt_tokens=%d completion_tokens=%d total_tokens=%d",
		execution.ExecutionId,
		execution.Workflow.OrgId,
		agentOutput.Status,
		durationSeconds,
		actualToolCalls,
		agentOutput.LLMCallCount,
		agentOutput.PromptTokens,
		agentOutput.CompletionTokens,
		agentOutput.TotalTokens,
	)

	isStandaloneRun := execution.ExecutionId == execution.WorkflowId || execution.ExecutionId == execution.Workflow.ID
	if standalone || isStandaloneRun || project.Environment == "worker" {
		return
	}

	marshalledResult, marshalErr := json.Marshal(nodeResult)
	if marshalErr != nil {
		log.Printf("[ERROR][%s] Failed marshalling nodeResult for /api/v1/streams: %s", execution.ExecutionId, marshalErr)
		return
	}

	streamUrl := fmt.Sprintf("%s/api/v1/streams", getBackendBaseUrl())
	httpClient := &http.Client{}

	streamReq, reqErr := http.NewRequest("POST", streamUrl, bytes.NewBuffer(marshalledResult))
	if reqErr != nil {
		log.Printf("[ERROR][%s] Error building /api/v1/streams request for agent status '%s': %s", execution.ExecutionId, nodeResult.Status, reqErr)
		return
	}
	streamReq.Header.Set("Content-Type", "application/json")

	_, _, streamErr := DoRequestWithRetry(httpClient, streamReq, 3)
	if streamErr != nil {
		log.Printf("[ERROR][%s] Failed POSTing agent nodeResult '%s' to /api/v1/streams after 3 attempts: %s. Updating DB status directly.", execution.ExecutionId, nodeResult.Status, streamErr)
		for resultIndex, existingResult := range execution.Results {
			if existingResult.Action.ID == nodeResult.Action.ID {
				execution.Results[resultIndex] = nodeResult
				break
			}
		}
		_ = SetWorkflowExecution(ctx, execution, true)
		return
	}

	redeployToOrborus(ctx, execution, nodeResult.Status)
}

// Marks the AI Agent run as FINISHED (guaranteeing a final finish decision), persists to DB, and notifies /api/v1/streams for downstream workflow nodes.
func finishAgentRun(
	ctx context.Context,
	execution WorkflowExecution,
	startNode Action,
	agentOutput AgentOutput,
) (Action, error) {
	nowMs := time.Now().UnixMilli()
	agentOutput.Decisions = ensureFinalFinishDecision(agentOutput.Decisions, agentOutput.Output, nowMs, false)

	updatedExec, updatedOutput, streamNodeResult, saveErr := saveAgentStateToDB(ctx, execution, startNode, agentOutput, AgentStateFinished, "")
	if saveErr != nil {
		return startNode, saveErr
	}

	notifyWorkflowStream(ctx, updatedExec, updatedOutput, streamNodeResult)
	return startNode, nil
}

// Marks the AI Agent run as ABORTED (guaranteeing a synthetic finish decision), persists to DB, and notifies /api/v1/streams with FAILURE.
func abortAgentRun(
	ctx context.Context,
	execution WorkflowExecution,
	startNode Action,
	agentOutput AgentOutput,
	abortLabel string,
	abortReason string,
) (Action, error) {
	log.Printf("[ERROR][%s] AI_AGENT_ABORT: org=%s label=%s decisions=%d llm_calls=%d total_tokens=%d reason=%q",
		execution.ExecutionId,
		execution.Workflow.OrgId,
		abortLabel,
		len(agentOutput.Decisions),
		agentOutput.LLMCallCount,
		agentOutput.TotalTokens,
		abortReason,
	)

	nowMs := time.Now().UnixMilli()
	agentOutput.Decisions = ensureFinalFinishDecision(agentOutput.Decisions, abortReason, nowMs, true)

	updatedExec, updatedOutput, streamNodeResult, saveErr := saveAgentStateToDB(ctx, execution, startNode, agentOutput, AgentStateAborted, abortReason)
	if saveErr != nil {
		return startNode, errors.New(abortReason)
	}

	notifyWorkflowStream(ctx, updatedExec, updatedOutput, streamNodeResult)
	return startNode, errors.New(abortReason)
}

// Executes a single tool call via RunAgentDecisionSingulActionHandler and sets its RunDetails ("FINISHED", "WAITING", or "FAILURE").
func runTool(
	execution WorkflowExecution,
	agentOutput AgentOutput,
	decision AgentDecision,
) (completedDecision AgentDecision) {
	completedDecision = decision
	completedDecision.RunDetails.StartedAt = time.Now().UnixMilli()

	defer func() {
		recoveredPanic := recover()
		if recoveredPanic != nil {
			log.Printf("[ERROR][%s] AI_AGENT_PANIC: org=%s decision_id=%s panic=%v", execution.ExecutionId, execution.Workflow.OrgId, completedDecision.RunDetails.Id, recoveredPanic)
			completedDecision.RunDetails.Status = "FAILURE"
			completedDecision.RunDetails.CompletedAt = time.Now().UnixMilli()
			completedDecision.RunDetails.RawResponse = fmt.Sprintf("PANIC: %v", recoveredPanic)
		}
	}()

	if completedDecision.Category == "standalone" {
		if completedDecision.Action == "add_tool" {
			completedDecision.RunDetails.Status = "RUNNING"
			return completedDecision
		}
		if completedDecision.Action == "answer" {
			completedDecision.RunDetails.Status = "FINISHED"
			completedDecision.RunDetails.CompletedAt = time.Now().UnixMilli()
			return completedDecision
		}

		completedDecision.RunDetails.Status = "FAILURE"
		completedDecision.RunDetails.CompletedAt = time.Now().UnixMilli()
		completedDecision.RunDetails.RawResponse = fmt.Sprintf("Invalid standalone decision. Action '%s' must use category 'singul' or 'finish'.", completedDecision.Action)
		log.Printf("[ERROR][%s] AI Agent: Invalid standalone decision for action '%s'. Marked as failure.", execution.ExecutionId, completedDecision.Action)
		return completedDecision
	}

	toolAllowed, allowedTools := isAgentToolAllowed(agentOutput, completedDecision)
	if !toolAllowed {
		completedDecision.RunDetails.Status = "FAILURE"
		completedDecision.RunDetails.CompletedAt = time.Now().UnixMilli()
		completedDecision.RunDetails.RawResponse = fmt.Sprintf("Tool '%s' is not allowed for this run. Allowed tools: %s", completedDecision.Tool, strings.Join(allowedTools, ", "))
		return completedDecision
	}

	rawResponse, debugUrl, resolvedAppName, categoryLabels, actionName, runError := RunAgentDecisionSingulActionHandler(execution, completedDecision, agentOutput.ExecutionMode)
	if len(resolvedAppName) > 0 {
		completedDecision.Tool = resolvedAppName
	}

	completedDecision.RunDetails.RawResponse = string(rawResponse)
	completedDecision.RunDetails.DebugUrl = debugUrl
	completedDecision.RunDetails.CategoryLabels = categoryLabels
	completedDecision.RunDetails.ActionName = actionName

	parsedDelay := 0
	if len(completedDecision.Delay) > 0 {
		delayValue, delayErr := strconv.Atoi(completedDecision.Delay)
		if delayErr == nil && delayValue > 0 && delayValue <= 2678400 {
			parsedDelay = delayValue
		}
	}

	if parsedDelay > 0 && runError == nil {
		completedDecision.RunDetails.Status = "WAITING"
	} else if runError != nil {
		completedDecision.RunDetails.Status = "FAILURE"
		completedDecision.RunDetails.CompletedAt = time.Now().UnixMilli()
		if len(completedDecision.RunDetails.RawResponse) == 0 {
			completedDecision.RunDetails.RawResponse = fmt.Sprintf("Failed to start decision action. Raw Error: %s", runError)
		}
	} else {
		completedDecision.RunDetails.Status = "FINISHED"
		completedDecision.RunDetails.CompletedAt = time.Now().UnixMilli()
	}

	durationSeconds := (time.Now().UnixMilli() - completedDecision.RunDetails.StartedAt) / 1000
	log.Printf("[INFO][%s] AI_AGENT_TOOL: org=%s tool=%s action=%s status=%s duration=%ds", execution.ExecutionId, execution.Workflow.OrgId, completedDecision.Tool, completedDecision.Action, completedDecision.RunDetails.Status, durationSeconds)

	return completedDecision
}

// Sends an org notification when an agent decision requires user input ("ask"/"question") or tool approval.
func sendUserWaitNotification(
	ctx context.Context,
	execution WorkflowExecution,
	startNode Action,
	decision AgentDecision,
) {
	if standalone {
		return
	}

	backendUrl := getBackendBaseUrl()

	if decision.Action == "ask" || decision.Action == "question" {
		questionText := decision.Reason
		if len(decision.Fields) > 0 && len(decision.Fields[0].Value) > 0 {
			questionText = decision.Fields[0].Value
		}
		safeQuestion := strings.ReplaceAll(questionText, "'", "\\'")

		notifyErr := CreateOrgNotification(
			ctx,
			fmt.Sprintf("Agent - input required: '%s'", safeQuestion),
			"Input required during agent run.",
			fmt.Sprintf("/forms/%s?authorization=%s&reference_execution=%s&source_node=%s&decision_id=%s&backend_url=%s",
				execution.WorkflowId,
				url.QueryEscape(execution.Authorization),
				execution.ExecutionId,
				startNode.ID,
				decision.RunDetails.Id,
				url.QueryEscape(backendUrl),
			),
			execution.ExecutionOrg,
			false,
			"LOW",
			"agent_approval",
		)
		if notifyErr != nil {
			log.Printf("[ERROR][%s] Failed creating notification for ask input: %s", execution.ExecutionId, notifyErr)
		}
		return
	}

	if decision.ApprovalRequired {
		notifyErr := CreateOrgNotification(
			ctx,
			fmt.Sprintf("Agent - approval required for '%s'", decision.Tool),
			"Approval required during agent run.",
			fmt.Sprintf("/forms/%s?authorization=%s&reference_execution=%s&source_node=%s&decision_id=%s&backend_url=%s",
				execution.WorkflowId,
				execution.Authorization,
				execution.ExecutionId,
				startNode.ID,
				decision.RunDetails.Id,
				backendUrl,
			),
			execution.ExecutionOrg,
			false,
			"MEDIUM",
			"agent_approval",
		)
		if notifyErr != nil {
			log.Printf("[ERROR][%s] Failed creating notification for approval required: %s", execution.ExecutionId, notifyErr)
		}
	}
}

// Returns true if a tool decision that required approval has been approved by the user and has not yet executed its tool call.
func isDecisionApprovedByUser(decision AgentDecision) bool {
	if !decision.ApprovalRequired || decision.Action == "ask" || decision.Action == "question" {
		return false
	}
	trimmedResponse := strings.TrimSpace(decision.RunDetails.RawResponse)
	if trimmedResponse == "Approved by user" || strings.HasPrefix(trimmedResponse, "Approved by user") {
		return true
	}
	if len(trimmedResponse) > 0 {
		return false
	}
	for _, field := range decision.Fields {
		if field.Key == "approve" && strings.HasPrefix(strings.TrimSpace(field.Value), "Approved to continue") {
			return true
		}
	}
	return false
}

// Returns true if a decision represents the final "finish" step (either by Action or Category).
func isFinishDecision(decision AgentDecision) bool {
	return strings.EqualFold(strings.TrimSpace(decision.Action), "finish") ||
		strings.EqualFold(strings.TrimSpace(decision.Category), "finish")
}

// Returns true if a decision must pause and wait for the user (either an "ask"/"question" step or an unapproved tool requiring approval).
func requiresUserWait(decision AgentDecision) bool {
	if decision.Action == "ask" || decision.Action == "question" {
		return true
	}
	return !standalone &&
		decision.ApprovalRequired &&
		!isDecisionApprovedByUser(decision) &&
		(decision.Category == "singul" || decision.Category == "standalone")
}

// Returns true if a decision still needs runAgentTools to execute it or wait on it.
func isDecisionPending(decision AgentDecision) bool {
	return decision.RunDetails.Status == "WAITING" ||
		decision.RunDetails.Status == "RUNNING" ||
		isDecisionApprovedByUser(decision)
}

// Returns true if any decision in the list is still pending tool execution or user input.
func hasPendingAgentDecisions(decisions []AgentDecision) bool {
	for _, decision := range decisions {
		if isDecisionPending(decision) {
			return true
		}
	}
	return false
}

// Executes pending agent decisions step-by-step (by index 'I'):
// - Any newly parsed non-finish LLM decisions are appended to agentOutput.Decisions upfront.
// - Decisions with the same step 'I' run in parallel via runTool.
// - Decisions requiring user input ("ask"/"question" or unapproved ApprovalRequired) pause in AgentStateWaiting.
func runAgentTools(
	ctx context.Context,
	execution WorkflowExecution,
	startNode Action,
	agentOutput AgentOutput,
	parsedDecisions []AgentDecision,
) (WorkflowExecution, AgentOutput, error) {
	isNewLLMTurn := len(parsedDecisions) > 0
	turnStartIndex := len(agentOutput.Decisions)

	for _, decision := range parsedDecisions {
		if len(decision.Action) == 0 || isFinishDecision(decision) {
			continue
		}
		if len(decision.RunDetails.Id) == 0 {
			decision.RunDetails.Id = generateDecisionId()
		}
		if decision.RunDetails.Status != "IGNORED" && decision.RunDetails.Status != "FINISHED" && decision.RunDetails.Status != "SUCCESS" {
			decision.RunDetails.Status = "WAITING"
		}
		agentOutput.Decisions = append(agentOutput.Decisions, decision)
	}

	totalDecisions := len(agentOutput.Decisions)
	if totalDecisions > turnStartIndex {
		turnSlice := agentOutput.Decisions[turnStartIndex:totalDecisions]
		sort.SliceStable(turnSlice, func(firstPos, secondPos int) bool {
			return turnSlice[firstPos].I < turnSlice[secondPos].I
		})
	}

	firstPendingIndex := -1
	for decisionIndex, decision := range agentOutput.Decisions {
		if isDecisionPending(decision) {
			firstPendingIndex = decisionIndex
			break
		}
	}
	if firstPendingIndex == -1 {
		return execution, agentOutput, nil
	}

	// Group pending decision indices by step number 'I' (decisions with the same 'I' run in parallel)
	var stepGroups [][]int
	for decisionIndex := firstPendingIndex; decisionIndex < totalDecisions; decisionIndex++ {
		if len(stepGroups) == 0 || agentOutput.Decisions[decisionIndex].I != agentOutput.Decisions[decisionIndex-1].I {
			stepGroups = append(stepGroups, []int{decisionIndex})
		} else {
			lastGroupIndex := len(stepGroups) - 1
			stepGroups[lastGroupIndex] = append(stepGroups[lastGroupIndex], decisionIndex)
		}
	}

	log.Printf("[INFO][%s] [AGENT-LOOP] runAgentTools: total_decisions=%d first_pending_idx=%d step_groups=%d (new_llm_turn=%t)", execution.ExecutionId, totalDecisions, firstPendingIndex, len(stepGroups), isNewLLMTurn)

	waitingForUser := false

	for _, stepDecisionIndices := range stepGroups {
		currentStepIndex := agentOutput.Decisions[stepDecisionIndices[0]].I
		lastIndexInStep := stepDecisionIndices[len(stepDecisionIndices)-1]

		if isExecutionAbortedByUser(ctx, execution.ExecutionId) {
			log.Printf("[INFO][%s] Workflow execution was aborted by user before step %d. Stopping tool execution.", execution.ExecutionId, currentStepIndex)
			_, _ = abortAgentRun(ctx, execution, startNode, agentOutput, "user_aborted", "Agent run was aborted by user")
			return execution, agentOutput, errors.New("Agent run was aborted by user")
		}

		stepStartedAt := time.Now().UnixMilli()
		hasRunnableToolsInStep := false

		for _, decisionIndex := range stepDecisionIndices {
			decision := agentOutput.Decisions[decisionIndex]
			if !isDecisionPending(decision) {
				continue
			}
			decision.RunDetails.StartedAt = stepStartedAt

			if requiresUserWait(decision) {
				decision.RunDetails.Status = "WAITING"
			} else {
				decision.ApprovalRequired = false
				decision.RunDetails.Status = "RUNNING"
				hasRunnableToolsInStep = true
			}
			agentOutput.Decisions[decisionIndex] = decision
		}

		log.Printf("[INFO][%s] [AGENT-LOOP] runAgentTools step i=%d starting: decisions_in_step=%d runnable=%t", execution.ExecutionId, currentStepIndex, len(stepDecisionIndices), hasRunnableToolsInStep)

		if hasRunnableToolsInStep {
			execution, agentOutput, _, _ = saveAgentStateToDB(ctx, execution, startNode, agentOutput, AgentStateRunning, "")
		}

		var toolWaitGroup sync.WaitGroup
		var stateMutex sync.Mutex
		stepFailed := false
		stepWaiting := false

		// Immutable snapshots for this parallel group so goroutines never race on stateMutex writes
		stepExecSnapshot := execution
		stepOutputSnapshot := agentOutput

		for _, decisionIndex := range stepDecisionIndices {
			currentDecision := agentOutput.Decisions[decisionIndex]

			if currentDecision.RunDetails.Status == "WAITING" {
				stepWaiting = true
				continue
			}
			if currentDecision.RunDetails.Status != "RUNNING" {
				continue
			}

			toolWaitGroup.Add(1)
			go func(targetIndex int, decisionToRun AgentDecision) {
				defer toolWaitGroup.Done()

				finishedDecision := runTool(stepExecSnapshot, stepOutputSnapshot, decisionToRun)

				stateMutex.Lock()
				agentOutput.Decisions[targetIndex] = finishedDecision
				if finishedDecision.RunDetails.Status == "FAILURE" {
					stepFailed = true
				}
				if finishedDecision.RunDetails.Status == "WAITING" {
					stepWaiting = true
				}
				stateMutex.Unlock()
			}(decisionIndex, currentDecision)
		}

		toolWaitGroup.Wait()

		if isExecutionAbortedByUser(ctx, execution.ExecutionId) {
			log.Printf("[INFO][%s] Workflow execution was aborted by user during step %d. Stopping tool execution.", execution.ExecutionId, currentStepIndex)
			_, _ = abortAgentRun(ctx, execution, startNode, agentOutput, "user_aborted", "Agent run was aborted by user")
			return execution, agentOutput, errors.New("Agent run was aborted by user")
		}

		// If this step failed or paused for user input, drop any un-executed future steps from this turn
		// so they are not left in WAITING/ABORTED (the next LLM turn will re-evaluate with the updated results).
		if (stepFailed || stepWaiting) && lastIndexInStep+1 < len(agentOutput.Decisions) {
			agentOutput.Decisions = agentOutput.Decisions[:lastIndexInStep+1]
		}

		targetStepState := AgentStateRunning
		if stepWaiting && !stepFailed {
			targetStepState = AgentStateWaiting
			waitingForUser = true
		}

		var saveErr error
		execution, agentOutput, _, saveErr = saveAgentStateToDB(ctx, execution, startNode, agentOutput, targetStepState, "")
		if saveErr != nil {
			return execution, agentOutput, saveErr
		}

		log.Printf("[INFO][%s] [AGENT-LOOP] runAgentTools step i=%d finished: failed=%t waiting_for_user=%t state=%s", execution.ExecutionId, currentStepIndex, stepFailed, stepWaiting, targetStepState)

		// Only notify the user after all runnable tools in a new LLM step have finished and state is saved as WAITING
		if stepWaiting && !stepFailed && isNewLLMTurn {
			for _, decisionIndex := range stepDecisionIndices {
				if agentOutput.Decisions[decisionIndex].RunDetails.Status == "WAITING" {
					sendUserWaitNotification(ctx, execution, startNode, agentOutput.Decisions[decisionIndex])
				}
			}
		}

		if stepFailed || stepWaiting {
			break
		}
	}

	if !waitingForUser {
		log.Printf("[INFO][%s] [AGENT-LOOP] runAgentTools completed batch -> handing back to HandleAiAgentExecutionStart2", execution.ExecutionId)
		_, triggerErr := triggerAgentStart(ctx, execution, startNode, agentOutput, "runAgentTools")
		if triggerErr != nil {
			return execution, agentOutput, triggerErr
		}
	} else {
		log.Printf("[INFO][%s] [AGENT-LOOP] runAgentTools parked agent in WAITING for user input/approval", execution.ExecutionId)
	}

	return execution, agentOutput, nil
}

type AgentInternalRequest struct {
	ExecutionId     string          `json:"execution_id"`
	Authorization   string          `json:"authorization"`
	StartNode       Action          `json:"start_node"`
	AgentOutput     AgentOutput     `json:"agent_output"`
	ParsedDecisions []AgentDecision `json:"parsed_decisions,omitempty"`
	Caller          string          `json:"caller"`
}

// Sends an internal POST request and waits only for the flushed HTTP 202 Accepted ACK line before closing the connection.
func postAgentInternalWithAck(endpointPath string, payload AgentInternalRequest) error {
	if standalone {
		return errors.New("standalone mode uses direct in-process execution")
	}

	marshalledPayload, marshalErr := json.Marshal(payload)
	if marshalErr != nil {
		return marshalErr
	}

	targetUrl := fmt.Sprintf("%s%s", getBackendBaseUrl(), endpointPath)
	req, reqErr := http.NewRequest("POST", targetUrl, bytes.NewBuffer(marshalledPayload))
	if reqErr != nil {
		return reqErr
	}
	req.Header.Set("Content-Type", "application/json")

	httpClient := &http.Client{
		Transport: &http.Transport{
			ResponseHeaderTimeout: 10 * time.Second,
		},
	}

	httpResp, doErr := httpClient.Do(req)
	if doErr != nil {
		return doErr
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusAccepted {
		bodyBytes, _ := ioutil.ReadAll(io.LimitReader(httpResp.Body, 1024))
		return fmt.Errorf("unexpected status %d from %s: %s", httpResp.StatusCode, endpointPath, string(bodyBytes))
	}

	ackLine, readErr := bufio.NewReader(httpResp.Body).ReadString('\n')
	if readErr != nil && len(ackLine) == 0 {
		return fmt.Errorf("failed reading 202 ACK from %s: %w", endpointPath, readErr)
	}

	return nil
}

// Validates execution_id + authorization against the DB, immediately flushes HTTP 202 Accepted so the caller can exit, and returns a detached background context.
func authenticateAndAckAgentInternalRequest(
	resp http.ResponseWriter,
	request *http.Request,
) (context.Context, WorkflowExecution, AgentInternalRequest, bool) {
	if HandleCors(resp, request) {
		return nil, WorkflowExecution{}, AgentInternalRequest{}, false
	}

	// Detached background context so client disconnect after 202 Flush never cancels DB or HTTP calls
	ctx := context.Background()

	bodyBytes, readErr := ioutil.ReadAll(request.Body)
	if readErr != nil {
		log.Printf("[ERROR] Failed reading internal agent request body: %s", readErr)
		resp.WriteHeader(http.StatusBadRequest)
		_, _ = resp.Write([]byte(`{"success":false,"reason":"Failed reading request body"}`))
		return nil, WorkflowExecution{}, AgentInternalRequest{}, false
	}

	var reqPayload AgentInternalRequest
	if unmarshalErr := json.Unmarshal(bodyBytes, &reqPayload); unmarshalErr != nil {
		log.Printf("[ERROR] Failed unmarshalling internal agent request body: %s", unmarshalErr)
		resp.WriteHeader(http.StatusBadRequest)
		_, _ = resp.Write([]byte(`{"success":false,"reason":"Invalid request JSON"}`))
		return nil, WorkflowExecution{}, AgentInternalRequest{}, false
	}

	if len(reqPayload.ExecutionId) == 0 || len(reqPayload.Authorization) == 0 || len(reqPayload.StartNode.ID) == 0 {
		log.Printf("[WARNING] Missing execution_id, authorization, or start_node in internal agent request")
		resp.WriteHeader(http.StatusUnauthorized)
		_, _ = resp.Write([]byte(`{"success":false,"reason":"Missing execution credentials"}`))
		return nil, WorkflowExecution{}, AgentInternalRequest{}, false
	}

	execution, execErr := GetWorkflowExecution(ctx, reqPayload.ExecutionId)
	if execErr != nil || execution == nil {
		log.Printf("[WARNING][%s] Failed fetching execution in internal agent request: %v", reqPayload.ExecutionId, execErr)
		resp.WriteHeader(http.StatusUnauthorized)
		_, _ = resp.Write([]byte(`{"success":false,"reason":"Bad execution mapping (1)"}`))
		return nil, WorkflowExecution{}, AgentInternalRequest{}, false
	}

	if execution.Authorization != reqPayload.Authorization {
		log.Printf("[WARNING][%s] Authorization mismatch in internal agent request", reqPayload.ExecutionId)
		resp.WriteHeader(http.StatusForbidden)
		_, _ = resp.Write([]byte(`{"success":false,"reason":"Bad execution mapping (2)"}`))
		return nil, WorkflowExecution{}, AgentInternalRequest{}, false
	}

	if len(execution.Workflow.OrgId) == 0 && len(execution.ExecutionOrg) > 0 {
		execution.Workflow.OrgId = execution.ExecutionOrg
	}
	if len(execution.ExecutionOrg) == 0 && len(execution.Workflow.OrgId) > 0 {
		execution.ExecutionOrg = execution.Workflow.OrgId
	}

	resp.Header().Set("Content-Type", "application/json")
	resp.Header().Set("X-Content-Type-Options", "nosniff")
	resp.WriteHeader(http.StatusAccepted)
	_, _ = resp.Write([]byte(`{"success":true,"accepted":true}` + "\n"))
	if flusher, ok := resp.(http.Flusher); ok {
		flusher.Flush()
	}

	return ctx, *execution, reqPayload, true
}

// Triggers /api/v1/agent/loop/tools with 202 Flush ACK to reset the Cloud Run timeout, falling back to in-process runAgentTools if the HTTP handoff fails.
func triggerAgentToolRunner(
	ctx context.Context,
	execution WorkflowExecution,
	startNode Action,
	agentOutput AgentOutput,
	parsedDecisions []AgentDecision,
	caller string,
) (WorkflowExecution, AgentOutput, error) {
	payload := AgentInternalRequest{
		ExecutionId:     execution.ExecutionId,
		Authorization:   execution.Authorization,
		StartNode:       startNode,
		AgentOutput:     agentOutput,
		ParsedDecisions: parsedDecisions,
		Caller:          caller,
	}

	ackErr := postAgentInternalWithAck("/api/v1/agent/loop/tools", payload)
	if ackErr == nil {
		log.Printf("[INFO][%s] Handed off %d decisions to /api/v1/agent/loop/tools (caller=%s)", execution.ExecutionId, len(parsedDecisions), caller)
		return execution, agentOutput, nil
	}

	log.Printf("[WARNING][%s] Handoff to /api/v1/agent/loop/tools failed (%v) — falling back to in-process runAgentTools", execution.ExecutionId, ackErr)
	return runAgentTools(ctx, execution, startNode, agentOutput, parsedDecisions)
}

// Triggers /api/v1/agent/loop/turn with 202 Flush ACK to reset the Cloud Run timeout, falling back to in-process HandleAiAgentExecutionStart2 if the HTTP handoff fails.
func triggerAgentStart(
	ctx context.Context,
	execution WorkflowExecution,
	startNode Action,
	agentOutput AgentOutput,
	caller string,
) (Action, error) {
	payload := AgentInternalRequest{
		ExecutionId:   execution.ExecutionId,
		Authorization: execution.Authorization,
		StartNode:     startNode,
		AgentOutput:   agentOutput,
		Caller:        caller,
	}

	ackErr := postAgentInternalWithAck("/api/v1/agent/loop/turn", payload)
	if ackErr == nil {
		log.Printf("[INFO][%s] Handed off next turn to /api/v1/agent/loop/turn (caller=%s)", execution.ExecutionId, caller)
		return startNode, nil
	}

	log.Printf("[WARNING][%s] Handoff to /api/v1/agent/loop/turn failed (%v) — falling back to in-process HandleAiAgentExecutionStart2", execution.ExecutionId, ackErr)
	return HandleAiAgentExecutionStart2(ctx, execution, startNode, agentOutput, caller)
}

// HTTP handler for /api/v1/agent/loop/tools that validates auth, flushes 202 Accepted immediately, and runs runAgentTools synchronously in this container request.
func HandleAgentLoopTools(resp http.ResponseWriter, request *http.Request) {
	ctx, execution, reqPayload, ok := authenticateAndAckAgentInternalRequest(resp, request)
	if !ok {
		return
	}

	_, _, err := runAgentTools(ctx, execution, reqPayload.StartNode, reqPayload.AgentOutput, reqPayload.ParsedDecisions)
	if err != nil {
		log.Printf("[WARNING][%s] HandleAgentLoopTools completed with error: %v", execution.ExecutionId, err)
	}
}

// HTTP handler for /api/v1/agent/loop/turn that validates auth, flushes 202 Accepted immediately, and runs HandleAiAgentExecutionStart2 synchronously in this container request.
func HandleAgentLoopTurn(resp http.ResponseWriter, request *http.Request) {
	ctx, execution, reqPayload, ok := authenticateAndAckAgentInternalRequest(resp, request)
	if !ok {
		return
	}

	_, err := HandleAiAgentExecutionStart2(ctx, execution, reqPayload.StartNode, reqPayload.AgentOutput, reqPayload.Caller)
	if err != nil {
		log.Printf("[WARNING][%s] HandleAgentLoopTurn completed with error: %v", execution.ExecutionId, err)
	}
}

// Returns true if a decision is a non-tool standalone "answer" (requires no external tool call).
func isStandaloneAnswerDecision(decision AgentDecision) bool {
	return strings.EqualFold(strings.TrimSpace(decision.Category), "standalone") &&
		strings.EqualFold(strings.TrimSpace(decision.Action), "answer")
}

// Returns true if parsedDecisions needs runAgentTools (any tool/ask/approval, or standalone answer without a finish).
func hasRunnableAgentDecisions(parsedDecisions []AgentDecision) bool {
	hasFinish := false
	for _, decision := range parsedDecisions {
		if isFinishDecision(decision) {
			hasFinish = true
			continue
		}
		if !isStandaloneAnswerDecision(decision) {
			return true
		}
	}
	return !hasFinish
}

// Extracts the final response text from a "finish" decision (checking output/body fields first, then Reason, then rawOutput).
func extractFinalFinishOutput(parsedDecisions []AgentDecision, rawOutput string) string {
	for _, decision := range parsedDecisions {
		if !isFinishDecision(decision) {
			continue
		}
		for _, field := range decision.Fields {
			fieldKey := strings.ToLower(strings.TrimSpace(field.Key))
			if (fieldKey == "output" || fieldKey == "body" || fieldKey == "result") && len(strings.TrimSpace(field.Value)) > 0 {
				return field.Value
			}
		}
		if len(strings.TrimSpace(decision.Reason)) > 0 {
			return decision.Reason
		}
	}
	return strings.TrimSpace(rawOutput)
}

// Initializes the agent on Turn 0: logs AI_AGENT_START immediately, validates on-prem AI config, resolves $workflow variables and branch conditions ONCE, and saves initial RUNNING state to DB.
func initAgentFirstTurn(
	ctx context.Context,
	execution WorkflowExecution,
	startNode Action,
	agentOutput AgentOutput,
	callerName string,
) (WorkflowExecution, Action, AgentOutput, bool, error) {
	rawParams := parseNodeParams(startNode)
	originalUserInput := rawParams.UserInput

	// 1. Populate baseline node state BEFORE any validation or variable resolution can abort
	agentOutput.Status = AgentStateRunning
	agentOutput.ExecutionId = execution.ExecutionId
	agentOutput.NodeId = startNode.ID
	if agentOutput.StartedAt == 0 {
		agentOutput.StartedAt = time.Now().UnixMilli()
	}
	agentOutput.CompletedAt = 0
	if len(rawParams.UserInput) > 0 {
		agentOutput.Input = rawParams.UserInput
	} else if len(agentOutput.Input) == 0 && len(execution.ExecutionArgument) > 0 {
		agentOutput.Input = execution.ExecutionArgument
	}
	if len(originalUserInput) > 0 {
		agentOutput.OriginalInput = originalUserInput
	} else if len(agentOutput.OriginalInput) == 0 && len(agentOutput.Input) > 0 {
		agentOutput.OriginalInput = agentOutput.Input
	}
	if len(rawParams.Memory) > 0 {
		agentOutput.Memory = rawParams.Memory
	} else if len(agentOutput.Memory) == 0 {
		agentOutput.Memory = "shuffle_db"
	}
	if len(rawParams.Skill) > 0 {
		agentOutput.Template = rawParams.Skill
	}
	if len(rawParams.ExecutionMode) > 0 {
		agentOutput.ExecutionMode = rawParams.ExecutionMode
	}

	// 2. Always log AI_AGENT_START once at the very beginning of Turn 0 before any abort can occur
	initiatedBy := execution.Workflow.UpdatedBy
	if len(initiatedBy) == 0 {
		initiatedBy = "system"
	}
	log.Printf("[INFO][%s] AI_AGENT_START: org=%s workflow=%s user=%s caller=%s input_length=%d", execution.ExecutionId, execution.Workflow.OrgId, execution.WorkflowId, initiatedBy, callerName, len(agentOutput.Input))

	if !standalone && (execution.Status == "ABORTED" || execution.Status == "FAILURE") {
		abortedNode, abortErr := abortAgentRun(ctx, execution, startNode, agentOutput, "user_aborted", "Agent run was aborted by user")
		return execution, abortedNode, agentOutput, true, abortErr
	}

	// 3. Validate On-Prem AI Configuration
	if project.Environment == "onprem" {
		if !evaluateLocalAI(ctx, execution) {
			onpremAiConfigErr := "To use the AI Agent on-premise, configure your LLM credentials by connecting the OpenAI app in Shuffle App Auth (supports OpenAI and any compatible provider/proxy), or enable Cloud Sync with \"Shuffle Cloud AI\" to run requests through Shuffle Cloud."
			log.Printf("[ERROR] AI Configuration Error: %s", onpremAiConfigErr)
			abortedNode, abortErr := abortAgentRun(ctx, execution, startNode, agentOutput, "onprem_ai_not_configured", onpremAiConfigErr)
			return execution, abortedNode, agentOutput, true, abortErr
		}
	}

	// 4. Resolve $workflow variables and branch conditions ONCE
	resolvedNode, branchSkipped, skipReason := resolveVars(execution, startNode)
	if branchSkipped {
		agentOutput.Status = AgentStateFinished
		agentOutput.Output = skipReason
		execution, agentOutput, nodeResult, _ := saveAgentStateToDB(ctx, execution, startNode, agentOutput, "SKIPPED", skipReason)
		notifyWorkflowStream(ctx, execution, agentOutput, nodeResult)
		return execution, startNode, agentOutput, true, nil
	}
	startNode = resolvedNode
	resolvedParams := parseNodeParams(startNode)

	// Update fields with resolved parameter values (including if a $var resolved to empty string)
	if len(rawParams.UserInput) > 0 || len(resolvedParams.UserInput) > 0 {
		agentOutput.Input = resolvedParams.UserInput
		if len(agentOutput.Input) == 0 && len(execution.ExecutionArgument) > 0 {
			agentOutput.Input = execution.ExecutionArgument
		}
	}
	if len(resolvedParams.Memory) > 0 {
		agentOutput.Memory = resolvedParams.Memory
	}
	if len(resolvedParams.Skill) > 0 {
		agentOutput.Template = resolvedParams.Skill
	}
	if len(resolvedParams.ExecutionMode) > 0 {
		agentOutput.ExecutionMode = resolvedParams.ExecutionMode
	}

	execution, agentOutput, _, _ = saveAgentStateToDB(ctx, execution, startNode, agentOutput, AgentStateRunning, "")

	return execution, startNode, agentOutput, false, nil
}

// Checks whether the organization (or its billing parent org) has exceeded its monthly AI token or app execution quota in cloud mode.
func checkAgentBillingQuota(ctx context.Context, execution WorkflowExecution) (bool, string) {
	if standalone || len(execution.Workflow.OrgId) == 0 {
		return false, ""
	}

	billingOrgId := execution.Workflow.OrgId
	currentOrg, orgErr := GetOrg(ctx, execution.Workflow.OrgId)
	billingOrg := currentOrg

	// Bill against the parent org if this is a sub-org.
	// Check CreatorOrg first, fall back to ManagerOrgs[0] for older sub-orgs.
	parentOrgId := ""
	if orgErr == nil && currentOrg != nil {
		if len(currentOrg.CreatorOrg) > 0 {
			parentOrgId = currentOrg.CreatorOrg
		} else if len(currentOrg.ManagerOrgs) > 0 && len(currentOrg.ManagerOrgs[0].Id) > 0 {
			parentOrgId = currentOrg.ManagerOrgs[0].Id
		}
	}
	if len(parentOrgId) > 0 {
		parentOrg, parentErr := GetOrg(ctx, parentOrgId)
		if parentErr == nil && parentOrg != nil && len(parentOrg.Id) > 0 {
			billingOrgId = parentOrgId
			billingOrg = parentOrg
		} else {
			log.Printf("[WARNING][%s] AI Agent: Failed getting parent org %s, falling back to current org for billing: %v", execution.ExecutionId, parentOrgId, parentErr)
		}
	}

	orgStats, statsErr := GetOrgStatistics(ctx, billingOrgId)
	monthlyAppRuns := int64(0)
	monthlyLLMTokens := int64(0)
	if statsErr == nil && orgStats != nil {
		convertedStats := GetCorrectedStats(orgStats)
		monthlyAppRuns = convertedStats.MonthlyAppExecutions + convertedStats.MonthlyChildAppExecutions
		monthlyLLMTokens = convertedStats.MonthlyLLMTokens + convertedStats.MonthlyChildOrgLLMTokens
	}

	if billingOrg != nil {
		appRunLimit := int64(billingOrg.SyncFeatures.AppExecutions.Limit)
		if project.Environment == "cloud" {
			useTokenOverride := false
			if expiryMonthStr := os.Getenv("AI_CREDIT_END_MONTH"); len(expiryMonthStr) > 0 {
				if expiryMonth, convErr := strconv.Atoi(expiryMonthStr); convErr == nil && expiryMonth >= 1 && expiryMonth <= 12 {
					now := time.Now()
					expiryDate := time.Date(now.Year(), time.Month(expiryMonth), 1, 0, 0, 0, 0, now.Location())
					if now.Before(expiryDate) {
						useTokenOverride = true
					}
				}
			}

			if useTokenOverride {
				geminiTokenLimit := int64(100_000_000)
				if os.Getenv("AI_CREDITS") > "" {
					credVal, convErr := strconv.ParseInt(os.Getenv("AI_CREDITS"), 10, 64)
					if convErr == nil {
						geminiTokenLimit = credVal
					}
				}

				if monthlyLLMTokens >= geminiTokenLimit {
					return true, fmt.Sprintf("AI LLM token limit reached: %d >= %d. Contact support@shuffler.io to learn more, or connect to your API vendor/self-hosted model of choice to continue!", monthlyLLMTokens, geminiTokenLimit)
				}
			} else if monthlyAppRuns >= appRunLimit {
				return true, fmt.Sprintf("AI App limit reached: %d >= %d. Contact support@shuffler.io to learn more, or connect to your API vendor/self-hosted model of choice to continue!", monthlyAppRuns, appRunLimit)
			}
		}
	}

	return false, ""
}

// Executes a single agent loop turn: builds prompt/tools/history context, calls the LLM, parses decisions, and either finishes or triggers the tool runner.
func runAgentTurn(
	ctx context.Context,
	execution WorkflowExecution,
	startNode Action,
	agentOutput AgentOutput,
	callerName string,
) (Action, error) {
	params := parseNodeParams(startNode)
	if len(agentOutput.Input) > 0 {
		params.UserInput = agentOutput.Input
	}

	if len(strings.TrimSpace(params.UserInput)) == 0 {
		return abortAgentRun(ctx, execution, startNode, agentOutput, "empty_user_input", "No input provided to AI Agent")
	}

	// Guard against runaway infinite loops across all turns (default 60 decisions, configurable via AI_AGENT_MAX_STEPS)
	maxAgentSteps := 60
	if envMaxSteps := strings.TrimSpace(os.Getenv("AI_AGENT_MAX_STEPS")); len(envMaxSteps) > 0 {
		if parsedMax, convErr := strconv.Atoi(envMaxSteps); convErr == nil && parsedMax > 0 {
			maxAgentSteps = parsedMax
		}
	}
	if len(agentOutput.Decisions)+1 >= maxAgentSteps {
		log.Printf("[ERROR][%s] AI_AGENT_MAX_STEPS_EXCEEDED: org=%s loop_count=%d (cache=%d, decisions=%d)", execution.ExecutionId, execution.Workflow.OrgId, len(agentOutput.Decisions)+1, 0, len(agentOutput.Decisions))
		go func() {
			_ = IncrementCacheDump(ctx, execution.Workflow.OrgId, "agent_max_loops_hit", 1)
		}()
		return abortAgentRun(ctx, execution, startNode, agentOutput, "max_agent_loops_reached", fmt.Sprintf("Agent reached maximum execution steps limit (%d) without finishing.", len(agentOutput.Decisions)+1))
	}

	// 1. Build Skill, Tools Context, and Org/User Metadata
	skillSystemRule, skillContext, requiredApps, updatedRawTools := loadSkill(ctx, params.Skill, params.RawTools, execution)
	params.RawTools = updatedRawTools
	decidedApps, allowedActionString, specificAppMetadata := buildToolsContext(ctx, params.RawTools, requiredApps)
	userMetadata := buildUserMetadata(ctx, execution, decidedApps, specificAppMetadata)

	if len(allowedActionString) > 0 {
		agentOutput.AllowedActions = strings.Split(allowedActionString, ",")
	}

	// 2. Build History Context & Guard Against Repeated Identical Tool Failures
	historyCtx, historyErr := prepareHistoryContext(execution, agentOutput.Decisions)
	if historyErr != nil {
		log.Printf("[WARNING][%s] AI Agent: Failed marshalling history context for node %s: %v", execution.ExecutionId, startNode.ID, historyErr)
	}
	if historyCtx.ShouldHardAbort {
		return abortAgentRun(ctx, execution, startNode, agentOutput, "max_retries_exceeded", "Agent stopped after 4 consecutive failed attempts on the same action.")
	}

	// 3. Check Billing Quota, Build ChatCompletionRequest & Execute LLM Call
	if quotaExceeded, quotaReason := checkAgentBillingQuota(ctx, execution); quotaExceeded {
		return abortAgentRun(ctx, execution, startNode, agentOutput, "app_limit_exceeded", quotaReason)
	}

	systemPrompt := getAgentMainSystemPrompt(params.EnableQuestions)
	completionRequest := buildCompletionRequest(params, systemPrompt, skillSystemRule, skillContext, userMetadata, historyCtx)

	log.Printf("[INFO][%s] [AGENT-LOOP] runAgentTurn calling LLM: turn=#%d history_decisions=%d next_step_i=%d continuation=%t", execution.ExecutionId, agentOutput.LLMCallCount+1, len(agentOutput.Decisions), historyCtx.NextStepIndex, len(historyCtx.ContinuationMessage) > 0)

	rawOutput, openaiResponse, llmErr := runAgentLLM(ctx, execution, startNode, params, completionRequest)
	if llmErr != nil {
		return abortAgentRun(ctx, execution, startNode, agentOutput, "ai_query_failed", llmErr.Error())
	}

	agentOutput.LLMCallCount += 1
	if openaiResponse.Usage.TotalTokens > 0 {
		agentOutput.TotalTokens += int64(openaiResponse.Usage.TotalTokens)
		agentOutput.PromptTokens += int64(openaiResponse.Usage.PromptTokens)
		agentOutput.CompletionTokens += int64(openaiResponse.Usage.CompletionTokens)
	}
	// RunAiQuery always streams from the upstream LLM internally while returning full JSON to our recorder.
	completionRequest.Stream = true
	agentOutput.LLMRequests = append(agentOutput.LLMRequests, completionRequest)
	agentOutput.LLMResponses = append(agentOutput.LLMResponses, openaiResponse)

	// Check if user actively aborted the workflow while LLM query was in flight
	if isExecutionAbortedByUser(ctx, execution.ExecutionId) {
		log.Printf("[INFO][%s] Workflow execution was aborted by user while LLM call was in flight. Stopping agent.", execution.ExecutionId)
		return abortAgentRun(ctx, execution, startNode, agentOutput, "user_aborted", "Agent run was aborted by user")
	}

	// 4. Parse LLM Decisions
	parsedDecisions, cleanedDecisionString, parseErr := parseLLMDecisions(rawOutput, openaiResponse, historyCtx.NextStepIndex)
	agentOutput.DecisionString = cleanedDecisionString
	if parseErr != nil || len(parsedDecisions) == 0 {
		errMsg := "AI Agent returned no valid decisions"
		if parseErr != nil {
			errMsg = parseErr.Error()
		}
		return abortAgentRun(ctx, execution, startNode, agentOutput, "decision_parse_failed", errMsg)
	}

	log.Printf("[INFO][%s] [AGENT-LOOP] runAgentTurn parsed %d decision(s) from LLM (turn=#%d, total_tokens=%d)", execution.ExecutionId, len(parsedDecisions), agentOutput.LLMCallCount, agentOutput.TotalTokens)

	// 5. Route: If any runnable tool or human-in-the-loop decision exists -> hand off to Tool Runner; otherwise -> Finish
	if hasRunnableAgentDecisions(parsedDecisions) {
		log.Printf("[INFO][%s] [AGENT-LOOP] runAgentTurn -> handing %d decision(s) to runAgentTools", execution.ExecutionId, len(parsedDecisions))
		_, _, toolErr := triggerAgentToolRunner(ctx, execution, startNode, agentOutput, parsedDecisions, callerName)
		return startNode, toolErr
	}

	nowMs := time.Now().UnixMilli()
	for decisionIndex := range parsedDecisions {
		if isStandaloneAnswerDecision(parsedDecisions[decisionIndex]) {
			parsedDecisions[decisionIndex].RunDetails.Status = "FINISHED"
			parsedDecisions[decisionIndex].RunDetails.StartedAt = nowMs
			parsedDecisions[decisionIndex].RunDetails.CompletedAt = nowMs
		}
	}

	log.Printf("[INFO][%s] [AGENT-LOOP] runAgentTurn -> LLM returned finish decision, finalizing agent run", execution.ExecutionId)
	agentOutput.Decisions = append(agentOutput.Decisions, parsedDecisions...)
	agentOutput.Output = extractFinalFinishOutput(parsedDecisions, rawOutput)
	return finishAgentRun(ctx, execution, startNode, agentOutput)
}

// Entry point for the AI Agent: loads state from DB, runs first-turn initialization ONCE on Turn 0, and delegates the active turn to runAgentTurn.
func HandleAiAgentExecutionStart2(
	ctx context.Context,
	execution WorkflowExecution,
	startNode Action,
	incomingAgentOutput AgentOutput,
	callerName string,
) (Action, error) {
	if strings.TrimSpace(callerName) == "" {
		callerName = "unknown"
	}
	if ctx == nil {
		ctx = context.Background()
	}

	// 1. Load existing state from DB (if any)
	rawParams := parseNodeParams(startNode)
	var agentOutput AgentOutput
	execution, startNode, agentOutput = loadAgentStateFromDB(ctx, execution, startNode, rawParams, rawParams.UserInput, "", incomingAgentOutput)

	log.Printf("[INFO][%s] [AGENT-LOOP] HandleAiAgentExecutionStart2 invoked: caller='%s' node=%s agent_status='%s' exec_status='%s' decisions=%d llm_calls=%d", execution.ExecutionId, callerName, startNode.ID, agentOutput.Status, execution.Status, len(agentOutput.Decisions), agentOutput.LLMCallCount)

	// 2. First Turn Initialization (runs ONLY ONCE when there are no prior decisions)
	if len(agentOutput.Decisions) == 0 {
		var aborted bool
		var initErr error
		execution, startNode, agentOutput, aborted, initErr = initAgentFirstTurn(ctx, execution, startNode, agentOutput, callerName)
		if aborted || initErr != nil {
			return startNode, initErr
		}
	} else {
		if !standalone && (execution.Status == "ABORTED" || execution.Status == "FAILURE") {
			return abortAgentRun(ctx, execution, startNode, agentOutput, "user_aborted", "Agent run was aborted by user")
		}

		// Prevent duplicate overlapping executions if the agent is already actively running
		if agentOutput.Status == AgentStateRunning && callerName != "runAgentTools" {
			log.Printf("[INFO][%s] AI Agent is already actively running (status=%s, agent=%s). Ignoring concurrent trigger from '%s'.", execution.ExecutionId, execution.Status, agentOutput.Status, callerName)
			return startNode, nil
		}

		// If any decision is still pending (e.g. just approved by the user, or another decision in the step is still WAITING), hand off to runAgentTools
		if hasPendingAgentDecisions(agentOutput.Decisions) {
			log.Printf("[INFO][%s] [AGENT-LOOP] HandleAiAgentExecutionStart2 -> pending decisions found, handing off to runAgentTools (caller='%s')", execution.ExecutionId, callerName)
			_, _, toolErr := triggerAgentToolRunner(ctx, execution, startNode, agentOutput, nil, callerName)
			return startNode, toolErr
		}

		// Transition from WAITING / FINISHED to RUNNING in DB when waking up for a new LLM turn (e.g. question answer or continuation)
		if agentOutput.Status != AgentStateRunning {
			execution, agentOutput, _, _ = saveAgentStateToDB(ctx, execution, startNode, agentOutput, AgentStateRunning, "")
		}
	}

	// 3. Execute the current Agent Loop Turn
	return runAgentTurn(ctx, execution, startNode, agentOutput, callerName)
}


//DONE
// update the system prompt to tell the LLM to not mix an ask / approval wait with a parallel tool in the same step I
// the final thing i wanted is somewhat topologically similar to 
// Then HandleAiAgentExecutionStart2 becomes a crystal-clear ~60-line controller that anyone can read in 10 seconds:
// but its just a blue print of an idea or sketch work and this dont mean it has be perfectly 100% similar to this

// goals for the HandleAiAgentExecutionStart2 is a clean flow of logic and code taht makes sense looking at it
// we should be able to know which logic handles the first time call vs subsequent calls right and 
// we need a handler that triggers the HandleAiAgentExecutionStart2 so the agent run tools can use and same for agent run tools so that HandleAiAgentExecutionStart2 can use
// no need to over complicate please look at the other handlers the way they handle but wait how do yhou hanlde this it has no apikey so how you auth so then look shuffuru folder and executeSingleAction and see how it does with exec and auth id
// we can adopt that if it looks good, then the only last piece of puzzle would be how do yhou make sure that given the loop is highly dependent on this api calls calling each other how do you make sure these API calls never fail
// meaning like as long we you triggered the other function successfully you aer good you can exit but wait isnt APi calls are synchronous right you have to WAIT ? then what is the point so how do we knwo that the other handler got our call reached and its all good its goign to do its job we can return ? 
// the issue is say it reached our handler and our run tools got triggered but the caller hit some sorta timeout immediately so they think oh no its a time out but it got triggerd on the other side or what if transient network issues fucking us up
// keep in mind the whole point of using this ping pong http calls loop is that we can not hit the timeout of cloud run but since if api call is failing which will break the loop then as a fall back we can directly try running the function directly inside this instace as a fall back and return and it will call back anyway with api call so that tiny bit of extra compute here might not cause any issue
// given that we still graviated towards this multi server way meaning if agent loop and some loops hit a fresh instance most of the time means state managemetn and race condition handling is even more important right 
// but wait do we need this ? or run the all the functions within the same cloud run instance and only return if ask or approval required kinda thing" 

// func HandleAiAgentExecutionStart2(execution WorkflowExecution, startNode Action, payload AgentStepPayload) error {
// 	log.Printf("[INFO][%s] Agent Controller: phase=%s caller=%s", execution.ExecutionId, payload.Phase, payload.Caller)
// 	// 1. Central Error & Max-Step Guard
// 	if payload.Err != nil {
// 		return finalizeAgentExecution(execution, startNode, payload.State, "FAILURE", payload.Err.Error())
// 	}
// 	switch payload.Phase {
// 	case PhaseInit:
// 		// Runs ONCE per agent invocation:
// 		// - Validate on-prem AI auth (!evaluateLocalAI)
// 		// - Resolve $variables, load org metadata, fetch available tools/skills ONCE
// 		// - Load existing history if this is a user "continue" / answer to an "ask"
// 		state, err := initAgentState(execution, startNode)
// 		if err != nil {
// 			return finalizeAgentExecution(execution, startNode, state, "FAILURE", err.Error())
// 		}
// 		// Kick off LLM in background and return immediately
// 		go runAgentLLM(execution, startNode, state)
// 		return nil
// 	case PhaseLLMDone:
// 		state := payload.State
// 		state.AppendDecisions(payload.LLMDecisions)
// 		// Did LLM say "finish"?
// 		if isFinished, output := state.CheckFinished(); isFinished {
// 			return finalizeAgentExecution(execution, startNode, state, "SUCCESS", output)
// 		}
// 		// Did LLM ask a question or require approval? Park execution in WAITING.
// 		if isWaiting := state.CheckWaitingForUser(); isWaiting {
// 			return parkAgentExecutionForUser(execution, startNode, state)
// 		}
// 		// Otherwise, run ALL decided tools (1 or 100, sequential or parallel) and call back ONCE
// 		go runAgentToolsBatch(execution, startNode, state, payload.LLMDecisions)
// 		return nil
// 	case PhaseToolsDone:
// 		state := payload.State
// 		state.UpdateToolResults(payload.ToolResults)
// 		state.StepCount++
// 		if state.StepCount >= state.MaxSteps {
// 			return finalizeAgentExecution(execution, startNode, state, "FAILURE", "Max agent steps reached")
// 		}
// 		// Save checkpoint once after tools complete, then loop back to LLM!
// 		saveAgentCheckpoint(execution, startNode, state)
// 		go runAgentLLM(execution, startNode, state)
// 		return nil
// 	}
// 	return nil
// }

// TODO:

//1. https://aiplatform.googleapis.com/v1/projects/shuffler/locations/europe-west2/endpoints/openapi/chat/completions": http2: timeout awaiting response headers
// interesting bug, our new design should be very resilent with traisent netowklr failures at all layers like TLS tcp, clinet side bs yeah all those
//2. Clean up the way the HandleAiAgentExecutionStart2 handles decision approved or asking question back as its not at all supposed to run the tools by itself it should liteally needed to send off to runAgentTools
// 3. there is even more mess in the other functions too we cant merge this at this point like that 