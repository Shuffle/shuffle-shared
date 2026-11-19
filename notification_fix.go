package shuffle

// AI suggested fixes for workflow failure notifications.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	uuid "github.com/satori/go.uuid"
)

type NotificationFixChange struct {
	NodeId    string `json:"node_id"`
	NodeLabel string `json:"node_label"`
	Parameter string `json:"parameter"`
	Before    string `json:"before"`
	After     string `json:"after"`
}

type NotificationFixSuggestion struct {
	Success        bool                    `json:"success"`
	SuggestionId   string                  `json:"suggestion_id"`
	NotificationId string                  `json:"notification_id"`
	WorkflowId     string                  `json:"workflow_id"`
	ExecutionId    string                  `json:"execution_id"`
	NodeId         string                  `json:"node_id"`
	NodeLabel      string                  `json:"node_label"`
	Fixable        bool                    `json:"fixable"`
	Explanation    string                  `json:"explanation"`
	Changes        []NotificationFixChange `json:"changes"`
	CreatedAt      int64                   `json:"created_at"`
	Applied        bool                    `json:"applied"`
}

// Origins set by CreateOrgNotification for failures an edit of the node itself can fix
var notificationFixOrigins = []string{
	"workflow_silent_failure",
	"action_failure",
	"liquid_syntax",
	"app_error",
	"workflow_execution",
}

// Fallback for notifications stored without origin (e.g. forwarded from workers)
var notificationFixTitlePrefixes = []string{
	"Potential error in Workflow",
	"Error in Workflow",
	"Liquid Syntax Error in Workflow",
	"App error for node",
	"Bad Status code in Workflow",
}

var notificationFixVariableRegex = regexp.MustCompile(`\$([a-zA-Z0-9_]+)`)

const notificationFixCacheMinutes = 1440

// Returned when the workflow changed after the suggestion was made. The UI regenerates on this.
var errNotificationFixStale = errors.New("the node was changed after this suggestion was made")

// Notifications are reused for every new failure of the same node, so suggestions are per execution
func getNotificationFixCacheKey(notificationId, executionId string) string {
	return fmt.Sprintf("notification_fix_%s_%s", notificationId, executionId)
}

func getNotificationFixExecutionId(notification Notification) string {
	if len(notification.ExecutionId) > 0 {
		return notification.ExecutionId
	}

	return getNotificationReferenceParam(notification.ReferenceUrl, "execution_id")
}

func IsNotificationAiFixable(notification Notification) bool {
	if len(notification.ExecutionId) == 0 && len(getNotificationReferenceParam(notification.ReferenceUrl, "execution_id")) == 0 {
		return false
	}

	if len(notification.Origin) > 0 {
		return ArrayContains(notificationFixOrigins, notification.Origin)
	}

	for _, prefix := range notificationFixTitlePrefixes {
		if strings.HasPrefix(notification.Title, prefix) {
			return true
		}
	}

	return false
}

func truncateForFix(value string, max int) string {
	if len(value) <= max {
		return value
	}

	return value[:max] + "... (truncated)"
}

// Auth fields and literal secrets are never sent to the LLM nor editable.
// Pure variable references like "$exec.api_key" are not secrets.
func isNotificationFixProtectedParam(param WorkflowAppActionParameter) bool {
	if param.Configuration {
		return true
	}

	return isSensitiveParameter(param.Name) && !strings.HasPrefix(strings.TrimSpace(param.Value), "$")
}

// IDs of every node upstream of nodeId, following branches backwards. Only their outputs exist when nodeId runs.
func getNotificationFixUpstreamIds(workflow *Workflow, nodeId string) []string {
	parents := map[string][]string{}
	for _, branch := range workflow.Branches {
		parents[branch.DestinationID] = append(parents[branch.DestinationID], branch.SourceID)
	}

	upstream := []string{}
	visited := map[string]bool{nodeId: true}
	queue := append([]string{}, parents[nodeId]...)
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		if visited[id] {
			continue
		}

		visited[id] = true
		upstream = append(upstream, id)
		queue = append(queue, parents[id]...)
	}

	return upstream
}

// One line per field of a JSON value, e.g. `$exec.batch_id (string) = "f638..."`. Goes one level into nested objects.
func describeNotificationFixFields(prefix string, raw string) []string {
	var parsed interface{}
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		return []string{fmt.Sprintf("%s (text) = %q", prefix, truncateForFix(raw, 80))}
	}

	lines := []string{}
	var walk func(path string, value interface{}, depth int)
	walk = func(path string, value interface{}, depth int) {
		// ponytail: capped at 40 fields per source, raise if big payloads hide the field the AI needs
		if len(lines) >= 40 {
			return
		}

		switch typed := value.(type) {
		case map[string]interface{}:
			if depth >= 2 || len(typed) == 0 {
				lines = append(lines, fmt.Sprintf("%s (object, %d keys)", path, len(typed)))
				return
			}

			keys := []string{}
			for key := range typed {
				keys = append(keys, key)
			}

			sort.Strings(keys)
			for _, key := range keys {
				walk(path+"."+key, typed[key], depth+1)
			}
		case []interface{}:
			lines = append(lines, fmt.Sprintf("%s (list, %d items)", path, len(typed)))
		case string:
			lines = append(lines, fmt.Sprintf("%s (string) = %q", path, truncateForFix(typed, 80)))
		default:
			valueJson, _ := json.Marshal(typed)
			lines = append(lines, fmt.Sprintf("%s = %s", path, string(valueJson)))
		}
	}

	walk(prefix, parsed, 0)
	return lines
}

func getNotificationFixCache(ctx context.Context, notificationId, executionId string) (*NotificationFixSuggestion, error) {
	cache, err := GetCache(ctx, getNotificationFixCacheKey(notificationId, executionId))
	if err != nil {
		return nil, err
	}

	var data []byte
	switch typed := cache.(type) {
	case []byte:
		data = typed
	case string:
		data = []byte(typed)
	default:
		return nil, errors.New("bad cache format")
	}

	suggestion := NotificationFixSuggestion{}
	if err := json.Unmarshal(data, &suggestion); err != nil {
		return nil, err
	}

	return &suggestion, nil
}

func setNotificationFixCache(ctx context.Context, suggestion NotificationFixSuggestion) error {
	data, err := json.Marshal(suggestion)
	if err != nil {
		return err
	}

	return SetCache(ctx, getNotificationFixCacheKey(suggestion.NotificationId, suggestion.ExecutionId), data, notificationFixCacheMinutes)
}

func GenerateNotificationFix(ctx context.Context, user User, notification Notification) (*NotificationFixSuggestion, error) {
	executionId := getNotificationFixExecutionId(notification)

	nodeId := notification.NodeId
	if len(nodeId) == 0 {
		nodeId = getNotificationReferenceParam(notification.ReferenceUrl, "node")
	}

	if debug {
		log.Printf("[DEBUG][%s] Generating AI fix for notification %s, node %s, user %s", executionId, notification.Id, nodeId, user.Username)
	}

	// Re-read the execution: at notification time the node result often isn't stored yet
	execution, err := GetWorkflowExecution(ctx, executionId)
	if err != nil {
		log.Printf("[ERROR][%s] Failed loading execution for AI fix of notification %s: %s", executionId, notification.Id, err)
		return nil, fmt.Errorf("failed loading execution %s: %s", executionId, err)
	}

	if execution.ExecutionOrg != user.ActiveOrg.Id && execution.Workflow.OrgId != user.ActiveOrg.Id {
		log.Printf("[AUDIT][%s] User %s (%s) in org %s denied access to execution of org %s for AI fix", executionId, user.Username, user.Id, user.ActiveOrg.Id, execution.ExecutionOrg)
		return nil, errors.New("execution does not belong to your organization")
	}

	workflowId := execution.WorkflowId
	if len(execution.Workflow.ID) > 0 {
		workflowId = execution.Workflow.ID
	}

	workflow, err := GetWorkflow(ctx, workflowId)
	if err != nil || workflow == nil || len(workflow.ID) == 0 {
		log.Printf("[ERROR][%s] Failed loading workflow %s for AI fix of notification %s: %v", executionId, workflowId, notification.Id, err)
		return nil, fmt.Errorf("failed loading workflow %s", workflowId)
	}

	if workflow.OrgId != user.ActiveOrg.Id {
		log.Printf("[AUDIT][%s] User %s (%s) in org %s denied access to workflow %s of org %s for AI fix", executionId, user.Username, user.Id, user.ActiveOrg.Id, workflow.ID, workflow.OrgId)
		return nil, errors.New("workflow does not belong to your organization")
	}

	// The current workflow is what we edit. The node may have been removed since.
	actionIndex := findActionIndexByID(workflow, nodeId)

	// Cached under the notification's execution ID, which Apply looks up again
	suggestion := &NotificationFixSuggestion{
		Success:        true,
		SuggestionId:   uuid.NewV4().String(),
		NotificationId: notification.Id,
		WorkflowId:     workflow.ID,
		ExecutionId:    executionId,
		NodeId:         nodeId,
		CreatedAt:      time.Now().Unix(),
		Changes:        []NotificationFixChange{},
	}

	if actionIndex == -1 {
		log.Printf("[INFO][%s] Node %s no longer exists in workflow %s. Nothing to fix for notification %s", executionId, nodeId, workflow.ID, notification.Id)
		suggestion.Explanation = "The failing node no longer exists in the workflow, so there is nothing to fix."
		return suggestion, nil
	}

	failingAction := &workflow.Actions[actionIndex]
	suggestion.NodeLabel = failingAction.Label

	failingResult := ""
	failingStatus := ""
	for _, result := range execution.Results {
		if result.Action.ID == nodeId {
			failingResult = result.Result
			failingStatus = result.Status
			break
		}
	}

	if len(failingResult) == 0 {
		log.Printf("[INFO][%s] No result for node %s in execution. Using the notification text as the error for the AI fix", executionId, nodeId)
		failingResult = notification.FailureReason
		if len(failingResult) == 0 {
			failingResult = notification.Description
		}
	}

	// Node parameters the LLM may see and edit
	editableParams := []MinimalParameter{}
	for _, param := range failingAction.Parameters {
		if isNotificationFixProtectedParam(param) {
			continue
		}

		editableParams = append(editableParams, MinimalParameter{Name: param.Name, Value: param.Value})
	}

	// Data the failing node references: $exec and $<label> of upstream nodes
	referencedData := map[string]string{}
	for _, param := range editableParams {
		for _, match := range notificationFixVariableRegex.FindAllStringSubmatch(param.Value, -1) {
			ref := strings.ToLower(match[1])
			if _, ok := referencedData[ref]; ok {
				continue
			}

			if ref == "exec" {
				referencedData[ref] = truncateForFix(execution.ExecutionArgument, 3000)
				continue
			}

			for _, result := range execution.Results {
				resultLabel := strings.ToLower(strings.ReplaceAll(result.Action.Label, " ", "_"))
				if resultLabel == ref && result.Action.ID != nodeId {
					referencedData[ref] = truncateForFix(result.Result, 3000)
					break
				}
			}
		}
	}

	// Everything the failing node could reference, so the AI can spot values that were meant to be variables
	availableVariables := describeNotificationFixFields("$exec", execution.ExecutionArgument)
	for _, upstreamId := range getNotificationFixUpstreamIds(workflow, nodeId) {
		for _, result := range execution.Results {
			if result.Action.ID == upstreamId {
				label := strings.ToLower(strings.ReplaceAll(result.Action.Label, " ", "_"))
				availableVariables = append(availableVariables, describeNotificationFixFields("$"+label, result.Result)...)
				break
			}
		}
	}

	// Names only: values can be secrets
	for _, variable := range workflow.WorkflowVariables {
		availableVariables = append(availableVariables, fmt.Sprintf("$%s (workflow variable)", variable.Name))
	}

	for _, variable := range workflow.ExecutionVariables {
		availableVariables = append(availableVariables, fmt.Sprintf("$%s (execution variable)", variable.Name))
	}

	if debug {
		referencedKeys := []string{}
		for key := range referencedData {
			referencedKeys = append(referencedKeys, key)
		}

		log.Printf("[DEBUG][%s] AI fix context for node '%s' (%s): status %s, %d editable params, %d protected, referenced data: %v, %d available variables", executionId, failingAction.Label, nodeId, failingStatus, len(editableParams), len(failingAction.Parameters)-len(editableParams), referencedKeys, len(availableVariables))
	}

	failingNode := map[string]interface{}{
		"id":         failingAction.ID,
		"label":      failingAction.Label,
		"app_name":   failingAction.AppName,
		"action":     failingAction.Name,
		"parameters": editableParams,
	}

	failingNodeJson, _ := json.MarshalIndent(failingNode, "", "  ")
	referencedJson, _ := json.MarshalIndent(referencedData, "", "  ")

	workflowOverview := []string{}
	for _, action := range workflow.Actions {
		workflowOverview = append(workflowOverview, fmt.Sprintf("- %s (app: %s, action: %s)", action.Label, action.AppName, action.Name))
	}

	// Inefficient because returns full value not just the edit.
	systemMessage := `You fix a single failing node in a Shuffle workflow. Shuffle is a security automation platform where each node runs an app action with parameters.

Variable syntax inside parameter values:
- $exec.field references the workflow's input data (the trigger payload).
- $node_label.field references the output of an earlier node. Labels are lowercase with spaces replaced by underscores.
- Shuffle replaces these variables with raw text BEFORE the node runs.
- Text without a leading $ is never replaced. For example r'''batch_id''' in Python is just the string "batch_id".
- Only the variables listed under "Available variables" exist when this node runs.
- For the "Shuffle Tools" execute_python action, the "code" parameter is Python 3. Output is whatever is printed; print JSON to pass structured data on.

Your job: from the node's parameters, the error it produced and the available data, find the root cause and fix every bug in this node that would make it fail or produce wrong data. The error only shows the first problem: Python stops at the first syntax error, so check the whole parameter value for more.

Rules:
- Only change parameters of the failing node that are listed in its parameters. Never invent new parameter names.
- For each change, return the COMPLETE new value of that parameter, not a diff. Keep everything you are not fixing byte-for-byte identical.
- Check every variable reference against "Available variables". Fix references that don't exist (typos like $exec.bah_id) and literal values that were clearly meant to be a variable (a bare batch_id where $exec.batch_id exists).
- Only fix what is broken. Don't refactor, rename, or restyle working code.
- If the failure can't be fixed by editing this node's parameters (bad input data, wrong credentials, external service down, missing permissions, rate limits), set "fixable" to false and explain what the user should do instead.

Respond ONLY with a JSON object, no markdown:
{
  "fixable": true,
  "explanation": "Plain text, at most 4 short sentences: what was wrong and what the change does.",
  "changes": [
    { "parameter": "<existing parameter name>", "value": "<complete new value>" }
  ]
}`

	userMessage := fmt.Sprintf(`Workflow "%s" nodes:
%s

Failing node:
%s

Node status: %s
Node output / error:
%s

Available variables for this node:
%s

Data referenced by the node (truncated):
%s`,
		workflow.Name,
		strings.Join(workflowOverview, "\n"),
		string(failingNodeJson),
		failingStatus,
		truncateForFix(failingResult, 4000),
		strings.Join(availableVariables, "\n"),
		string(referencedJson),
	)

	aiResponse := struct {
		Fixable     bool   `json:"fixable"`
		Explanation string `json:"explanation"`
		Changes     []struct {
			Parameter string `json:"parameter"`
			Value     string `json:"value"`
		} `json:"changes"`
	}{}

	callInfo := AiCallInfo{
		Caller: "GenerateNotificationFix",
		OrgID:  user.ActiveOrg.Id,
	}

	var parseErr error
	for attempt := 0; attempt < 2; attempt++ {
		currentUserMessage := userMessage
		if attempt > 0 {
			currentUserMessage += "\n\nIMPORTANT: Your previous answer was not valid JSON. Return ONLY the JSON object."
		}

		output, err := RunAiQuery(ctx, callInfo, systemMessage, currentUserMessage)
		if err != nil {
			log.Printf("[ERROR][%s] AI request failed for notification fix %s: %s", executionId, notification.Id, err)
			return nil, fmt.Errorf("AI request failed: %s", err)
		}

		parseErr = json.Unmarshal([]byte(strings.TrimSpace(FixContentOutput(output))), &aiResponse)
		if parseErr == nil {
			break
		}

		log.Printf("[WARNING][%s] Invalid JSON from AI for notification fix %s (attempt %d): %s", executionId, notification.Id, attempt+1, parseErr)
	}

	if parseErr != nil {
		log.Printf("[ERROR][%s] AI returned invalid JSON for notification fix %s after retries: %s", executionId, notification.Id, parseErr)
		return nil, errors.New("AI returned an invalid response. Please try again.")
	}

	suggestion.Explanation = strings.TrimSpace(aiResponse.Explanation)
	if !aiResponse.Fixable {
		log.Printf("[INFO][%s] AI marked node '%s' (%s) as not fixable: %s", executionId, failingAction.Label, nodeId, suggestion.Explanation)
		return suggestion, nil
	}

	// Validate: only existing, unprotected params on the failing node, with an actual change
	seen := []string{}
	for _, change := range aiResponse.Changes {
		paramIndex := -1
		for i, param := range failingAction.Parameters {
			if strings.EqualFold(param.Name, change.Parameter) {
				paramIndex = i
				break
			}
		}

		dropReason := ""
		switch {
		case paramIndex == -1:
			dropReason = "parameter doesn't exist on the node"
		case isNotificationFixProtectedParam(failingAction.Parameters[paramIndex]):
			dropReason = "parameter is protected (auth or secret)"
		case failingAction.Parameters[paramIndex].Value == change.Value:
			dropReason = "value is unchanged"
		case ArrayContains(seen, failingAction.Parameters[paramIndex].Name):
			dropReason = "parameter was already changed"
		}

		if len(dropReason) > 0 {
			log.Printf("[WARNING][%s] Dropped AI change to parameter '%s' on node '%s' (%s): %s", executionId, change.Parameter, failingAction.Label, nodeId, dropReason)
			continue
		}

		param := failingAction.Parameters[paramIndex]
		seen = append(seen, param.Name)
		suggestion.Changes = append(suggestion.Changes, NotificationFixChange{
			NodeId:    failingAction.ID,
			NodeLabel: failingAction.Label,
			Parameter: param.Name,
			Before:    param.Value,
			After:     change.Value,
		})
	}

	suggestion.Fixable = len(suggestion.Changes) > 0
	if !suggestion.Fixable && len(suggestion.Explanation) == 0 {
		suggestion.Explanation = "The AI couldn't find a safe change to fix this node."
	}

	log.Printf("[INFO][%s] AI fix for node '%s' (%s): accepted %d of %d proposed change(s)", executionId, failingAction.Label, nodeId, len(suggestion.Changes), len(aiResponse.Changes))

	return suggestion, nil
}

// Applies a suggestion to the stored workflow. Refuses if any touched parameter changed since the suggestion was made.
func ApplyNotificationFix(ctx context.Context, user User, suggestion NotificationFixSuggestion) (*Workflow, *WorkflowOperation, error) {
	if !suggestion.Fixable || len(suggestion.Changes) == 0 {
		return nil, nil, errors.New("this suggestion has no changes to apply")
	}

	// Always from the DB, never the agent's draft cache
	workflow, err := GetWorkflow(ctx, suggestion.WorkflowId)
	if err != nil || workflow == nil || len(workflow.ID) == 0 {
		log.Printf("[ERROR] Failed loading workflow %s to apply AI fix for notification %s: %v", suggestion.WorkflowId, suggestion.NotificationId, err)
		return nil, nil, errors.New("workflow not found")
	}

	if workflow.OrgId != user.ActiveOrg.Id {
		log.Printf("[AUDIT] User %s (%s) in org %s denied applying AI fix to workflow %s of org %s", user.Username, user.Id, user.ActiveOrg.Id, workflow.ID, workflow.OrgId)
		return nil, nil, errors.New("workflow does not belong to your organization")
	}

	actionIndex := findActionIndexByID(workflow, suggestion.NodeId)
	if actionIndex == -1 {
		return nil, nil, fmt.Errorf("the node no longer exists in the workflow: %w", errNotificationFixStale)
	}

	updates := MinimalAction{Parameters: []MinimalParameter{}}
	for _, change := range suggestion.Changes {
		if change.NodeId != suggestion.NodeId {
			log.Printf("[WARNING] AI fix for notification %s targets node %s but suggestion node is %s. Refusing", suggestion.NotificationId, change.NodeId, suggestion.NodeId)
			return nil, nil, errors.New("suggestion touches an unexpected node")
		}

		found := false
		for _, param := range workflow.Actions[actionIndex].Parameters {
			if param.Name != change.Parameter {
				continue
			}

			if param.Value != change.Before {
				return nil, nil, fmt.Errorf("parameter '%s': %w", change.Parameter, errNotificationFixStale)
			}

			found = true
			break
		}

		if !found {
			return nil, nil, fmt.Errorf("parameter '%s' no longer exists: %w", change.Parameter, errNotificationFixStale)
		}

		updates.Parameters = append(updates.Parameters, MinimalParameter{Name: change.Parameter, Value: change.After})
	}

	// Keep the pre-fix state as a revision so the fix can be reverted
	if err := SetWorkflowRevision(ctx, *workflow); err != nil {
		log.Printf("[WARNING] Failed saving pre-fix revision for workflow %s: %s", workflow.ID, err)
	}

	data, err := json.Marshal(updates)
	if err != nil {
		return nil, nil, err
	}

	op := WorkflowOperation{Op: "edit_node", ID: suggestion.NodeId, Data: data}
	if err := opEditNode(workflow, &op); err != nil {
		log.Printf("[ERROR] Failed editing node %s in workflow %s for AI fix: %s", suggestion.NodeId, workflow.ID, err)
		return nil, nil, err
	}

	if err := SetWorkflow(ctx, *workflow, workflow.ID); err != nil {
		log.Printf("[ERROR] Failed saving workflow %s after AI fix for notification %s: %s", workflow.ID, suggestion.NotificationId, err)
		return nil, nil, fmt.Errorf("failed saving workflow: %s", err)
	}

	go func(savedWorkflow Workflow) {
		if err := SetWorkflowRevision(context.Background(), savedWorkflow); err != nil {
			log.Printf("[WARNING] Failed saving post-fix revision for workflow %s: %s", savedWorkflow.ID, err)
		}
	}(*workflow)

	return workflow, &op, nil
}

// Returns the notification from /api/v1/notifications/{id}/fix[/apply] if the user may access it
func getNotificationForFix(resp http.ResponseWriter, request *http.Request) (User, *Notification, bool) {
	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in notification fix: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return user, nil, false
	}

	if user.Role == "org-reader" {
		log.Printf("[WARNING] Org-reader doesn't have access to notification fix: %s (%s)", user.Username, user.Id)
		resp.WriteHeader(403)
		resp.Write([]byte(`{"success": false, "reason": "Read only user"}`))
		return user, nil, false
	}

	location := strings.Split(request.URL.Path, "/")
	if len(location) < 6 || len(location[4]) != 36 {
		log.Printf("[WARNING] Badly formatted notification ID in notification fix path: %s", request.URL.Path)
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false, "reason": "Badly formatted notification ID"}`))
		return user, nil, false
	}

	ctx := GetContext(request)
	notification, err := GetNotification(ctx, location[4])
	if err != nil {
		log.Printf("[WARNING] Failed getting notification %s for fix: %s", location[4], err)
	} else if notification.OrgId != user.ActiveOrg.Id || (notification.Personal && notification.UserId != user.Id) {
		log.Printf("[AUDIT] User %s (%s) in org %s denied access to notification %s of org %s for fix", user.Username, user.Id, user.ActiveOrg.Id, notification.Id, notification.OrgId)
	}

	if err != nil || notification.OrgId != user.ActiveOrg.Id || (notification.Personal && notification.UserId != user.Id) {
		resp.WriteHeader(404)
		resp.Write([]byte(`{"success": false, "reason": "Notification not found"}`))
		return user, nil, false
	}

	return user, notification, true
}

// Mirrors the cloud AI limit in HandleEditWorkflowWithLLM. On-prem the AI provider (or cloud sync) enforces its own limits.
func notificationFixLimitReached(ctx context.Context, orgId string) bool {
	if project.Environment != "cloud" {
		return false
	}

	usage := int64(0)
	if orgStats, err := GetOrgStatistics(ctx, orgId); err == nil && orgStats != nil {
		usage = orgStats.MonthlyAIUsage
	}

	if cacheData, err := GetCache(ctx, fmt.Sprintf("cache_%s_ai_executions", orgId)); err == nil {
		if byteData, ok := cacheData.([]uint8); ok {
			if parsed, err := strconv.ParseInt(string(byteData), 16, 64); err == nil {
				usage += parsed
			}
		}
	}

	limit := int64(100)
	if org, err := GetOrg(ctx, orgId); err == nil && org != nil && org.SyncFeatures.ShuffleGPT.Limit > 0 {
		limit = org.SyncFeatures.ShuffleGPT.Limit
	}

	if usage >= limit {
		log.Printf("[AUDIT] Org %s has exceeded its AI limit for notification fixes (%d/%d)", orgId, usage, limit)
		return true
	}

	return false
}

// POST /api/v1/notifications/{id}/fix (?refresh=true regenerates). GET only returns a cached suggestion.
func HandleGetNotificationFix(resp http.ResponseWriter, request *http.Request) {
	if HandleCors(resp, request) {
		return
	}

	user, notification, ok := getNotificationForFix(resp, request)
	if !ok {
		return
	}

	if !IsNotificationAiFixable(*notification) {
		log.Printf("[INFO] Notification %s (origin '%s', title '%s') isn't AI fixable", notification.Id, notification.Origin, notification.Title)
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false, "reason": "This notification type can't be fixed with AI"}`))
		return
	}

	ctx := GetContext(request)
	if request.URL.Query().Get("refresh") != "true" {
		if cached, err := getNotificationFixCache(ctx, notification.Id, getNotificationFixExecutionId(*notification)); err == nil {
			if debug {
				log.Printf("[DEBUG] Returning cached AI fix for notification %s (applied: %t)", notification.Id, cached.Applied)
			}

			data, _ := json.Marshal(cached)
			resp.WriteHeader(200)
			resp.Write(data)
			return
		}
	}

	// GET only reads the cache: the UI calls it when a card loads to show "Fix applied" without an AI call.
	// Backends without the GET route answer 405, so mixed versions never generate on page load.
	if request.Method == "GET" {
		resp.WriteHeader(200)
		resp.Write([]byte(`{"success": false, "cached": false, "reason": "No suggestion generated yet"}`))
		return
	}

	if notificationFixLimitReached(ctx, user.ActiveOrg.Id) {
		resp.WriteHeader(429)
		resp.Write([]byte(`{"success": false, "reason": "You have exceeded your monthly AI limit. Contact support@shuffler.io if you need more credits."}`))
		return
	}

	startTime := time.Now()
	suggestion, err := GenerateNotificationFix(ctx, user, *notification)
	if err != nil {
		log.Printf("[WARNING] Failed generating fix for notification %s in org %s: %s", notification.Id, user.ActiveOrg.Id, err)
		reason, _ := json.Marshal(err.Error())
		resp.WriteHeader(500)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": %s}`, reason)))
		return
	}

	if project.Environment == "cloud" {
		IncrementCache(ctx, user.ActiveOrg.Id, "ai_executions", 1)
	}

	if err := setNotificationFixCache(ctx, *suggestion); err != nil {
		log.Printf("[WARNING] Failed caching fix for notification %s: %s", notification.Id, err)
	}

	log.Printf("[AUDIT] Generated AI fix for notification %s (workflow %s, node %s) for user %s (%s) in %s. Fixable: %t, changes: %d", notification.Id, suggestion.WorkflowId, suggestion.NodeId, user.Username, user.Id, time.Since(startTime).Round(time.Millisecond), suggestion.Fixable, len(suggestion.Changes))

	data, _ := json.Marshal(suggestion)
	resp.WriteHeader(200)
	resp.Write(data)
}

// POST /api/v1/notifications/{id}/fix/apply
func HandleApplyNotificationFix(resp http.ResponseWriter, request *http.Request) {
	if HandleCors(resp, request) {
		return
	}

	user, notification, ok := getNotificationForFix(resp, request)
	if !ok {
		return
	}

	// The suggestion the user reviewed. Apply refuses anything else.
	applyRequest := struct {
		SuggestionId string `json:"suggestion_id"`
	}{}

	body, err := ioutil.ReadAll(io.LimitReader(request.Body, 1<<20))
	if err == nil && len(body) > 0 {
		if err := json.Unmarshal(body, &applyRequest); err != nil {
			log.Printf("[WARNING] Invalid body when applying AI fix for notification %s: %s", notification.Id, err)
		}
	}

	ctx := GetContext(request)
	suggestion, err := getNotificationFixCache(ctx, notification.Id, getNotificationFixExecutionId(*notification))
	if err != nil {
		// Expired, backend restarted, or a newer failure reopened the notification
		log.Printf("[INFO] No current AI fix to apply for notification %s: %s", notification.Id, err)
		resp.WriteHeader(409)
		resp.Write([]byte(`{"success": false, "reason": "This suggestion is no longer current.", "replaced": true}`))
		return
	}

	if len(applyRequest.SuggestionId) == 0 || applyRequest.SuggestionId != suggestion.SuggestionId {
		log.Printf("[INFO] AI fix for notification %s: apply for suggestion %q but current is %q. Refusing", notification.Id, applyRequest.SuggestionId, suggestion.SuggestionId)
		resp.WriteHeader(409)
		resp.Write([]byte(`{"success": false, "reason": "This suggestion was replaced by a newer one.", "replaced": true}`))
		return
	}

	if suggestion.Applied {
		log.Printf("[INFO] AI fix for notification %s was already applied. Refusing to apply again", notification.Id)
		resp.WriteHeader(409)
		resp.Write([]byte(`{"success": false, "reason": "This fix has already been applied"}`))
		return
	}

	workflow, op, err := ApplyNotificationFix(ctx, user, *suggestion)
	if err != nil {
		// Stale is expected (the node was edited after the suggestion) and makes the UI regenerate
		if errors.Is(err, errNotificationFixStale) {
			log.Printf("[INFO] AI fix for notification %s is stale: %s", notification.Id, err)
		} else {
			log.Printf("[ERROR] Failed applying AI fix for notification %s: %s", notification.Id, err)
		}

		reason, _ := json.Marshal(err.Error())
		resp.WriteHeader(409)
		resp.Write([]byte(fmt.Sprintf(`{"success": false, "reason": %s, "stale": %t}`, reason, errors.Is(err, errNotificationFixStale))))
		return
	}

	suggestion.Applied = true
	if err := setNotificationFixCache(ctx, *suggestion); err != nil {
		log.Printf("[WARNING] Failed marking AI fix for notification %s as applied in cache: %s", notification.Id, err)
	}

	notification.ModifiedBy = user.Username
	if err := markNotificationRead(ctx, notification); err != nil {
		log.Printf("[WARNING] Failed marking notification %s read after fix: %s", notification.Id, err)
	}

	log.Printf("[AUDIT] Applied AI fix for notification %s to workflow %s node %s by user %s (%s)", notification.Id, workflow.ID, suggestion.NodeId, user.Username, user.Id)

	resp.WriteHeader(200)
	resp.Write([]byte(fmt.Sprintf(`{"success": true, "workflow_id": "%s", "execution_id": "%s"}`, workflow.ID, suggestion.ExecutionId)))

	// Live-update open editors. The stream endpoint only accepts header auth, so session users get their apikey forwarded.
	streamRequest := request.Clone(context.Background())
	if len(streamRequest.Header.Get("Authorization")) == 0 && len(user.ApiKey) > 0 {
		streamRequest.Header.Set("Authorization", fmt.Sprintf("Bearer %s", user.ApiKey))
	}

	streamOps := collectStreamOps(workflow, op, map[string]string{}, len(workflow.Branches), nil)
	if debug {
		log.Printf("[DEBUG] Streaming %d op(s) for workflow %s after AI fix", len(streamOps), workflow.ID)
	}

	go streamWorkflowOperations(context.Background(), streamRequest, workflow.ID, streamOps)
}
