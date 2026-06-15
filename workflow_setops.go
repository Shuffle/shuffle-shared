package shuffle

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
)


func generateNodeID() string {
	return uuid.New().String()
}

func createCondition(sourceVal, conditionVal, destVal string) Condition {
	return Condition{
		Source: WorkflowAppActionParameter{
			ID:      generateNodeID(),
			Name:    "source",
			Variant: "STATIC_VALUE",
			Value:   sourceVal,
		},
		Condition: WorkflowAppActionParameter{
			ID:    generateNodeID(),
			Name:  "condition",
			Value: conditionVal,
		},
		Destination: WorkflowAppActionParameter{
			ID:      generateNodeID(),
			Name:    "destination",
			Variant: "STATIC_VALUE",
			Value:   destVal,
		},
	}
}


func findAppByID(ctx context.Context, appID string, user User) (*WorkflowApp, error) {
	if len(appID) == 0 {
		return nil, fmt.Errorf("app_id is required")
	}

	standalone := os.Getenv("STANDALONE") == "true"
	if standalone {
		app, _, err := GetAppSingul("", appID)
		return app, err
	}

	app, err := GetApp(ctx, appID, user, false)
	return app, err
}


func enrichActionFromApp(ctx context.Context, minAct *MinimalAction, realApp *WorkflowApp, environment string) (Action, error) {
	if len(realApp.Actions) == 0 {
		return Action{}, fmt.Errorf("app %s has no actions defined", realApp.Name)
	}

	// Select action: if agent specified a name, use it; otherwise prefer "custom_action"; fallback to first
	var appAction WorkflowAppAction
	if minAct.Name != "" {
		found := false
		for _, act := range realApp.Actions {
			if strings.EqualFold(act.Name, minAct.Name) {
				appAction = act
				found = true
				break
			}
		}
		if !found {
			return Action{}, fmt.Errorf("action %s not found in app %s (available: %s)", minAct.Name, realApp.Name, getActionNames(realApp.Actions))
		}
	} else {
		found := false
		for _, act := range realApp.Actions {
			if act.Name == "custom_action" {
				appAction = act
				found = true
				break
			}
		}
		if !found {
			// Fallback to first action
			appAction = realApp.Actions[0]
		}
	}

	actionParams := make([]WorkflowAppActionParameter, len(appAction.Parameters))
	copy(actionParams, appAction.Parameters)

	for i, appParam := range actionParams {
		for _, agentParam := range minAct.Parameters {
			if strings.EqualFold(appParam.Name, agentParam.Name) {
				actionParams[i].Value = agentParam.Value
				break
			}
		}
	}

	newAction := Action{
		ID:           generateNodeID(),
		AppName:      realApp.Name,
		AppID:        realApp.ID,
		AppVersion:   realApp.AppVersion,
		Name:         appAction.Name,
		Label:        minAct.Label,
		Description:  realApp.Description,
		Parameters:   actionParams,
		LargeImage:   realApp.LargeImage,
		SmallImage:   realApp.SmallImage,
		Environment:  environment,
		IsValid:      realApp.IsValid,
		Public:       realApp.Public,
		Generated:    realApp.Generated,
		ReferenceUrl: realApp.ReferenceUrl,
		Position: Position{
			X: float64(minAct.X),
			Y: float64(minAct.Y),
		},
	}

	return newAction, nil
}

func enrichTriggerFromApp(minTrig *MinimalTrigger, environment string) (Trigger, error) {
	appNameLower := strings.ToLower(strings.TrimSpace(minTrig.AppName))

	switch appNameLower {
	case "webhook":
		webhookImage := GetTriggerData("Webhook")
		ID := generateNodeID()
		webhookURL := fmt.Sprintf("https://shuffler.io/api/v1/hooks/webhook_%s", ID)

		if project.Environment != "cloud" {
			if len(os.Getenv("BASE_URL")) > 0 {
				webhookURL = fmt.Sprintf("%s/api/v1/hooks/webhook_%s", os.Getenv("BASE_URL"), ID)
			} else if len(os.Getenv("SHUFFLE_CLOUDRUN_URL")) > 0 {
				webhookURL = fmt.Sprintf("%s/api/v1/hooks/webhook_%s", os.Getenv("SHUFFLE_CLOUDRUN_URL"), ID)
			} else {
				port := os.Getenv("PORT")
				if len(port) == 0 {
					port = "5001"
				}
				webhookURL = fmt.Sprintf("http://localhost:%s/api/v1/hooks/webhook_%s", port, ID)
			}
		}

		return Trigger{
			AppName:     "Webhook",
			AppVersion:  "1.0.0",
			Label:       minTrig.Label,
			TriggerType: "WEBHOOK",
			ID:          ID,
			Description: "Custom HTTP input trigger",
			LargeImage:  webhookImage,
			Environment: environment,
			Status:      "uninitialized",
			Parameters: []WorkflowAppActionParameter{
				{Name: "url", Value: webhookURL},
				{Name: "tmp", Value: ""},
				{Name: "auth_headers", Value: ""},
				{Name: "custom_response_body", Value: ""},
				{Name: "await_response", Value: "v1"},
			},
			Position: Position{
				X: float64(minTrig.X),
				Y: float64(minTrig.Y),
			},
		}, nil

	case "schedule":
		scheduleImage := GetTriggerData("Schedule")
		scheduleValue := "*/25 * * * *"
		if len(minTrig.Parameters) > 0 && len(minTrig.Parameters[0].Value) > 0 {
			scheduleValue = minTrig.Parameters[0].Value
		}

		return Trigger{
			AppName:     "Schedule",
			AppVersion:  "1.0.0",
			Label:       minTrig.Label,
			TriggerType: "SCHEDULE",
			ID:          generateNodeID(),
			Description: "Schedule time trigger",
			LargeImage:  scheduleImage,
			Environment: environment,
			Status:      "uninitialized",
			Parameters: []WorkflowAppActionParameter{
				{Name: "cron", Value: scheduleValue},
				{Name: "execution_argument", Value: ""},
			},
			Position: Position{
				X: float64(minTrig.X),
				Y: float64(minTrig.Y),
			},
		}, nil

	default:
		return Trigger{}, fmt.Errorf("unsupported trigger type: %s", minTrig.AppName)
	}
}

func broadcastToStream(workflowID string, operation WorkflowOperation, userID string, username string, authHeader string) {
	// Convert SetOps operation to StreamOps format
	item := "node" // default
	switch operation.Op {
	case "add_branch", "edit_branch", "delete_branch":
		item = "branch"
	case "add_condition", "edit_condition", "delete_condition":
		item = "condition"
	}

	if len(userID) == 0 {
		userID = "agent"
	}
	if len(username) == 0 {
		username = "agent"
	}

	streamOp := StreamWorkflowOperation{
		Item:      item,
		Type:      operation.Op,
		ID:        operation.ID,
		UserID:    userID,
		Username:  username,
		Data:      operation.Data,
		Timestamp: time.Now().UnixMilli(),
	}

	// Marshal to JSON
	payload, err := json.Marshal(streamOp)
	if err != nil {
		log.Printf("[WARNING] Failed to marshal stream operation for workflow %s: %s", workflowID, err)
		return
	}

	baseURL := os.Getenv("BASE_URL")
	if len(baseURL) == 0 {
		if len(os.Getenv("SHUFFLE_CLOUDRUN_URL")) > 0 {
			baseURL = os.Getenv("SHUFFLE_CLOUDRUN_URL")
		} else {
			port := os.Getenv("PORT")
			if len(port) == 0 {
				port = "5001"
			}
			baseURL = fmt.Sprintf("http://localhost:%s", port)
		}
	}

	streamURL := fmt.Sprintf("%s/api/v1/workflows/%s/stream", baseURL, workflowID)

	// Create HTTP POST request
	req, err := http.NewRequest("POST", streamURL, strings.NewReader(string(payload)))
	if err != nil {
		log.Printf("[WARNING] Failed to create stream request for workflow %s: %s", workflowID, err)
		return
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	if len(authHeader) > 0 {
		req.Header.Set("Authorization", authHeader)
	}

	// Make request with timeout
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[WARNING] Failed to broadcast to stream for workflow %s: %s", workflowID, err)
		return
	}
	defer resp.Body.Close()

	// Log result
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		log.Printf("[DEBUG] Streamed operation %s to workflow %s", operation.Op, workflowID)
	} else {
		log.Printf("[WARNING] Stream endpoint returned status %d for workflow %s", resp.StatusCode, workflowID)
	}
}

func HandleWorkflowSetOps(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	ctx := GetContext(request)
	user, userErr := HandleApiAuthentication(resp, request)
	if userErr != nil {
		log.Printf("[WARNING] Api authentication failed in HandleWorkflowSetOps: %s", userErr)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Authentication failed"}`))
		return
	}

	if user.Role == "org-reader" {
		log.Printf("[WARNING] Org-reader doesn't have access to modify workflow: %s (%s)", user.Username, user.Id)
		resp.WriteHeader(403)
		resp.Write([]byte(`{"success": false, "reason": "Read only user"}`))
		return
	}

	// Extract workflow ID from URL
	location := strings.Split(request.URL.String(), "/")
	var workflowID string
	if len(location) > 4 && location[1] == "api" {
		workflowID = location[4]
		if strings.Contains(workflowID, "?") {
			workflowID = strings.Split(workflowID, "?")[0]
		}
	}

	if len(workflowID) != 36 {
		log.Printf("[WARNING] Invalid workflow ID: %s", workflowID)
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false, "reason": "Invalid workflow ID"}`))
		return
	}

	// Parse request
	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Printf("[WARNING] Failed reading request body: %s", err)
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false, "reason": "Failed to read request"}`))
		return
	}
	defer request.Body.Close()

	var setOpsReq WorkflowSetOpsRequest
	err = json.Unmarshal(body, &setOpsReq)
	if err != nil {
		log.Printf("[ERROR] Failed unmarshaling request: %s", err)
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false, "reason": "Invalid request format"}`))
		return
	}

	// Validate request
	if setOpsReq.WorkflowID != workflowID {
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false, "reason": "Workflow ID mismatch"}`))
		return
	}

	if len(setOpsReq.Operations) == 0 {
		resp.WriteHeader(400)
		resp.Write([]byte(`{"success": false, "reason": "No operations provided"}`))
		return
	}

	// Get workflow (from cache or DB)
	cacheKey := fmt.Sprintf("workflow_ops_cache_%s_%s", workflowID, user.Id)
	cachedWorkflow, cacheErr := GetCache(ctx, cacheKey)

	var workflow *Workflow
	if cacheErr == nil && cachedWorkflow != nil {
		// Use cached version (agent's draft)
		if byteData, ok := cachedWorkflow.([]byte); ok {
			workflow = &Workflow{}
			err = json.Unmarshal(byteData, workflow)
			if err != nil {
				log.Printf("[WARNING] Failed unmarshaling cached workflow: %s", err)
				workflow = nil
			}
		}
	}

	// Fallback to DB if no cache
	if workflow == nil {
		workflow, err = GetWorkflow(ctx, workflowID)
		if err != nil {
			log.Printf("[WARNING] Failed getting workflow %s: %s", workflowID, err)
			resp.WriteHeader(400)
			resp.Write([]byte(`{"success": false, "reason": "Workflow not found"}`))
			return
		}
	}

	// Check access
	if workflow.OrgId != user.ActiveOrg.Id && workflow.Owner != user.Id {
		log.Printf("[AUDIT] User %s denied access to workflow %s", user.Username, workflowID)
		resp.WriteHeader(403)
		resp.Write([]byte(`{"success": false, "reason": "Access denied"}`))
		return
	}

	// Apply operations (all-or-nothing) with temp ID mapping
	tempIDMap := make(map[string]string) // Maps temp_id → real_id
	for opIndex, operation := range setOpsReq.Operations {
		err = applyWorkflowOperationWithMapping(ctx, user, workflow, &operation, tempIDMap)
		if err != nil {
			errMsg := fmt.Sprintf(`{"success": false, "reason": "Operation %d failed: %s", "failed_at_op": %d}`, opIndex, err.Error(), opIndex)
			log.Printf("[WARNING] Operation %d failed: %s", opIndex, err)
			resp.WriteHeader(400)
			resp.Write([]byte(errMsg))
			return
		}
	}

	// Save to cache (volatile, 30 min TTL)
	workflowBytes, err := json.Marshal(workflow)
	if err != nil {
		log.Printf("[ERROR] Failed marshaling workflow: %s", err)
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false, "reason": "Internal server error"}`))
		return
	}

	cacheErr = SetCache(ctx, cacheKey, workflowBytes, 1800)
	if cacheErr != nil {
		log.Printf("[WARNING] Failed caching workflow: %s", cacheErr)
		// Don't fail the request, cache is best-effort
	}

	// Build response
	minWf := buildMinimalWorkflow(workflow)
	response := WorkflowSetOpsResponse{
		Success:           true,
		WorkflowID:        workflowID,
		Message:           fmt.Sprintf("Applied %d operations successfully", len(setOpsReq.Operations)),
		OperationsApplied: len(setOpsReq.Operations),
		Workflow:          minWf,
		IDMapping:         tempIDMap, // Include temp_id → real_id mappings
		CacheExpiresIn:    1800,
	}

	resp.Header().Set("Content-Type", "application/json")
	resp.WriteHeader(200)
	responseData, _ := json.Marshal(response)
	resp.Write(responseData)

	// Broadcast operations to stream endpoint (agent gets response immediately, streaming happens in background)
	// Extract auth header from incoming request to pass to stream endpoint
	authHeader := request.Header.Get("Authorization")
	for _, operation := range setOpsReq.Operations {
		go broadcastToStream(workflowID, operation, user.Id, user.Username, authHeader)
	}

	if debug{
		log.Printf("[INFO] Applied %d operations to workflow %s for user %s", len(setOpsReq.Operations), workflowID, user.Username)
	}
}


func applyWorkflowOperationWithMapping(ctx context.Context, user User, wf *Workflow, op *WorkflowOperation, tempIDMap map[string]string) error {
	switch op.Op {
	// ====== NODE OPERATIONS ======
	case "add_node":
		return opAddNodeWithMapping(ctx, user, wf, op, tempIDMap)
	case "edit_node":
		return opEditNode(wf, op)
	case "move_node":
		return opMoveNode(wf, op)
	case "delete_node":
		return opDeleteNode(wf, op)

	// ====== BRANCH OPERATIONS ======
	case "add_branch":
		return opAddBranchWithMapping(wf, op, tempIDMap)
	case "edit_branch":
		return opEditBranch(wf, op)
	case "delete_branch":
		return opDeleteBranch(wf, op)

	// ====== CONDITION OPERATIONS ======
	case "add_condition":
		return opAddCondition(wf, op)
	case "edit_condition":
		return opEditCondition(wf, op)
	case "delete_condition":
		return opDeleteCondition(wf, op)

	default:
		return fmt.Errorf("unknown operation: %s", op.Op)
	}
}

func findNodePosition(wf *Workflow, nodeID string) (string, int, error) {
	// Search actions
	for i, act := range wf.Actions {
		if act.ID == nodeID {
			return "action", i, nil
		}
	}
	// Search triggers
	for i, trig := range wf.Triggers {
		if trig.ID == nodeID {
			return "trigger", i, nil
		}
	}
	return "", -1, fmt.Errorf("node %s not found", nodeID)
}


func opAddNodeWithMapping(ctx context.Context, user User, wf *Workflow, op *WorkflowOperation, tempIDMap map[string]string) error {
	err := opAddNode(ctx, user, wf, op)
	if err != nil {
		return err
	}

	// If agent provided a temp_id, track the mapping to the real node ID
	if len(op.TempID) > 0 {
		// Find the node that was just added (should be the last action or trigger)
		if op.NodeType == "action" && len(wf.Actions) > 0 {
			realID := wf.Actions[len(wf.Actions)-1].ID
			tempIDMap[op.TempID] = realID
		} else if op.NodeType == "trigger" && len(wf.Triggers) > 0 {
			realID := wf.Triggers[len(wf.Triggers)-1].ID
			tempIDMap[op.TempID] = realID
		}
	}
	return nil
}

func opAddNode(ctx context.Context, user User, wf *Workflow, op *WorkflowOperation) error {
	switch op.NodeType {
	case "action":
		var minAct MinimalAction
		if err := json.Unmarshal(op.Data, &minAct); err != nil {
			return fmt.Errorf("invalid action data: %w", err)
		}

		if len(minAct.AppID) == 0 {
			return fmt.Errorf("app_id is required in action data")
		}

		realApp, err := findAppByID(ctx, minAct.AppID, user)
		if err != nil {
			return fmt.Errorf("failed to find app %s: %w", minAct.AppID, err)
		}

		newAction, err := enrichActionFromApp(ctx, &minAct, realApp, wf.ExecutingOrg.Id)
		if err != nil {
			return fmt.Errorf("failed to enrich action: %w", err)
		}
        // Commented out parameter validation to allow agents to add new parameters dynamically
		// for _, param := range newAction.Parameters {
		// 	if param.Required && param.Value == "" {
		// 		return fmt.Errorf("required parameter '%s' not provided for action %s", param.Name, realApp.Name)
		// 	}
		// }

		// Should we let the agent specify the position? If not, can we auto-calculate based on existing nodes ??
		newAction.Position = Position{
			X: float64(minAct.X),
			Y: float64(minAct.Y),
		}

		// 4. INSERT at specified location (search both actions AND triggers)
		if op.InsertAfter != "" && op.InsertBefore != "" {
			// Both provided: insert between them
			afterType, afterIdx, afterErr := findNodePosition(wf, op.InsertAfter)
			beforeType, beforeIdx, beforeErr := findNodePosition(wf, op.InsertBefore)
			if afterErr != nil {
				return fmt.Errorf("insert_after node %s not found", op.InsertAfter)
			}
			if beforeErr != nil {
				return fmt.Errorf("insert_before node %s not found", op.InsertBefore)
			}
			// If both are actions, validate order
			if afterType == "action" && beforeType == "action" {
				if afterIdx >= beforeIdx {
					return fmt.Errorf("insert_after node must come before insert_before node in workflow")
				}
				wf.Actions = insertActionAt(wf.Actions, afterIdx+1, newAction)
			} else if afterType == "trigger" {
				// After trigger, before could be trigger or action
				// Insert at beginning of actions array (after all triggers)
				if len(wf.Actions) == 0 {
					wf.Actions = append(wf.Actions, newAction)
				} else {
					wf.Actions = insertActionAt(wf.Actions, 0, newAction)
				}
			} else {
				// Complex case: can't position between action and trigger easily
				return fmt.Errorf("cannot insert between action and trigger - provide consistent node types")
			}
		} else if op.InsertAfter != "" {
			afterType, afterIdx, afterErr := findNodePosition(wf, op.InsertAfter)
			if afterErr != nil {
				return fmt.Errorf("insert_after node %s not found", op.InsertAfter)
			}
			if afterType == "action" {
				wf.Actions = insertActionAt(wf.Actions, afterIdx+1, newAction)
			} else {
				// After trigger, insert at beginning of actions
				if len(wf.Actions) == 0 {
					wf.Actions = append(wf.Actions, newAction)
				} else {
					wf.Actions = insertActionAt(wf.Actions, 0, newAction)
				}
			}
		} else if op.InsertBefore != "" {
			beforeType, beforeIdx, beforeErr := findNodePosition(wf, op.InsertBefore)
			if beforeErr != nil {
				return fmt.Errorf("insert_before node %s not found", op.InsertBefore)
			}
			if beforeType == "action" {
				wf.Actions = insertActionAt(wf.Actions, beforeIdx, newAction)
			} else {
				// Before trigger, insert at beginning
				if len(wf.Actions) == 0 {
					wf.Actions = append(wf.Actions, newAction)
				} else {
					wf.Actions = insertActionAt(wf.Actions, 0, newAction)
				}
			}
		} else {
			// No position hint: append at end
			wf.Actions = append(wf.Actions, newAction)
		}

		return nil

	case "trigger":
		var minTrig MinimalTrigger
		if err := json.Unmarshal(op.Data, &minTrig); err != nil {
			return fmt.Errorf("invalid trigger data: %w", err)
		}

		// 1. ENRICH: Create full Trigger with real structure
		newTrigger, err := enrichTriggerFromApp(&minTrig, wf.ExecutingOrg.Id)
		if err != nil {
			return fmt.Errorf("failed to enrich trigger: %w", err)
		}

		// 2. POSITION
		newTrigger.Position = Position{
			X: float64(minTrig.X),
			Y: float64(minTrig.Y),
		}

		// 3. INSERT at specified location (support insert_after/insert_before for triggers too)
		if op.InsertAfter != "" {
			afterType, afterIdx, afterErr := findNodePosition(wf, op.InsertAfter)
			if afterErr != nil {
				return fmt.Errorf("insert_after node %s not found", op.InsertAfter)
			}
			if afterType == "trigger" {
				wf.Triggers = insertTriggerAt(wf.Triggers, afterIdx+1, newTrigger)
			} else {
				// After action, append to end of triggers (triggers typically first)
				wf.Triggers = append(wf.Triggers, newTrigger)
			}
		} else if op.InsertBefore != "" {
			beforeType, beforeIdx, beforeErr := findNodePosition(wf, op.InsertBefore)
			if beforeErr != nil {
				return fmt.Errorf("insert_before node %s not found", op.InsertBefore)
			}
			if beforeType == "trigger" {
				wf.Triggers = insertTriggerAt(wf.Triggers, beforeIdx, newTrigger)
			} else {
				// Before action, append to triggers (they come first)
				wf.Triggers = append(wf.Triggers, newTrigger)
			}
		} else {
			wf.Triggers = append(wf.Triggers, newTrigger)
		}
		return nil

	default:
		return fmt.Errorf("unknown node_type: %s", op.NodeType)
	}
}

func opEditNode(wf *Workflow, op *WorkflowOperation) error {
	// Auto-detect node type: check if it's an action or trigger
	actidx := findActionIndexByID(wf, op.ID)
	trigidx := findTriggerIndexByID(wf, op.ID)

	if actidx != -1 {
		// It's an action
		var updates MinimalAction
		if err := json.Unmarshal(op.Data, &updates); err != nil {
			return fmt.Errorf("invalid action update data: %w", err)
		}

		// Apply partial updates
		if updates.Label != "" {
			wf.Actions[actidx].Label = updates.Label
		}
		if updates.Name != "" {
			wf.Actions[actidx].Name = updates.Name
		}

		// Merge parameter updates: update existing or add new
		if len(updates.Parameters) > 0 {
			for _, updateParam := range updates.Parameters {
				found := false
				for i := range wf.Actions[actidx].Parameters {
					if strings.EqualFold(wf.Actions[actidx].Parameters[i].Name, updateParam.Name) {
						wf.Actions[actidx].Parameters[i].Value = updateParam.Value
						found = true
						break
					}
				}
				// If parameter not found, add it (allows agent to add new params)
				if !found {
					wf.Actions[actidx].Parameters = append(wf.Actions[actidx].Parameters, WorkflowAppActionParameter{
						ID:    generateNodeID(),
						Name:  updateParam.Name,
						Value: updateParam.Value,
					})
				}
			}
		}
		return nil
	}

	if trigidx != -1 {
		// It's a trigger
		var updates MinimalTrigger
		if err := json.Unmarshal(op.Data, &updates); err != nil {
			return fmt.Errorf("invalid trigger update data: %w", err)
		}

		if updates.Label != "" {
			wf.Triggers[trigidx].Label = updates.Label
		}

		if len(updates.Parameters) > 0 {
			for _, updateParam := range updates.Parameters {
				for i := range wf.Triggers[trigidx].Parameters {
					if strings.EqualFold(wf.Triggers[trigidx].Parameters[i].Name, updateParam.Name) {
						wf.Triggers[trigidx].Parameters[i].Value = updateParam.Value
						break
					}
				}
			}
		}
		return nil
	}

	return fmt.Errorf("node %s not found in workflow (not an action or trigger)", op.ID)
}

func opMoveNode(wf *Workflow, op *WorkflowOperation) error {
	var pos struct {
		X float64 `json:"x"`
		Y float64 `json:"y"`
	}

	if err := json.Unmarshal(op.Data, &pos); err != nil {
		return fmt.Errorf("invalid position data: %w", err)
	}

	// Auto-detect node type: check if it's an action or trigger
	actidx := findActionIndexByID(wf, op.ID)
	if actidx != -1 {
		wf.Actions[actidx].Position = Position{X: pos.X, Y: pos.Y}
		return nil
	}

	trigidx := findTriggerIndexByID(wf, op.ID)
	if trigidx != -1 {
		wf.Triggers[trigidx].Position = Position{X: pos.X, Y: pos.Y}
		return nil
	}

	return fmt.Errorf("node %s not found in workflow (not an action or trigger)", op.ID)
}

func opDeleteNode(wf *Workflow, op *WorkflowOperation) error {
	switch op.NodeType {
	case "action":
		idx := findActionIndexByID(wf, op.ID)
		if idx == -1 {
			return fmt.Errorf("action %s not found", op.ID)
		}

		// Remove action
		wf.Actions = append(wf.Actions[:idx], wf.Actions[idx+1:]...)

		// Remove branches connected to this node
		var newBranches []Branch
		for _, br := range wf.Branches {
			if br.SourceID != op.ID && br.DestinationID != op.ID {
				newBranches = append(newBranches, br)
			}
		}
		wf.Branches = newBranches

	case "trigger":
		idx := findTriggerIndexByID(wf, op.ID)
		if idx == -1 {
			return fmt.Errorf("trigger %s not found", op.ID)
		}

		wf.Triggers = append(wf.Triggers[:idx], wf.Triggers[idx+1:]...)

		// Remove branches connected to this trigger (both source and destination)
		var newBranches []Branch
		for _, br := range wf.Branches {
			if br.SourceID != op.ID && br.DestinationID != op.ID {
				newBranches = append(newBranches, br)
			}
		}
		wf.Branches = newBranches

	default:
		return fmt.Errorf("unknown node_type: %s", op.NodeType)
	}

	return nil
}


func opAddBranchWithMapping(wf *Workflow, op *WorkflowOperation, tempIDMap map[string]string) error {
	var branchData struct {
		SourceID      string `json:"source_id"`
		DestinationID string `json:"destination_id"`
		Label         string `json:"label"`
	}

	if err := json.Unmarshal(op.Data, &branchData); err != nil {
		return fmt.Errorf("invalid branch data: %w", err)
	}

	// Resolve temp_ids to real_ids if provided
	if realID, exists := tempIDMap[branchData.SourceID]; exists {
		branchData.SourceID = realID
	}
	if realID, exists := tempIDMap[branchData.DestinationID]; exists {
		branchData.DestinationID = realID
	}

	// Re-marshal the resolved data back into op.Data for opAddBranch
	resolvedData, _ := json.Marshal(branchData)
	op.Data = resolvedData

	return opAddBranch(wf, op)
}

func opAddBranch(wf *Workflow, op *WorkflowOperation) error {
	var branchData struct {
		SourceID      string `json:"source_id"`
		DestinationID string `json:"destination_id"`
		Label         string `json:"label"`
	}

	if err := json.Unmarshal(op.Data, &branchData); err != nil {
		return fmt.Errorf("invalid branch data: %w", err)
	}

	// Validate both nodes exist
	sourceExists := findActionIndexByID(wf, branchData.SourceID) != -1 || findTriggerIndexByID(wf, branchData.SourceID) != -1
	destExists := findActionIndexByID(wf, branchData.DestinationID) != -1 || findTriggerIndexByID(wf, branchData.DestinationID) != -1

	if !sourceExists {
		return fmt.Errorf("source node %s not found", branchData.SourceID)
	}
	if !destExists {
		return fmt.Errorf("destination node %s not found", branchData.DestinationID)
	}

	newBranch := Branch{
		ID:            generateNodeID(),
		SourceID:      branchData.SourceID,
		DestinationID: branchData.DestinationID,
		Label:         branchData.Label,
		Conditions:    []Condition{},
	}

	// Detect circular references before adding branch
	if hasCircularBranch(wf, newBranch) {
		return fmt.Errorf("circular branch detected: would create loop from %s → %s", branchData.SourceID, branchData.DestinationID)
	}

	wf.Branches = append(wf.Branches, newBranch)
	return nil
}

func opEditBranch(wf *Workflow, op *WorkflowOperation) error {
	var updates struct {
		Label string `json:"label"`
	}

	if err := json.Unmarshal(op.Data, &updates); err != nil {
		return fmt.Errorf("invalid branch update data: %w", err)
	}

	for i, br := range wf.Branches {
		if br.ID == op.ID {
			if updates.Label != "" {
				wf.Branches[i].Label = updates.Label
			}
			return nil
		}
	}

	return fmt.Errorf("branch %s not found", op.ID)
}

func opDeleteBranch(wf *Workflow, op *WorkflowOperation) error {
	for i, br := range wf.Branches {
		if br.ID == op.ID {
			wf.Branches = append(wf.Branches[:i], wf.Branches[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("branch %s not found", op.ID)
}


func opAddCondition(wf *Workflow, op *WorkflowOperation) error {
	var condData struct {
		Source      string `json:"source"`
		Condition   string `json:"condition"`
		Destination string `json:"destination"`
	}

	if err := json.Unmarshal(op.Data, &condData); err != nil {
		return fmt.Errorf("invalid condition data: %w", err)
	}

	branchIdx := findBranchIndexByID(wf, op.BranchID)
	if branchIdx == -1 {
		return fmt.Errorf("branch %s not found", op.BranchID)
	}

	newCond := createCondition(condData.Source, condData.Condition, condData.Destination)
	wf.Branches[branchIdx].Conditions = append(wf.Branches[branchIdx].Conditions, newCond)

	return nil
}

func opEditCondition(wf *Workflow, op *WorkflowOperation) error {
	branchIdx := findBranchIndexByID(wf, op.BranchID)
	if branchIdx == -1 {
		return fmt.Errorf("branch %s not found", op.BranchID)
	}

	if op.ConditionIndex < 0 || op.ConditionIndex >= len(wf.Branches[branchIdx].Conditions) {
		return fmt.Errorf("condition index %d out of range", op.ConditionIndex)
	}

	var condData struct {
		Source      string `json:"source"`
		Condition   string `json:"condition"`
		Destination string `json:"destination"`
	}

	if err := json.Unmarshal(op.Data, &condData); err != nil {
		return fmt.Errorf("invalid condition update data: %w", err)
	}

	wf.Branches[branchIdx].Conditions[op.ConditionIndex] = createCondition(
		condData.Source,
		condData.Condition,
		condData.Destination,
	)

	return nil
}

func opDeleteCondition(wf *Workflow, op *WorkflowOperation) error {
	branchIdx := findBranchIndexByID(wf, op.BranchID)
	if branchIdx == -1 {
		return fmt.Errorf("branch %s not found", op.BranchID)
	}

	if op.ConditionIndex < 0 || op.ConditionIndex >= len(wf.Branches[branchIdx].Conditions) {
		return fmt.Errorf("condition index %d out of range", op.ConditionIndex)
	}

	wf.Branches[branchIdx].Conditions = append(
		wf.Branches[branchIdx].Conditions[:op.ConditionIndex],
		wf.Branches[branchIdx].Conditions[op.ConditionIndex+1:]...,
	)

	return nil
}


func findActionIndexByID(wf *Workflow, id string) int {
	for i, act := range wf.Actions {
		if act.ID == id {
			return i
		}
	}
	return -1
}

func findTriggerIndexByID(wf *Workflow, id string) int {
	for i, trig := range wf.Triggers {
		if trig.ID == id {
			return i
		}
	}
	return -1
}

func findBranchIndexByID(wf *Workflow, id string) int {
	for i, br := range wf.Branches {
		if br.ID == id {
			return i
		}
	}
	return -1
}

func insertActionAt(actions []Action, idx int, action Action) []Action {
	if idx > len(actions) {
		idx = len(actions)
	}
	return append(actions[:idx], append([]Action{action}, actions[idx:]...)...)
}

func insertTriggerAt(triggers []Trigger, idx int, trigger Trigger) []Trigger {
	if idx > len(triggers) {
		idx = len(triggers)
	}
	return append(triggers[:idx], append([]Trigger{trigger}, triggers[idx:]...)...)
}

// getActionNames returns comma-separated list of action names (for error messages)
func getActionNames(actions []WorkflowAppAction) string {
	var names []string
	for _, a := range actions {
		names = append(names, a.Name)
	}
	return strings.Join(names, ", ")
}

// hasCircularBranch detects if adding a new branch would create a cycle
func hasCircularBranch(wf *Workflow, newBranch Branch) bool {
	// Cycle detection: if destination can reach source, adding branch creates loop
	return canReach(wf, newBranch.DestinationID, newBranch.SourceID)
}

// canReach checks if target is reachable from source following existing branches (BFS)
func canReach(wf *Workflow, from, to string) bool {
	if from == to {
		return true
	}

	visited := make(map[string]bool)
	queue := []string{from}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		if visited[current] {
			continue
		}
		visited[current] = true

		if current == to {
			return true
		}

		// Find all outgoing branches from current node
		for _, br := range wf.Branches {
			if br.SourceID == current && !visited[br.DestinationID] {
				queue = append(queue, br.DestinationID)
			}
		}
	}

	return false
}
