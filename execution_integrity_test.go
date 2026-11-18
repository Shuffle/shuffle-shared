package shuffle

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestAgentDecisionsComplete(t *testing.T) {
	empty := AgentOutput{}
	if agentDecisionsComplete(empty, nil) {
		t.Fatal("an empty decision set must never be treated as complete")
	}

	oneDecision := AgentOutput{
		Decisions: []AgentDecision{
			{RunDetails: AgentDecisionRunDetails{Id: "one"}},
		},
	}

	if agentDecisionsComplete(oneDecision, nil) {
		t.Fatal("a decision set with no finished decisions must not be complete")
	}

	if !agentDecisionsComplete(oneDecision, []string{"one"}) {
		t.Fatal("a decision set whose decisions are all finished must be complete")
	}
}

func TestAgentResultBlocksFinish(t *testing.T) {
	agentAction := Action{AppName: "AI Agent", ID: "agent-action"}
	regularAction := Action{AppName: "execute_python", ID: "regular-action"}

	tests := []struct {
		name     string
		result   ActionResult
		expected bool
	}{
		{
			name:     "regular action is never inspected",
			result:   ActionResult{Action: regularAction, Status: "WAITING"},
			expected: false,
		},
		{
			name:     "regular action named agent is not treated as an AI Agent",
			result:   ActionResult{Action: Action{AppName: "execute_python", Name: "agent"}, Status: "WAITING", Result: `{"status":"RUNNING"}`},
			expected: false,
		},
		{
			name:     "shuffle-ai is treated as an AI Agent",
			result:   ActionResult{Action: Action{AppName: "shuffle-ai", Name: "run_agent"}, Status: "WAITING", Result: `{"status":"RUNNING"}`},
			expected: true,
		},
		{
			name:     "waiting agent with the RUNNING stub blocks completion",
			result:   ActionResult{Action: agentAction, Status: "WAITING", Result: `{"status":"RUNNING"}`},
			expected: true,
		},
		{
			name:     "successful agent with a finished output can complete",
			result:   ActionResult{Action: agentAction, Status: "SUCCESS", Result: `{"status":"FINISHED","decisions":[]}`},
			expected: false,
		},
		{
			name:     "waiting agent with a finished output can complete",
			result:   ActionResult{Action: agentAction, Status: "WAITING", Result: `{"status":"FINISHED","decisions":[]}`},
			expected: false,
		},
		{
			name:     "failed agent result blocks completion",
			result:   ActionResult{Action: agentAction, Status: "FAILURE", Result: `{"status":"FINISHED","decisions":[]}`},
			expected: true,
		},
		{
			name:     "successful agent with a RUNNING output blocks completion",
			result:   ActionResult{Action: agentAction, Status: "SUCCESS", Result: `{"status":"RUNNING","decisions":[]}`},
			expected: true,
		},
		{
			name:     "offload placeholder does not block completion",
			result:   ActionResult{Action: agentAction, Status: "SUCCESS", Result: `{"reason":"Result too large to handle (https://github.com/frikky/shuffle/issues/171).","id":"execution-id_agent-action"}`},
			expected: false,
		},
		{
			name:     "offload placeholder on a waiting agent blocks completion",
			result:   ActionResult{Action: agentAction, Status: "WAITING", Result: `{"reason":"Result too large to handle (https://github.com/frikky/shuffle/issues/171).","id":"execution-id_agent-action"}`},
			expected: true,
		},
		{
			name:     "agent is recognized by action name when app name is missing",
			result:   ActionResult{Action: Action{Name: "agent"}, Status: "WAITING", Result: `{"status":"RUNNING"}`},
			expected: true,
		},
		{
			name:     "skipped agent does not block completion",
			result:   ActionResult{Action: agentAction, Status: "SKIPPED", Result: `{"status":"RUNNING"}`},
			expected: false,
		},
		{
			name:     "empty agent result blocks completion",
			result:   ActionResult{Action: agentAction, Status: "SUCCESS", Result: ""},
			expected: true,
		},
		{
			name:     "malformed agent result blocks completion",
			result:   ActionResult{Action: agentAction, Status: "SUCCESS", Result: "not-json"},
			expected: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if actual := agentResultBlocksFinish(test.result); actual != test.expected {
				t.Fatalf("expected %t, got %t", test.expected, actual)
			}
		})
	}
}

func withLocalOffloadStorage(t *testing.T) string {
	t.Helper()

	previousProject := project
	previousFileLocation, hadFileLocation := os.LookupEnv("SHUFFLE_FILE_LOCATION")

	tempDir := t.TempDir()
	project.DbType = "opensearch"
	project.CacheDb = false
	os.Setenv("SHUFFLE_FILE_LOCATION", tempDir)

	t.Cleanup(func() {
		project = previousProject
		if hadFileLocation {
			os.Setenv("SHUFFLE_FILE_LOCATION", previousFileLocation)
		} else {
			os.Unsetenv("SHUFFLE_FILE_LOCATION")
		}
	})

	return tempDir
}

func writeOffloadFile(t *testing.T, basePath, orgId, executionId, actionId, contents string) {
	t.Helper()

	dirPath := filepath.Join(basePath, "large_executions", orgId)
	if err := os.MkdirAll(dirPath, 0755); err != nil {
		t.Fatalf("failed creating offload directory: %s", err)
	}

	filePath := filepath.Join(dirPath, executionId+"_"+actionId)
	if err := os.WriteFile(filePath, []byte(contents), 0644); err != nil {
		t.Fatalf("failed writing offload file: %s", err)
	}
}

func TestRehydrateExecutionValues(t *testing.T) {
	basePath := withLocalOffloadStorage(t)

	const (
		orgId       = "org-id"
		executionId = "execution-id"
		actionId    = "agent-action"
	)
	agentOutput := `{"status":"FINISHED","decisions":[{"action":"finish"}]}`
	writeOffloadFile(t, basePath, orgId, executionId, actionId, agentOutput)

	placeholder := `{"success":false,"reason":"Result too large to handle (https://github.com/frikky/shuffle/issues/171).","id":"execution-id_agent-action"}`
	execution := WorkflowExecution{
		ExecutionId:  executionId,
		ExecutionOrg: orgId,
		Results: []ActionResult{
			{
				Action: Action{ID: actionId, AppName: "AI Agent"},
				Result: placeholder,
			},
		},
	}

	rehydrateExecutionValues(context.Background(), &execution)

	if execution.Results[0].Result != agentOutput {
		t.Fatalf("expected the offloaded result to be rehydrated, got %q", execution.Results[0].Result)
	}
}

func TestRehydrateExecutionValuesLeavesInlineResultsAlone(t *testing.T) {
	withLocalOffloadStorage(t)

	execution := WorkflowExecution{
		ExecutionId: "execution-id",
		Results: []ActionResult{
			{
				Action: Action{ID: "action-id", AppName: "execute_python"},
				Result: `{"success":true}`,
			},
		},
	}

	rehydrateExecutionValues(context.Background(), &execution)

	if execution.Results[0].Result != `{"success":true}` {
		t.Fatalf("inline results must not be modified, got %q", execution.Results[0].Result)
	}
}

func TestLoadAgentOutputFromOffload(t *testing.T) {
	basePath := withLocalOffloadStorage(t)

	const (
		orgId       = "org-id"
		executionId = "execution-id"
		actionId    = "agent-action"
	)
	agentOutput := `{"status":"FINISHED","decisions":[{"action":"finish"}]}`
	writeOffloadFile(t, basePath, orgId, executionId, actionId, agentOutput)

	execution := WorkflowExecution{
		ExecutionId:  executionId,
		ExecutionOrg: orgId,
	}

	output, rawValue, err := loadAgentOutputFromOffload(context.Background(), execution, Action{ID: actionId, AppName: "AI Agent"})
	if err != nil {
		t.Fatalf("expected the offload file to be readable: %s", err)
	}

	if rawValue != agentOutput {
		t.Fatalf("expected raw value %q, got %q", agentOutput, rawValue)
	}

	if output.Status != "FINISHED" {
		t.Fatalf("expected recovered status FINISHED, got %q", output.Status)
	}

	if len(output.Decisions) != 1 {
		t.Fatalf("expected 1 recovered decision, got %d", len(output.Decisions))
	}
}

func TestFixexecutionKeepsOffloadedAgentResult(t *testing.T) {
	previousProject := project
	project.CacheDb = false
	project.DbType = ""
	t.Cleanup(func() {
		project = previousProject
	})

	placeholder := `{"success":false,"reason":"Result too large to handle (https://github.com/frikky/shuffle/issues/171).","size":2814376,"extra":"replace","id":"execution-id_agent-action"}`
	execution := WorkflowExecution{
		ExecutionId: "execution-id",
		Status:      "EXECUTING",
		Workflow: Workflow{
			ID:      "workflow-id",
			Actions: []Action{{ID: "agent-action", Name: "agent", AppName: "AI Agent"}},
		},
		Results: []ActionResult{
			{
				Action: Action{ID: "agent-action", Name: "agent", AppName: "AI Agent"},
				Status: "WAITING",
				Result: placeholder,
			},
		},
	}

	fixed, _ := Fixexecution(context.Background(), execution)

	if fixed.Results[0].Result != placeholder {
		t.Fatalf("an offloaded agent result must not be replaced by Fixexecution, got %q", fixed.Results[0].Result)
	}

	if fixed.Results[0].Status != "WAITING" {
		t.Fatalf("expected the agent result to stay WAITING, got %q", fixed.Results[0].Status)
	}
}

func TestLoadAgentOutputFromOffloadMissingFile(t *testing.T) {
	withLocalOffloadStorage(t)

	execution := WorkflowExecution{
		ExecutionId:  "execution-id",
		ExecutionOrg: "org-id",
	}

	if _, _, err := loadAgentOutputFromOffload(context.Background(), execution, Action{ID: "missing-action", AppName: "AI Agent"}); err == nil {
		t.Fatal("expected an error for a missing offload file")
	}
}

func TestFixexecutionDoesNotFinishUnfinishedAgent(t *testing.T) {
	previousProject := project
	project.CacheDb = false
	project.DbType = ""
	t.Cleanup(func() {
		project = previousProject
	})

	agentAction := Action{ID: "agent-action", Name: "agent", AppName: "AI Agent"}

	tests := []struct {
		name           string
		resultStatus   string
		result         string
		expectedStatus string
	}{
		{
			name:           "running agent output must not finish the execution",
			resultStatus:   "SUCCESS",
			result:         `{"status":"RUNNING","decisions":[]}`,
			expectedStatus: "ABORTED",
		},
		{
			name:           "empty agent output must not finish the execution",
			resultStatus:   "SUCCESS",
			result:         "",
			expectedStatus: "ABORTED",
		},
		{
			name:           "malformed agent output must not finish the execution",
			resultStatus:   "SUCCESS",
			result:         "not-json",
			expectedStatus: "ABORTED",
		},
		{
			name:           "finished agent output may finish the execution",
			resultStatus:   "SUCCESS",
			result:         `{"status":"FINISHED","decisions":[]}`,
			expectedStatus: "FINISHED",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			execution := WorkflowExecution{
				ExecutionId: "execution-id",
				Status:      "EXECUTING",
				Workflow: Workflow{
					ID:      "workflow-id",
					Actions: []Action{agentAction},
				},
				Results: []ActionResult{
					{Action: agentAction, Status: test.resultStatus, Result: test.result},
				},
			}

			fixed, _ := Fixexecution(context.Background(), execution)
			if fixed.Status != test.expectedStatus {
				t.Fatalf("expected execution status %q, got %q", test.expectedStatus, fixed.Status)
			}

			if test.expectedStatus == "ABORTED" && fixed.Results[0].Status != "FAILURE" {
				t.Fatalf("expected the invalid agent result to be marked FAILURE, got %q", fixed.Results[0].Status)
			}
		})
	}
}

func TestMarkAgentResultFailure(t *testing.T) {
	execution := WorkflowExecution{
		ExecutionId: "execution-id",
		Results: []ActionResult{
			{
				Action: Action{ID: "agent-action", AppName: "AI Agent"},
				Status: "WAITING",
				Result: `{"status":"RUNNING"}`,
			},
		},
	}

	failed := markAgentResultFailure(execution, 0, "decision lost")
	if failed.Results[0].Status != "FAILURE" {
		t.Fatalf("expected FAILURE, got %q", failed.Results[0].Status)
	}

	output := AgentOutput{}
	if err := json.Unmarshal([]byte(failed.Results[0].Result), &output); err != nil {
		t.Fatalf("failed parsing failed agent output: %s", err)
	}

	if output.Status != "FAILURE" {
		t.Fatalf("expected agent output status FAILURE, got %q", output.Status)
	}

	if output.Error != "decision lost" {
		t.Fatalf("expected error message to be preserved, got %q", output.Error)
	}

	if failed.Results[0].CompletedAt == 0 {
		t.Fatal("expected CompletedAt to be set")
	}
}

func TestRehydrateExecutionValuesRespectsBudget(t *testing.T) {
	basePath := withLocalOffloadStorage(t)

	const (
		orgId       = "org-id"
		executionId = "execution-id"
	)
	firstValue := "first-offloaded-value"
	secondValue := "second-offloaded-value"
	writeOffloadFile(t, basePath, orgId, executionId, "action-one", firstValue)
	writeOffloadFile(t, basePath, orgId, executionId, "action-two", secondValue)

	firstPlaceholder := `{"reason":"Result too large to handle (https://github.com/frikky/shuffle/issues/171).","size":21}`
	secondPlaceholder := `{"reason":"Result too large to handle (https://github.com/frikky/shuffle/issues/171).","size":22}`
	execution := WorkflowExecution{
		ExecutionId:  executionId,
		ExecutionOrg: orgId,
		Results: []ActionResult{
			{Action: Action{ID: "action-one"}, Result: firstPlaceholder},
			{Action: Action{ID: "action-two"}, Result: secondPlaceholder},
		},
	}

	budget := int64(30)
	rehydrateExecutionValuesWithLimit(context.Background(), &execution, &budget)

	if execution.Results[0].Result != firstValue {
		t.Fatalf("expected the first value to be rehydrated, got %q", execution.Results[0].Result)
	}

	if execution.Results[1].Result != secondPlaceholder {
		t.Fatalf("expected the second value to keep its placeholder, got %q", execution.Results[1].Result)
	}

	// The second value is larger than the remaining budget and must not be read.
	if budget != 9 {
		t.Fatalf("expected 9 bytes of remaining budget, got %d", budget)
	}
}

func TestRehydrateExecutionValuesSkipsValueLargerThanBudget(t *testing.T) {
	basePath := withLocalOffloadStorage(t)

	const (
		orgId       = "org-id"
		executionId = "execution-id"
	)
	writeOffloadFile(t, basePath, orgId, executionId, "large-action", "a-large-offloaded-value")

	placeholder := `{"reason":"Result too large to handle (https://github.com/frikky/shuffle/issues/171).","size":100}`
	execution := WorkflowExecution{
		ExecutionId:  executionId,
		ExecutionOrg: orgId,
		Results: []ActionResult{
			{Action: Action{ID: "large-action"}, Result: placeholder},
		},
	}

	budget := int64(10)
	rehydrateExecutionValuesWithLimit(context.Background(), &execution, &budget)

	if execution.Results[0].Result != placeholder {
		t.Fatalf("expected a value larger than the budget to keep its placeholder, got %q", execution.Results[0].Result)
	}

	if budget != 10 {
		t.Fatalf("expected the budget to be untouched, got %d", budget)
	}
}

func TestGetWorkflowQueueEnvironment(t *testing.T) {
	previousEnvironment := project.Environment
	t.Cleanup(func() {
		project.Environment = previousEnvironment
	})

	project.Environment = "onprem"
	if actual := getWorkflowQueueEnvironment("My_Env Name", "org-id"); actual != "my_env-name" {
		t.Fatalf("on-prem queue environment = %q, want %q", actual, "my_env-name")
	}

	project.Environment = "cloud"
	if actual := getWorkflowQueueEnvironment("My_Env Name", "org-id"); actual != "my-env-name_org-id" {
		t.Fatalf("cloud queue environment = %q, want %q", actual, "my-env-name_org-id")
	}
}
