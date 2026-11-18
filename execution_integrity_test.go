package shuffle

import (
	"context"
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
