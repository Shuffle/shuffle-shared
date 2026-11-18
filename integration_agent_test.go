//go:build integration

// Run this test against a disposable OpenSearch + Memcached pair:
//
//	SHUFFLE_OPENSEARCH_URL=http://localhost:9200 \
//	SHUFFLE_MEMCACHED=localhost:11211 \
//	go test -tags=integration -vet=off ./ -run TestAgentCompletionAndFailurePersistence
//
// It verifies that an unfinished agent result is not marked FINISHED and that
// an unrecoverable decision callback persists FAILURE without relying on the
// asynchronous agent self-request.

package shuffle

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"cloud.google.com/go/datastore"
	"cloud.google.com/go/storage"
	uuid "github.com/satori/go.uuid"
)

func TestAgentCompletionAndFailurePersistence(t *testing.T) {
	if os.Getenv("SHUFFLE_OPENSEARCH_URL") == "" || os.Getenv("SHUFFLE_MEMCACHED") == "" {
		t.Skip("integration backends not configured")
	}

	previousFileLocation := os.Getenv("SHUFFLE_FILE_LOCATION")
	os.Setenv("SHUFFLE_FILE_LOCATION", t.TempDir())
	os.Setenv("SHUFFLE_DISABLE_AGENT_SELFREQUEST", "true")
	t.Cleanup(func() {
		os.Setenv("SHUFFLE_FILE_LOCATION", previousFileLocation)
		os.Unsetenv("SHUFFLE_DISABLE_AGENT_SELFREQUEST")
	})

	if _, err := RunInit(datastore.Client{}, storage.Client{}, "shuffle-integration", "onprem", true, "opensearch", false, 0); err != nil {
		t.Fatalf("RunInit: %s", err)
	}
	InitOpensearchIndexes()

	ctx := context.Background()
	agentAction := Action{ID: "agent-action-" + uuid.NewV4().String(), Name: "agent", AppName: "AI Agent", Label: "Agent"}
	execution := WorkflowExecution{
		ExecutionId:   uuid.NewV4().String(),
		ExecutionOrg:  uuid.NewV4().String(),
		WorkflowId:    uuid.NewV4().String(),
		Authorization: uuid.NewV4().String(),
		Status:        "EXECUTING",
		Workflow: Workflow{
			ID:      uuid.NewV4().String(),
			Actions: []Action{agentAction},
		},
		Results: []ActionResult{
			{
				Action: agentAction,
				Status: "SUCCESS",
				Result: `{"status":"RUNNING","decisions":[]}`,
			},
		},
	}

	t.Cleanup(func() {
		DeleteKey(context.Background(), "workflowexecution", execution.ExecutionId)
	})

	if err := SetWorkflowExecution(ctx, execution, true); err != nil {
		t.Fatalf("SetWorkflowExecution: %s", err)
	}

	stored, err := GetWorkflowExecution(ctx, execution.ExecutionId, true)
	if err != nil {
		t.Fatalf("GetWorkflowExecution: %s", err)
	}
	if stored.Status == "FINISHED" {
		t.Fatalf("unfinished agent execution was marked FINISHED")
	}

	callback := ActionResult{
		ExecutionId:   execution.ExecutionId,
		Authorization: execution.Authorization,
		Action:        agentAction,
		Status:        "agent_does-not-exist",
		Result:        `{"run_details":{"id":"does-not-exist"}}`,
	}

	if _, _, err := handleAgentDecisionStreamResult(*stored, callback); err == nil {
		t.Fatal("expected an error for an unrecoverable decision")
	}

	stored, err = GetWorkflowExecution(ctx, execution.ExecutionId, true)
	if err != nil {
		t.Fatalf("GetWorkflowExecution after failure: %s", err)
	}
	if len(stored.Results) == 0 {
		t.Fatal("no results after failure")
	}
	if stored.Results[0].Status != "FAILURE" && stored.Status != "ABORTED" && stored.Status != "FAILURE" {
		body, _ := json.Marshal(stored.Results[0])
		t.Fatalf("agent failure was not persisted: execution=%s result=%s", stored.Status, string(body))
	}
}
