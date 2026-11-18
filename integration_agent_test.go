//go:build integration

// Run these tests against a disposable OpenSearch + Memcached pair:
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

func requireIntegrationBackends(t *testing.T) context.Context {
	t.Helper()

	if os.Getenv("SHUFFLE_OPENSEARCH_URL") == "" || os.Getenv("SHUFFLE_MEMCACHED") == "" {
		t.Skip("integration backends not configured")
	}

	if _, err := RunInit(datastore.Client{}, storage.Client{}, "shuffle-integration", "onprem", true, "opensearch", false, 0); err != nil {
		t.Fatalf("RunInit: %s", err)
	}
	InitOpensearchIndexes()

	return context.Background()
}

func TestExecutionCacheBackfillUsesCanonicalKey(t *testing.T) {
	ctx := requireIntegrationBackends(t)

	executionId := uuid.NewV4().String()
	execution := WorkflowExecution{
		ExecutionId:   executionId,
		ExecutionOrg:  uuid.NewV4().String(),
		WorkflowId:    uuid.NewV4().String(),
		Authorization: uuid.NewV4().String(),
		Status:        "EXECUTING",
		Workflow: Workflow{
			ID: uuid.NewV4().String(),
		},
	}

	if err := SetWorkflowExecution(ctx, execution, true); err != nil {
		t.Fatalf("SetWorkflowExecution: %s", err)
	}

	t.Cleanup(func() {
		DeleteKey(context.Background(), "workflowexecution", executionId)
	})

	canonicalKey := "workflowexecution_" + executionId
	DeleteCache(ctx, canonicalKey)
	if _, err := GetCache(ctx, canonicalKey); err == nil {
		t.Fatal("expected the execution cache entry to be deleted")
	}

	if _, err := GetWorkflowExecution(ctx, executionId, true); err != nil {
		t.Fatalf("GetWorkflowExecution: %s", err)
	}

	if _, err := GetCache(ctx, canonicalKey); err != nil {
		t.Fatalf("expected the DB read to backfill %q: %s", canonicalKey, err)
	}

	if _, err := GetCache(ctx, executionId); err == nil {
		t.Fatalf("execution cache was backfilled under the raw id %q", executionId)
	}
}

func TestAgentCompletionAndFailurePersistence(t *testing.T) {
	previousFileLocation := os.Getenv("SHUFFLE_FILE_LOCATION")
	os.Setenv("SHUFFLE_FILE_LOCATION", t.TempDir())
	os.Setenv("SHUFFLE_DISABLE_AGENT_SELFREQUEST", "true")
	t.Cleanup(func() {
		os.Setenv("SHUFFLE_FILE_LOCATION", previousFileLocation)
		os.Unsetenv("SHUFFLE_DISABLE_AGENT_SELFREQUEST")
	})

	ctx := requireIntegrationBackends(t)
	agentAction := Action{ID: "agent-action-" + uuid.NewV4().String(), Name: "agent", AppName: "AI Agent", Label: "Agent"}
	execution := WorkflowExecution{
		ExecutionId:   uuid.NewV4().String(),
		ExecutionOrg:  uuid.NewV4().String(),
		WorkflowId:    uuid.NewV4().String(),
		Authorization: uuid.NewV4().String(),
		Status:        "WAITING",
		Workflow: Workflow{
			ID:      uuid.NewV4().String(),
			Actions: []Action{agentAction},
		},
		Results: []ActionResult{
			{
				Action: agentAction,
				Status: "WAITING",
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
	if stored.Results[0].Status != "FAILURE" {
		body, _ := json.Marshal(stored.Results[0])
		t.Fatalf("agent result failure was not persisted: execution=%s result=%s", stored.Status, string(body))
	}

	if stored.Status != "ABORTED" && stored.Status != "FAILURE" {
		t.Fatalf("agent failure left a non-terminal execution: %s", stored.Status)
	}
}

func TestValidateFinishedDoesNotFinishUnfinishedAgent(t *testing.T) {
	ctx := requireIntegrationBackends(t)

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
				Result: `{"status":"WAITING","decisions":[{"i":1,"action":"ask"}]}`,
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
		t.Fatal("SetWorkflowExecution marked an unfinished agent execution FINISHED")
	}

	if ValidateFinished(ctx, -1, *stored) {
		t.Fatal("ValidateFinished returned true for an unfinished agent execution")
	}

	stored, err = GetWorkflowExecution(ctx, execution.ExecutionId, true)
	if err != nil {
		t.Fatalf("GetWorkflowExecution after ValidateFinished: %s", err)
	}
	if stored.Status == "FINISHED" {
		t.Fatal("ValidateFinished marked an unfinished agent execution FINISHED")
	}
}
