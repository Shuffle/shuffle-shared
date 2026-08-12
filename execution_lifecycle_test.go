package shuffle

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestIsTerminalExecutionStatus(t *testing.T) {
	terminal := []string{"FINISHED", "ABORTED", "FAILURE"}
	for _, status := range terminal {
		if !isTerminalExecutionStatus(status) {
			t.Fatalf("expected %s to be terminal", status)
		}
	}

	nonTerminal := []string{"EXECUTING", "WAITING", ""}
	for _, status := range nonTerminal {
		if isTerminalExecutionStatus(status) {
			t.Fatalf("expected %s to be non-terminal", status)
		}
	}
}

func TestExecutionIndexNames(t *testing.T) {
	if liveExecutionBaseIndex() != "workflowexecution_live" {
		t.Fatalf("expected workflowexecution_live, got %s", liveExecutionBaseIndex())
	}
	if archiveExecutionBaseIndex() != "workflowexecution" {
		t.Fatalf("expected workflowexecution, got %s", archiveExecutionBaseIndex())
	}
}

func TestGetExecutionGracePeriodDefault(t *testing.T) {
	os.Unsetenv("OPENSEARCH_EXECUTION_GRACE_PERIOD")
	if got := getExecutionGracePeriod(); got != time.Hour {
		t.Fatalf("expected 1h default, got %s", got)
	}
}

func TestGetExecutionGracePeriodOverride(t *testing.T) {
	os.Setenv("OPENSEARCH_EXECUTION_GRACE_PERIOD", "90m")
	defer os.Unsetenv("OPENSEARCH_EXECUTION_GRACE_PERIOD")

	if got := getExecutionGracePeriod(); got != 90*time.Minute {
		t.Fatalf("expected 90m override, got %s", got)
	}
}

func TestGetExecutionGracePeriodInvalidFallsBackToDefault(t *testing.T) {
	os.Setenv("OPENSEARCH_EXECUTION_GRACE_PERIOD", "not-a-duration")
	defer os.Unsetenv("OPENSEARCH_EXECUTION_GRACE_PERIOD")

	if got := getExecutionGracePeriod(); got != time.Hour {
		t.Fatalf("expected fallback to 1h default on invalid input, got %s", got)
	}
}

func TestGetExecutionArchiveSweepIntervalDefault(t *testing.T) {
	os.Unsetenv("OPENSEARCH_EXECUTION_ARCHIVE_SWEEP_INTERVAL")
	if got := getExecutionArchiveSweepInterval(); got != 30*time.Minute {
		t.Fatalf("expected 30m default, got %s", got)
	}
}

func TestResolveExecutionWriteTarget(t *testing.T) {
	tests := []struct {
		name             string
		incomingStatus   string
		archiveHasStatus string
		wantIndex        string
		wantUnarchive    bool
		wantErr          error
	}{
		{
			name:             "new execution not in archive writes to live",
			incomingStatus:   "EXECUTING",
			archiveHasStatus: "",
			wantIndex:        "workflowexecution_live",
			wantUnarchive:    false,
			wantErr:          nil,
		},
		{
			name:             "terminal write against already-archived terminal execution is rejected",
			incomingStatus:   "FINISHED",
			archiveHasStatus: "FINISHED",
			wantIndex:        "",
			wantUnarchive:    false,
			wantErr:          ErrExecutionArchived,
		},
		{
			name:             "non-terminal write against an already-archived execution triggers unarchive",
			incomingStatus:   "EXECUTING",
			archiveHasStatus: "FINISHED",
			wantIndex:        "workflowexecution_live",
			wantUnarchive:    true,
			wantErr:          nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lookup := func() (string, bool) {
				if tt.archiveHasStatus == "" {
					return "", false
				}
				return tt.archiveHasStatus, true
			}

			index, unarchive, err := resolveExecutionWriteTarget(tt.incomingStatus, lookup)
			if err != tt.wantErr {
				t.Fatalf("expected err %v, got %v", tt.wantErr, err)
			}
			if index != tt.wantIndex {
				t.Fatalf("expected index %s, got %s", tt.wantIndex, index)
			}
			if unarchive != tt.wantUnarchive {
				t.Fatalf("expected unarchive %v, got %v", tt.wantUnarchive, unarchive)
			}
		})
	}
}

func TestGetExecutionDocumentFallsBackToArchive(t *testing.T) {
	liveCalled := false
	archiveCalled := false

	liveLookup := func() (*WorkflowExecution, error) {
		liveCalled = true
		return nil, errors.New("execution doesn't exist")
	}
	archiveLookup := func() (*WorkflowExecution, error) {
		archiveCalled = true
		return &WorkflowExecution{ExecutionId: "abc"}, nil
	}

	exec, err := getExecutionDocumentWithLookups(liveLookup, archiveLookup)
	if err != nil {
		t.Fatalf("expected no error, got %s", err)
	}
	if !liveCalled || !archiveCalled {
		t.Fatalf("expected both live (tried first) and archive (fallback) to be called: live=%v archive=%v", liveCalled, archiveCalled)
	}
	if exec.ExecutionId != "abc" {
		t.Fatalf("expected execution abc, got %s", exec.ExecutionId)
	}
}

func TestGetExecutionDocumentSkipsArchiveWhenLiveFound(t *testing.T) {
	archiveCalled := false

	liveLookup := func() (*WorkflowExecution, error) {
		return &WorkflowExecution{ExecutionId: "live-one"}, nil
	}
	archiveLookup := func() (*WorkflowExecution, error) {
		archiveCalled = true
		return nil, errors.New("should not be called")
	}

	exec, err := getExecutionDocumentWithLookups(liveLookup, archiveLookup)
	if err != nil {
		t.Fatalf("expected no error, got %s", err)
	}
	if archiveCalled {
		t.Fatalf("archive lookup should not be called when live lookup succeeds")
	}
	if exec.ExecutionId != "live-one" {
		t.Fatalf("expected live-one, got %s", exec.ExecutionId)
	}
}

func TestExecutionSearchIndices(t *testing.T) {
	indices := executionSearchIndices()
	want := []string{
		strings.ToLower(GetESIndexPrefix(liveExecutionBaseIndex())),
		strings.ToLower(GetESIndexPrefix(archiveExecutionBaseIndex())),
	}

	if len(indices) != len(want) {
		t.Fatalf("expected %d indices, got %d (%v)", len(want), len(indices), indices)
	}
	for i := range want {
		if indices[i] != want[i] {
			t.Fatalf("expected index[%d]=%s, got %s", i, want[i], indices[i])
		}
	}
}

func TestDedupExecutionsByID(t *testing.T) {
	executions := []WorkflowExecution{
		{ExecutionId: "exec-1", CompletedAt: 100},
		{ExecutionId: "exec-2", CompletedAt: 50},
		{ExecutionId: "exec-1", CompletedAt: 200},
	}

	deduped := dedupExecutionsByID(executions)
	if len(deduped) != 2 {
		t.Fatalf("expected 2 unique executions, got %d", len(deduped))
	}

	byId := map[string]WorkflowExecution{}
	for _, e := range deduped {
		byId[e.ExecutionId] = e
	}

	if byId["exec-1"].CompletedAt != 200 {
		t.Fatalf("expected exec-1 to keep the newest copy (CompletedAt=200), got %d", byId["exec-1"].CompletedAt)
	}
	if byId["exec-2"].CompletedAt != 50 {
		t.Fatalf("expected exec-2 unchanged, got %d", byId["exec-2"].CompletedAt)
	}
}

func TestBuildArchivalSweepQuery(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	grace := time.Hour

	query := buildArchivalSweepQuery(now, grace)

	boolQuery, ok := query["query"].(map[string]interface{})["bool"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected bool query, got %v", query)
	}

	must, ok := boolQuery["must"].([]map[string]interface{})
	if !ok || len(must) != 2 {
		t.Fatalf("expected 2 must clauses (status terms + completed_at range), got %v", must)
	}

	terms, ok := must[0]["terms"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected first clause to be a terms query on status, got %v", must[0])
	}
	statuses, ok := terms["status"].([]string)
	if !ok || len(statuses) != 3 {
		t.Fatalf("expected 3 terminal statuses, got %v", terms["status"])
	}

	rangeQuery, ok := must[1]["range"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected second clause to be a range query on completed_at, got %v", must[1])
	}
	completedAtRange, ok := rangeQuery["completed_at"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected completed_at range, got %v", rangeQuery)
	}

	wantCutoff := now.Add(-grace).Unix()
	if completedAtRange["lt"] != wantCutoff {
		t.Fatalf("expected cutoff %d, got %v", wantCutoff, completedAtRange["lt"])
	}
}

func TestResolveArchiveWriteTarget(t *testing.T) {
	tests := []struct {
		name          string
		existingIndex string
		wantAlias     bool
	}{
		{
			name:          "not yet archived writes via alias",
			existingIndex: "",
			wantAlias:     true,
		},
		{
			name:          "already archived in an older generation writes to that concrete index",
			existingIndex: "shuffle_workflowexecution_000002",
			wantAlias:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lookup := func() (string, bool) {
				if tt.existingIndex == "" {
					return "", false
				}
				return tt.existingIndex, true
			}

			target, isAlias := resolveArchiveWriteTarget("shuffle_workflowexecution", lookup)
			if isAlias != tt.wantAlias {
				t.Fatalf("expected isAlias=%v, got %v (target=%s)", tt.wantAlias, isAlias, target)
			}
			if !tt.wantAlias && target != tt.existingIndex {
				t.Fatalf("expected target %s, got %s", tt.existingIndex, target)
			}
		})
	}
}

func TestBuildInFlightExecutionsQuery(t *testing.T) {
	query := buildInFlightExecutionsQuery()

	boolQuery, ok := query["query"].(map[string]interface{})["bool"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected bool query, got %v", query)
	}

	must, ok := boolQuery["must"].([]map[string]interface{})
	if !ok || len(must) != 1 {
		t.Fatalf("expected 1 must clause (status terms), got %v", must)
	}

	terms, ok := must[0]["terms"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected terms query on status, got %v", must[0])
	}
	statuses, ok := terms["status"].([]string)
	if !ok || len(statuses) != 2 {
		t.Fatalf("expected 2 non-terminal statuses (EXECUTING, WAITING), got %v", terms["status"])
	}
	for _, s := range statuses {
		if s == "FINISHED" || s == "ABORTED" || s == "FAILURE" {
			t.Fatalf("migration query must never select terminal statuses, got %s", s)
		}
	}
}

func TestGetOpensearchRetentionDaysIncludesWorkflowExecution(t *testing.T) {
	os.Unsetenv("OPENSEARCH_INDEX_RETENTION_DAYS")
	if got := getOpensearchRetentionDays("workflowexecution"); got != "365d" {
		t.Fatalf("expected 365d default archive retention, got %q", got)
	}
}

func TestGetOpensearchRetentionDaysOverride(t *testing.T) {
	os.Setenv("OPENSEARCH_INDEX_RETENTION_DAYS", `{"workflowexecution": 180}`)
	defer os.Unsetenv("OPENSEARCH_INDEX_RETENTION_DAYS")

	if got := getOpensearchRetentionDays("workflowexecution"); got != "180d" {
		t.Fatalf("expected 180d override via existing OPENSEARCH_INDEX_RETENTION_DAYS mechanism, got %q", got)
	}
}
