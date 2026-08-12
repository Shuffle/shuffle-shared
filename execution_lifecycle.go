package shuffle

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"

	"github.com/shuffle/opensearch-go/v4/opensearchapi"
)

// ErrExecutionArchived is returned by SetWorkflowExecution when a write
// targets an execution_id that has already been moved to the OpenSearch
// archive. Archived executions are immutable; callers (e.g. the /rerun and force-continue HTTP handlers)
// should turn this into a clean, non-500 response instead of retrying or failing loudly.
var ErrExecutionArchived = errors.New("execution has been archived and can no longer be modified")

const (
	defaultExecutionGracePeriod        = time.Hour
	defaultExecutionArchiveSweepPeriod = 30 * time.Minute
)

// isTerminalExecutionStatus reports whether a WorkflowExecution.Status value
// represents a finished run. Terminal executions are eligible for archival
// once they've sat in the live index for longer than getExecutionGracePeriod().
func isTerminalExecutionStatus(status string) bool {
	switch status {
	case "FINISHED", "ABORTED", "FAILURE":
		return true
	default:
		return false
	}
}

// liveExecutionBaseIndex is the base index name (before GetESIndexPrefix) for
// the small, non-rolling, keyed index that holds in-flight and
// recently-terminal executions. All execution writes target this index.
func liveExecutionBaseIndex() string {
	return "workflowexecution_live"
}

// archiveExecutionBaseIndex is the base index name for the existing
// "workflowexecution" alias, repurposed as an append-only, rollover-managed
// archive for confirmed-terminal executions.
func archiveExecutionBaseIndex() string {
	return "workflowexecution"
}

// getExecutionGracePeriod returns how long a terminal execution stays in the
// live index before becoming eligible for archival. Configurable via
// OPENSEARCH_EXECUTION_GRACE_PERIOD (Go duration string, e.g. "1h", "90m").
// Falls back to the 1h default on missing or invalid input.
func getExecutionGracePeriod() time.Duration {
	raw := strings.TrimSpace(os.Getenv("OPENSEARCH_EXECUTION_GRACE_PERIOD"))
	if raw == "" {
		return defaultExecutionGracePeriod
	}

	parsed, err := time.ParseDuration(raw)
	if err != nil {
		log.Printf("[WARNING] Invalid OPENSEARCH_EXECUTION_GRACE_PERIOD %q, using default %s: %s", raw, defaultExecutionGracePeriod, err)
		return defaultExecutionGracePeriod
	}

	return parsed
}

// getExecutionArchiveSweepInterval returns how often the background archival
// sweep runs. Configurable via OPENSEARCH_EXECUTION_ARCHIVE_SWEEP_INTERVAL.
// Falls back to the 30m default on missing or invalid input.
func getExecutionArchiveSweepInterval() time.Duration {
	raw := strings.TrimSpace(os.Getenv("OPENSEARCH_EXECUTION_ARCHIVE_SWEEP_INTERVAL"))
	if raw == "" {
		return defaultExecutionArchiveSweepPeriod
	}

	parsed, err := time.ParseDuration(raw)
	if err != nil {
		log.Printf("[WARNING] Invalid OPENSEARCH_EXECUTION_ARCHIVE_SWEEP_INTERVAL %q, using default %s: %s", raw, defaultExecutionArchiveSweepPeriod, err)
		return defaultExecutionArchiveSweepPeriod
	}

	return parsed
}

func init() {
	if mapping, ok := opensearchCoreMappings["workflowexecution"]; ok {
		opensearchCoreMappings["workflowexecution_live"] = mapping
	}
}

// resolveExecutionWriteTarget decides which base index a write for a given
// execution should target, and whether that write must also clean up an
// existing archive copy (unarchive). archiveStatusLookup returns
// (status, true) if the execution already exists in the archive, or
// ("", false) if it doesn't.
//
// Every new/live execution writes to live. An execution already archived
// only blocks the write if BOTH the archive copy and the incoming write are
// terminal (a duplicate/late re-affirmation of an already-finished
// execution) - that's rejected with ErrExecutionArchived. If the archive
// copy is terminal but the incoming write is non-terminal, this is a
// legitimate reopen (async decision-fixup race, or a slower recovery/
// failover path that fires after the grace window) - unarchive is
// signaled so the caller moves the doc back to live instead of leaving two
// diverging copies or writing into the (supposed to be append-only) archive.
func resolveExecutionWriteTarget(incomingStatus string, archiveStatusLookup func() (status string, found bool)) (targetIndex string, unarchive bool, err error) {
	_, found := archiveStatusLookup()
	if !found {
		return liveExecutionBaseIndex(), false, nil
	}

	if isTerminalExecutionStatus(incomingStatus) {
		return "", false, ErrExecutionArchived
	}

	return liveExecutionBaseIndex(), true, nil
}

// findExecutionInArchive searches the archive alias for a doc with this
// execution_id, returning the concrete backing index and status of the newest
// matching generation if found.
func findExecutionInArchive(ctx context.Context, aliasName, executionId string) (index string, status string, found bool) {
	var buf bytes.Buffer
	query := map[string]interface{}{
		"size": 1,
		"query": map[string]interface{}{
			"ids": map[string]interface{}{
				"values": []string{executionId},
			},
		},
		"sort": []map[string]interface{}{
			{
				"edited": map[string]interface{}{
					"order":         "desc",
					"unmapped_type": "long",
				},
			},
			{
				"created": map[string]interface{}{
					"order":         "desc",
					"unmapped_type": "long",
				},
			},
		},
	}
	if err := json.NewEncoder(&buf).Encode(query); err != nil {
		return "", "", false
	}

	resp, err := project.Es.Search(ctx, &opensearchapi.SearchReq{
		Indices: []string{aliasName},
		Body:    &buf,
		Params: opensearchapi.SearchParams{
			TrackTotalHits: true,
		},
	})
	if err != nil {
		return "", "", false
	}

	res := resp.Inspect().Response
	defer res.Body.Close()
	if res.StatusCode == 404 {
		return "", "", false
	}

	respBody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", "", false
	}

	wrapped := ExecutionSearchWrapper{}
	if err := json.Unmarshal(respBody, &wrapped); err != nil || len(wrapped.Hits.Hits) == 0 {
		return "", "", false
	}

	top := wrapped.Hits.Hits[0]
	return top.Index, top.Source.Status, true
}

// deleteExecutionFromArchiveIndex removes a single execution document from a
// concrete archive backing index (not the alias).
func deleteExecutionFromArchiveIndex(ctx context.Context, concreteIndex, executionId string) error {
	resp, err := project.Es.Document.Delete(ctx, opensearchapi.DocumentDeleteReq{
		Index:      concreteIndex,
		DocumentID: executionId,
	})
	if err != nil {
		return err
	}

	res := resp.Inspect().Response
	defer res.Body.Close()
	if res.StatusCode != 200 && res.StatusCode != 404 {
		respBody, _ := ioutil.ReadAll(res.Body)
		return fmt.Errorf("failed deleting %s from archive index %s: status=%d body=%s", executionId, concreteIndex, res.StatusCode, string(respBody))
	}

	return nil
}

// writeExecutionDocument is the single choke point for persisting a
// WorkflowExecution document to OpenSearch. It always targets the live index
// unless the execution is already archived and the incoming write is itself
// terminal (rejected with ErrExecutionArchived); if the execution is
// archived but the incoming write is non-terminal, the doc is unarchived
// (written to live, then removed from the archive) before returning.
func writeExecutionDocument(ctx context.Context, executionId string, incomingStatus string, data []byte) error {
	archiveAlias := strings.ToLower(GetESIndexPrefix(archiveExecutionBaseIndex()))
	archiveIndex, archiveStatus, archiveFound := findExecutionInArchive(ctx, archiveAlias, executionId)

	target, unarchive, err := resolveExecutionWriteTarget(incomingStatus, func() (string, bool) {
		return archiveStatus, archiveFound
	})
	if err != nil {
		return err
	}

	if err := indexEs(ctx, target, executionId, data); err != nil {
		return err
	}

	if unarchive {
		if delErr := deleteExecutionFromArchiveIndex(ctx, archiveIndex, executionId); delErr != nil {
			log.Printf("[WARNING][%s] Unarchived execution to live but failed to remove stale archive copy from %s: %s", executionId, archiveIndex, delErr)
		}
	}

	return nil
}

// getExecutionDocumentWithLookups tries liveLookup first; if it errors, falls
// back to archiveLookup. Factored out from getExecutionDocument so the
// try-live-then-archive control flow is unit-testable without a live
// OpenSearch cluster.
func getExecutionDocumentWithLookups(liveLookup, archiveLookup func() (*WorkflowExecution, error)) (*WorkflowExecution, error) {
	exec, err := liveLookup()
	if err == nil {
		return exec, nil
	}

	return archiveLookup()
}

// getExecutionDocument fetches a single WorkflowExecution by id, checking the
// live index first and falling back to the archive alias for executions that
// have already been archived.
func getExecutionDocument(ctx context.Context, executionId string) (*WorkflowExecution, error) {
	liveLookup := func() (*WorkflowExecution, error) {
		resp, err := project.Es.Document.Get(ctx, opensearchapi.DocumentGetReq{
			Index:      strings.ToLower(GetESIndexPrefix(liveExecutionBaseIndex())),
			DocumentID: executionId,
		})
		if err != nil {
			return nil, err
		}

		res := resp.Inspect().Response
		defer res.Body.Close()
		if res.StatusCode == 404 {
			return nil, errors.New("execution doesn't exist in live index")
		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return nil, err
		}

		wrapped := ExecWrapper{}
		if err := json.Unmarshal(respBody, &wrapped); err != nil || !wrapped.Found {
			return nil, errors.New("execution not found in live index")
		}

		return &wrapped.Source, nil
	}

	archiveLookup := func() (*WorkflowExecution, error) {
		resp, err := project.Es.Document.Get(ctx, opensearchapi.DocumentGetReq{
			Index:      strings.ToLower(GetESIndexPrefix(archiveExecutionBaseIndex())),
			DocumentID: executionId,
		})
		if err != nil {
			if strings.Contains(err.Error(), "has more than one index associated with it") {
				return getWorkflowExecutionByAliasSearch(ctx, strings.ToLower(GetESIndexPrefix(archiveExecutionBaseIndex())), executionId)
			}
			return nil, err
		}

		res := resp.Inspect().Response
		defer res.Body.Close()
		if res.StatusCode == 404 {
			return nil, errors.New("execution doesn't exist")
		}

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return nil, err
		}

		wrapped := ExecWrapper{}
		if err := json.Unmarshal(respBody, &wrapped); err != nil || !wrapped.Found {
			return nil, errors.New("execution not found in archive")
		}

		return &wrapped.Source, nil
	}

	return getExecutionDocumentWithLookups(liveLookup, archiveLookup)
}

// executionSearchIndices returns the list of concrete index/alias names that
// execution list/history queries should search across.
func executionSearchIndices() []string {
	return []string{
		strings.ToLower(GetESIndexPrefix(liveExecutionBaseIndex())),
		strings.ToLower(GetESIndexPrefix(archiveExecutionBaseIndex())),
	}
}

// dedupExecutionsByID collapses a result set that may contain more than one
// doc for the same execution_id down to one entry per execution_id, keeping
// whichever looks newest.
func dedupExecutionsByID(executions []WorkflowExecution) []WorkflowExecution {
	newest := map[string]WorkflowExecution{}
	order := []string{}

	for _, exec := range executions {
		existing, found := newest[exec.ExecutionId]
		if !found {
			newest[exec.ExecutionId] = exec
			order = append(order, exec.ExecutionId)
			continue
		}

		existingTs := existing.CompletedAt
		if existingTs == 0 {
			existingTs = existing.StartedAt
		}
		candidateTs := exec.CompletedAt
		if candidateTs == 0 {
			candidateTs = exec.StartedAt
		}

		if candidateTs > existingTs {
			newest[exec.ExecutionId] = exec
		}
	}

	deduped := make([]WorkflowExecution, 0, len(order))
	for _, id := range order {
		deduped = append(deduped, newest[id])
	}

	return deduped
}

// buildArchivalSweepQuery builds the OpenSearch query body for finding
// executions in the live index that are eligible for archival.
func buildArchivalSweepQuery(now time.Time, grace time.Duration) map[string]interface{} {
	cutoff := now.Add(-grace).Unix()

	return map[string]interface{}{
		"size": 1000,
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": []map[string]interface{}{
					{
						"terms": map[string]interface{}{
							"status": []string{"FINISHED", "ABORTED", "FAILURE"},
						},
					},
					{
						"range": map[string]interface{}{
							"completed_at": map[string]interface{}{
								"lt": cutoff,
							},
						},
					},
				},
			},
		},
	}
}

// resolveArchiveWriteTarget decides where an archive write for a given
// execution_id should go.
func resolveArchiveWriteTarget(aliasName string, existingLookup func() (index string, found bool)) (target string, isAlias bool) {
	if existingIndex, found := existingLookup(); found {
		return existingIndex, false
	}

	return aliasName, true
}

// archiveExecutionDocument writes an execution document into the archive,
// idempotently.
func archiveExecutionDocument(ctx context.Context, executionId string, data []byte) error {
	aliasName := strings.ToLower(GetESIndexPrefix(archiveExecutionBaseIndex()))

	target, isAlias := resolveArchiveWriteTarget(aliasName, func() (string, bool) {
		index, _, found := findExecutionInArchive(ctx, aliasName, executionId)
		return index, found
	})

	if isAlias {
		return indexEs(ctx, archiveExecutionBaseIndex(), executionId, data)
	}

	_, err := project.Es.Index(ctx, opensearchapi.IndexReq{
		Index:      target,
		DocumentID: executionId,
		Body:       bytes.NewReader(data),
		Params: opensearchapi.IndexParams{
			Refresh: "true",
		},
	})
	return err
}

// sweepArchivableExecutions finds executions in the live index that have
// been terminal for longer than getExecutionGracePeriod(), copies each into
// the archive, and deletes it from live.
func sweepArchivableExecutions(ctx context.Context) error {
	const lockKey = "opensearch_execution_sweep_lock"
	if _, err := GetCache(ctx, lockKey); err == nil {
		log.Printf("[DEBUG] Execution archival sweep already in progress elsewhere, skipping this pass")
		return nil
	}
	_ = SetCache(ctx, lockKey, []byte("1"), 300)

	query := buildArchivalSweepQuery(time.Now(), getExecutionGracePeriod())

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(query); err != nil {
		return err
	}

	resp, err := project.Es.Search(ctx, &opensearchapi.SearchReq{
		Indices: []string{strings.ToLower(GetESIndexPrefix(liveExecutionBaseIndex()))},
		Body:    &buf,
	})
	if err != nil {
		if strings.Contains(err.Error(), "index_not_found_exception") {
			return nil
		}
		return err
	}

	res := resp.Inspect().Response
	defer res.Body.Close()
	if res.StatusCode == 404 {
		return nil
	}

	respBody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}

	wrapped := ExecutionSearchWrapper{}
	if err := json.Unmarshal(respBody, &wrapped); err != nil {
		return err
	}

	archived := 0
	for _, hit := range wrapped.Hits.Hits {
		data, err := json.Marshal(hit.Source)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling execution %s for archival: %s", hit.Source.ExecutionId, err)
			continue
		}

		if err := archiveExecutionDocument(ctx, hit.Source.ExecutionId, data); err != nil {
			log.Printf("[WARNING] Failed archiving execution %s: %s", hit.Source.ExecutionId, err)
			continue
		}

		if err := DeleteKey(ctx, liveExecutionBaseIndex(), hit.Source.ExecutionId); err != nil {
			log.Printf("[WARNING] Archived execution %s but failed deleting it from live index: %s", hit.Source.ExecutionId, err)
			continue
		}

		archived++
	}

	if archived > 0 {
		log.Printf("[INFO] Archived %d terminal executions from live to archive index", archived)
	}

	return nil
}

// StartExecutionArchivalSweeper runs sweepArchivableExecutions on a ticker at
// getExecutionArchiveSweepInterval().
func StartExecutionArchivalSweeper(ctx context.Context) {
	if project.DbType != "opensearch" {
		return
	}

	interval := getExecutionArchiveSweepInterval()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := sweepArchivableExecutions(ctx); err != nil {
				log.Printf("[WARNING] Execution archival sweep failed: %s", err)
			}
		}
	}
}

// buildInFlightExecutionsQuery builds the query used by the one-time startup
// migration to find non-terminal executions in the legacy/archive index that
// need to move to the new live index.
func buildInFlightExecutionsQuery() map[string]interface{} {
	return map[string]interface{}{
		"size": 1000,
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": []map[string]interface{}{
					{
						"terms": map[string]interface{}{
							"status": []string{"EXECUTING", "WAITING"},
						},
					},
				},
			},
		},
	}
}

// migrateInFlightExecutionsToLive is a one-time startup migration for
// existing deployments.
func migrateInFlightExecutionsToLive(ctx context.Context) error {
	const lockKey = "opensearch_execution_migration_lock"
	if _, err := GetCache(ctx, lockKey); err == nil {
		log.Printf("[DEBUG] In-flight execution migration already in progress elsewhere, skipping")
		return nil
	}
	_ = SetCache(ctx, lockKey, []byte("1"), 600)

	query := buildInFlightExecutionsQuery()

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(query); err != nil {
		return err
	}

	resp, err := project.Es.Search(ctx, &opensearchapi.SearchReq{
		Indices: []string{strings.ToLower(GetESIndexPrefix(archiveExecutionBaseIndex()))},
		Body:    &buf,
	})
	if err != nil {
		if strings.Contains(err.Error(), "index_not_found_exception") {
			return nil
		}
		return err
	}

	res := resp.Inspect().Response
	defer res.Body.Close()
	if res.StatusCode == 404 {
		return nil
	}

	respBody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}

	wrapped := ExecutionSearchWrapper{}
	if err := json.Unmarshal(respBody, &wrapped); err != nil {
		return err
	}

	migrated := 0
	for _, hit := range wrapped.Hits.Hits {
		data, err := json.Marshal(hit.Source)
		if err != nil {
			log.Printf("[WARNING] Failed marshalling execution %s for live migration: %s", hit.Source.ExecutionId, err)
			continue
		}

		if err := indexEs(ctx, liveExecutionBaseIndex(), hit.Source.ExecutionId, data); err != nil {
			log.Printf("[WARNING] Failed migrating execution %s to live index: %s", hit.Source.ExecutionId, err)
			continue
		}

		if err := deleteExecutionFromArchiveIndex(ctx, hit.Index, hit.Source.ExecutionId); err != nil {
			log.Printf("[WARNING] Migrated execution %s to live but failed deleting legacy copy from %s: %s", hit.Source.ExecutionId, hit.Index, err)
			continue
		}

		migrated++
	}

	if migrated > 0 {
		log.Printf("[INFO] Migrated %d in-flight executions from legacy index to workflowexecution_live", migrated)
	}

	return nil
}
