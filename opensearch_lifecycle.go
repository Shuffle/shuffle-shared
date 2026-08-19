// This file contains all OpenSearch index lifecycle management: creation,
// mapping-drift migration, rollover, ISM retention policies, and the
// low-level index/alias/task helpers those flows are built from.
package shuffle

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shuffle/opensearch-go/v4/opensearchapi"
)

// resolveAliasWriteIndex looks up whether the given alias already has a write
// index attached in OpenSearch.
func resolveAliasWriteIndex(aliasInfo map[string]map[string]opensearchAliasState, alias string) (writeIndex string, found bool) {
	for indexName, aliases := range aliasInfo {
		if state, ok := aliases[alias]; ok && state.Present && state.IsWriteIndex {
			return indexName, true
		}
	}

	return "", false
}

// resolveAppendIndexCreationTarget decides which concrete backing index the
// create-loop in InitOpensearchIndices should target for a given append
// (rollover) base index: either a brand new "-000001" generation (if none
// exists yet) or the highest existing generation (if the index has already
// been created/rolled/collapsed before).
//
// existingIndices is the full list of real index names currently in the
// cluster (from getOpensearchIndices).
func resolveAppendIndexCreationTarget(existingIndices []string, index string) (target string, alreadyExists bool) {
	prefix := index + "-"
	highestGen := -1
	highestName := ""

	for _, name := range existingIndices {
		if !strings.HasPrefix(name, prefix) {
			continue
		}

		gen := getOpensearchGeneration(name)
		if gen <= 0 {
			continue
		}
		if gen > highestGen {
			highestGen = gen
			highestName = name
		}
	}

	if highestName == "" {
		return fmt.Sprintf("%s-000001", index), false
	}

	return highestName, true
}

// InitOpensearchIndices is the entry point for OpenSearch startup
// bootstrapping: creates every base index (from GetOpensearchBaseIndices)
// that doesn't exist yet, attaches rollover aliases/ISM policies for the
// rollover-eligible subset, registers mapping templates for future rollover
// generations, and migrates any single/keyed index whose live mapping has
// drifted from opensearchCoreMappings.
//
// Safe to call on every backend restart and from multiple replicas
// concurrently - every step is idempotent or existence-checked first. No-op
// if DbType isn't "opensearch" or if SHUFFLE_SKIP_OPENSEARCH_INDEX_INIT is
// set.
func InitOpensearchIndices() {
	if project.DbType != "opensearch" {
		return
	}

	if os.Getenv("SHUFFLE_SKIP_OPENSEARCH_INDEX_INIT") == "true" {
		return
	}

	// Check if the "workflowexecution" index exists and configuring rollovers if possible
	log.Printf("[INFO] Configuring Opensearch indices for scaling")

	ctx := context.Background()
	opensearchUrl := strings.TrimRight(os.Getenv("SHUFFLE_OPENSEARCH_URL"), "/")
	if len(opensearchUrl) == 0 {
		opensearchUrl = "https://shuffle-opensearch:9200"
	}

	relevantScaleIndices := []string{}
	for _, baseIndex := range GetOpensearchBaseIndices() {
		relevantScaleIndices = append(relevantScaleIndices, GetESIndexPrefix(baseIndex))
	}

	// Only append-heavy stores get rollover. Stateful keyed stores stay on a
	// single backing index (rollover there splits _id across generations
	// and breaks single-document reads, e.g. org_statistics).
	appendIndices := []string{}
	for _, baseIndex := range GetOpensearchRolloverIndices() {
		appendIndices = append(appendIndices, strings.ToLower(GetESIndexPrefix(baseIndex)))
	}

	singleIndices := []string{}
	for _, index := range relevantScaleIndices {
		index = strings.ToLower(index)
		if !ArrayContains(appendIndices, index) {
			singleIndices = append(singleIndices, index)
		}
	}

	customConfig := os.Getenv("OPENSEARCH_INDEX_CONFIG")
	if len(customConfig) > 0 {
		checkValidJson := map[string]interface{}{}
		if err := json.Unmarshal([]byte(customConfig), &checkValidJson); err != nil {
			log.Printf("[ERROR] Invalid JSON in OPENSEARCH_INDEX_CONFIG: %s", err)
			customConfig = ""
		} else {
			log.Printf("[DEBUG] Using custom index config for relevant scale indices: %s", customConfig)
		}
	}

	customRollover := os.Getenv("OPENSEARCH_INDEX_ROLLOVER")
	if len(customRollover) > 0 {
		checkValidJson := map[string]interface{}{}
		if err := json.Unmarshal([]byte(customRollover), &checkValidJson); err != nil {
			log.Printf("[ERROR] Invalid JSON in OPENSEARCH_INDEX_ROLLOVER: %s", err)
			customRollover = ""
		} else {
			log.Printf("[DEBUG] Using custom rollover config for relevant scale indices: %s", customRollover)
		}
	}

	rolloverConfig, err := json.Marshal(map[string]interface{}{
		"conditions": getOpensearchDefaultRolloverConditions(),
	})
	if err != nil {
		log.Printf("[ERROR] Failed building default rollover config: %s", err)
		return
	}

	if len(customRollover) > 0 {
		rolloverConfig = []byte(customRollover)
	}

	ismEnabled := strings.ToLower(strings.TrimSpace(os.Getenv("OPENSEARCH_USE_ISM_ROLLOVER"))) != "false"
	ismPolicyName := strings.TrimSpace(os.Getenv("OPENSEARCH_ISM_POLICY_NAME"))
	if ismPolicyName == "" {
		ismPolicyName = "shuffle-rollover"
	}

	// Ensure all ISM rollover policies exist and are up to date.
	ismReady := false
	if ismEnabled {
		for _, baseIndex := range GetOpensearchRolloverIndices() {
			alias := strings.ToLower(GetESIndexPrefix(baseIndex))
			retention := getOpensearchRetentionDays(baseIndex)
			ready, err := ensureOpensearchISMRolloverPolicy(ctx, opensearchUrl, alias, rolloverConfig, retention, ismPolicyName)
			if err != nil {
				log.Printf("[WARNING] Failed ensuring ISM rollover policy '%s': %s", ismPolicyName, err)
				continue
			}
			if ready {
				ismReady = true
			}
		}
	}

	// Fix existing indices
	if fixResult, fixErr := FixOpensearchIndexPrefix(ctx); fixErr != nil {
		log.Printf("[WARNING] Prefix repair before init failed: %s", fixErr)
	} else if !fixResult.Success {
		log.Printf("[WARNING] Prefix repair before init completed with verification warnings: %s", fixResult.Reason)
	} else {
		log.Printf("[INFO] Prefix repair before init: expected aliases=%d found=%d", fixResult.ExpectedAliases, fixResult.FoundAliases)
	}

	// Ensure an IndexTemplate exists for all rollover indices.
	if len(customConfig) == 0 {
		ensureOpensearchMappingTemplates(ctx, opensearchUrl)
	}

	existingOpensearchIndices, existingIndicesErr := getOpensearchIndices(project.Es, opensearchUrl)
	if existingIndicesErr != nil {
		log.Printf("[WARNING] Failed listing existing OpenSearch indices before create-loop (falling back to blind -000001 creation for all indices): %s", existingIndicesErr)
		existingOpensearchIndices = []string{}
	}

	existingOpensearchAliases, existingAliasesErr := getOpensearchAliases(project.Es, opensearchUrl)
	if existingAliasesErr != nil {
		log.Printf("[WARNING] Failed listing existing OpenSearch aliases before create-loop (falling back to name-based existence checks only): %s", existingAliasesErr)
		existingOpensearchAliases = map[string]map[string]opensearchAliasState{}
	}

	for _, index := range relevantScaleIndices {
		indexConfig, err := json.Marshal(map[string]interface{}{
			"aliases": map[string]interface{}{
				index: map[string]bool{"is_write_index": true},
			},
			"settings": getOpensearchDefaultIndexSettings(),
			"mappings": opensearchDynamicMappingSettings(),
		})
		if err != nil {
			log.Printf("[ERROR] Failed building default index config for %s: %s", index, err)
			continue
		}

		if len(customConfig) > 0 {
			indexConfig = []byte(customConfig)

			// Check if alias is in the index or not, otherwise inject it
			unmarshalled := map[string]interface{}{}
			if err := json.Unmarshal(indexConfig, &unmarshalled); err != nil {
				log.Printf("[ERROR] Invalid JSON in OPENSEARCH_INDEX_CONFIG (2): %s", err)
			} else {
				if _, ok := unmarshalled["aliases"]; !ok {
					// Inject it
					aliasPart := map[string]interface{}{
						index: map[string]bool{
							"is_write_index": true,
						},
					}
					unmarshalled["aliases"] = aliasPart
					newConfig, err := json.Marshal(unmarshalled)
					if err != nil {
						log.Printf("[ERROR] Invalid JSON in OPENSEARCH_INDEX_CONFIG (3): %s", err)
					} else {
						indexConfig = newConfig
						log.Printf("[INFO] Injected alias into OPENSEARCH_INDEX_CONFIG for index %s", index)
					}
				}
			}
		}

		index = strings.ToLower(index)
		isAppend := ArrayContains(appendIndices, index)
		if len(customConfig) == 0 {
			indexConfig = applyOpensearchCoreMappings(indexConfig, index)
		}
		initialIndexName, alreadyExists := resolveAppendIndexCreationTarget(existingOpensearchIndices, index)
		if !alreadyExists {
			// Name-prefix matching found nothing, but the alias may still
			// already be served by a legacy, oddly-named backing index
			// (e.g. from an old double-prefix bug).
			//
			// Check the alias's actual write-index assignment before
			// attempting to create a new index - creating one now would
			// give the alias two write indices and OpenSearch would reject
			// it outright.
			if writeIndex, aliasHasWriteIndex := resolveAliasWriteIndex(existingOpensearchAliases, index); aliasHasWriteIndex {
				initialIndexName = writeIndex
				alreadyExists = true
			}
		}
		if isAppend {
			indexConfig = ensureOpensearchIndexRolloverAlias(indexConfig, index)
		}
		// Directly try to force create it. Opensearch throws a 400 if it fails.

		var resp *opensearchapi.IndicesCreateResp
		var createErr error
		if alreadyExists {
			log.Printf("[INFO] Index %s already exists at generation %s - skipping creation, ensuring ISM/rollover on existing index", index, initialIndexName)
		} else {
			resp, createErr = project.Es.Indices.Create(ctx, opensearchapi.IndicesCreateReq{
				Index: initialIndexName,
				Body:  bytes.NewReader(indexConfig),
			})

			res := resp.Inspect().Response
			defer res.Body.Close()
			if createErr != nil {
				if !strings.Contains(fmt.Sprintf("%s", createErr), "serverless mode") && !strings.Contains(fmt.Sprintf("%s", createErr), "resource_already_exists_exception") {
					log.Printf("[WARNING] Error creating index %s: %s", index, createErr)
				}

				// Make sure if the resource exist it is part of correct alias
				if strings.Contains(fmt.Sprintf("%s", createErr), "resource_already_exists_exception") {
					body := fmt.Sprintf(`{
					  "actions": [
					    {
					      "add": {
					        "index": "%s",
					        "alias": "%s",
					        "is_write_index": true
					      }
					    }
					  ]
					}`, initialIndexName, index)

					aliasResp, aerr := project.Es.Aliases(ctx, opensearchapi.AliasesReq{
						Body: strings.NewReader(body),
					})
					if aerr != nil {
						log.Printf("[WARNING] Failed to ensure alias %s for index %s: %s", index, initialIndexName, aerr)
						return
					}

					res := aliasResp.Inspect().Response
					defer res.Body.Close()

					if res.StatusCode >= 300 {
						log.Printf("[WARNING] Alias enforcement failed: %s", res.String())
						return
					}
				}
			} else {
				if res.IsError() {
					if !strings.Contains(res.String(), "resource_already_exists_exception") {
						log.Printf("[DEBUG] Error creating index %s with custom config: %s", index, res.String())
					}

				} else {
					log.Printf("[DEBUG] Successfully created index %s with custom config", index)
				}
			}
		}

		// Non-append indices stay on a single backing index - no rollover/ISM.
		if !isAppend {
			continue
		}

		if ismReady {
			if err := ensureOpensearchIndexRolloverAliasSetting(ctx, opensearchUrl, initialIndexName, index); err != nil {
				log.Printf("[WARNING] Failed ensuring rollover_alias on index %s: %s", initialIndexName, err)
			}

			policyID := fmt.Sprintf("%s-%s", ismPolicyName, index)
			if err := ensureOpensearchIndexISMPolicy(ctx, opensearchUrl, initialIndexName, policyID); err != nil {
				log.Printf("[WARNING] Failed attaching ISM policy '%s' to %s: %s", policyID, initialIndexName, err)
			}

			continue
		}

		rolloverResp, err := project.Es.Indices.Rollover(ctx, opensearchapi.IndicesRolloverReq{
			Alias: index,
			Body:  bytes.NewReader(rolloverConfig),
		})

		if err != nil {
			if !strings.Contains(fmt.Sprintf("%s", err), "serverless mode") && !strings.Contains(fmt.Sprintf("%s", err), "status: 404") {
				log.Printf("[WARNING] Problem during rollover config for %s: %s", index, err)
			}

			continue
		}

		rolloverRes := rolloverResp.Inspect().Response
		defer rolloverRes.Body.Close()
		if rolloverRes.IsError() {
			log.Printf("[ERROR] Rollover config failed for %s: %s", index, rolloverRes.String())
		} else {
			log.Printf("[INFO] Rollover executed successfully for %s", index)
		}

	}

	// Migrate existing deployments that rolled stateful indices in the past:
	// collapse all generations of each single index into its newest backing
	// index and detach ISM so it never rolls again. Idempotent.
	for _, singleIndex := range singleIndices {
		if err := collapseSingleIndexAliases(ctx, opensearchUrl, singleIndex); err != nil {
			log.Printf("[WARNING] Failed collapsing single index %s: %s", singleIndex, err)
		}
	}

	// Apply mapping migrations to existing single/keyed indices when the live
	// mapping has drifted from opensearchCoreMappings. Skipped when a custom
	// OPENSEARCH_INDEX_CONFIG is set (the operator owns those mappings).
	if len(customConfig) == 0 {
		for _, singleIndex := range singleIndices {
			if err := migrateOpensearchSingleIndex(ctx, opensearchUrl, singleIndex); err != nil {
				log.Printf("[WARNING] Failed migrating mapping for single index %s: %s", singleIndex, err)
			}
		}
	}

	if fixResult, fixErr := FixOpensearchIndexPrefix(ctx); fixErr != nil {
		log.Printf("[WARNING] Alias verification after init failed: %s", fixErr)
	} else if !fixResult.Success {
		log.Printf("[WARNING] Alias verification after init completed with warnings: %s", fixResult.Reason)
	} else {
		log.Printf("[INFO] Alias verification after init passed: expected aliases=%d found=%d", fixResult.ExpectedAliases, fixResult.FoundAliases)
	}

}

// getOpensearchIndexProperties returns the "properties" subtree of an index's live mappings.
func getOpensearchIndexProperties(foundClient opensearchapi.Client, opensearchUrl, indexName string) (map[string]interface{}, error) {
	resp, err := foundClient.Indices.Mapping.Get(context.Background(), &opensearchapi.MappingGetReq{Indices: []string{indexName}})
	if err != nil {
		return nil, fmt.Errorf("failed reading mapping for %s: %w", indexName, err)
	}

	for _, idx := range resp.Indices {
		mappings := map[string]interface{}{}
		if len(idx.Mappings) > 0 {
			if err := json.Unmarshal(idx.Mappings, &mappings); err != nil {
				return nil, err
			}
		}
		props, _ := mappings["properties"].(map[string]interface{})
		return props, nil
	}

	return nil, nil
}

// createOpensearchIndexFromBody creates an index with an explicit create body.
func createOpensearchIndexFromBody(ctx context.Context, opensearchUrl, indexName string, body []byte) error {
	if _, err := project.Es.Indices.Create(ctx, opensearchapi.IndicesCreateReq{
		Index: indexName,
		Body:  bytes.NewReader(body),
	}); err != nil {
		return fmt.Errorf("failed creating index %s: %w", indexName, err)
	}

	return nil
}

// migrateOpensearchSingleIndex re-creates a single (keyed) index with the
// current core mappings when its live mapping has drifted.
//
// It bulk-copies the existing backing index into a fresh generation (via
// reindexOpensearchIndex's failure-aware async task polling - not a bare
// synchronous call, so a mapping rejection or task-level error, e.g. a batch
// overflowing OpenSearch's 2GB transport limit, aborts the migration instead
// of silently deleting a partially-copied source), then write-blocks the
// source for a final catch-up copy and verifies an exact document count
// match before atomically swapping the alias to the new generation and
// dropping the old one.
//
// Any failure at any step aborts without deleting the source or touching
// the alias, leaving the next automatic retry (this runs idempotently on
// every startup) to pick up from current state.
func migrateOpensearchSingleIndex(ctx context.Context, opensearchUrl, baseIndex string) error {
	foundClient := project.Es
	allIndices, err := getOpensearchIndices(foundClient, opensearchUrl)
	if err != nil {
		return err
	}

	generations := []string{}
	for _, idx := range allIndices {
		if idx == baseIndex || strings.HasPrefix(idx, baseIndex+"-") {
			generations = append(generations, idx)
		}
	}
	if len(generations) == 0 {
		return nil
	}

	sort.Slice(generations, func(i, j int) bool {
		return getOpensearchGeneration(generations[i]) > getOpensearchGeneration(generations[j])
	})

	// collapseSingleIndexAliases runs just before this; if multiple generations
	// remain, defer to it rather than racing a partial collapse.
	if len(generations) > 1 {
		return nil
	}

	src := generations[0]
	actualProps, err := getOpensearchIndexProperties(foundClient, opensearchUrl, src)
	if err != nil {
		return err
	}
	if !opensearchMappingsDiffer(baseIndex, actualProps) {
		return nil
	}

	nextGen := getOpensearchGeneration(src) + 1
	dest := fmt.Sprintf("%s-%06d", baseIndex, nextGen)

	body := map[string]interface{}{
		"settings": getOpensearchDefaultIndexSettings(),
		"mappings": opensearchMappingsFor(baseIndex),
	}
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return err
	}

	if err := createOpensearchIndexFromBody(ctx, opensearchUrl, dest, bodyJSON); err != nil {
		return err
	}

	log.Printf("[INFO] Opensearch single-index mapping migration: starting bulk copy %s -> %s", src, dest)
	if err := reindexOpensearchIndex(ctx, opensearchUrl, src, dest); err != nil {
		return fmt.Errorf("bulk copy: %w", err)
	}

	// Freeze the source so a final catch-up pass can close any gap opened
	// by writes that landed concurrently during the bulk copy above, before
	// we trust the document counts to match exactly and delete the source.
	//
	// This mirrors the same write-block/catch-up/verify pattern used for
	// legacy alias-collision migrations (runOpensearchCollisionMigration) -
	// without it, a write landing in src during the copy could be silently
	// lost the moment src is deleted below.
	if err := setOpensearchIndexWriteBlock(foundClient, opensearchUrl, src, true); err != nil {
		return fmt.Errorf("write-blocking source before final catch-up: %w", err)
	}

	if err := reindexOpensearchIndex(ctx, opensearchUrl, src, dest); err != nil {
		_ = setOpensearchIndexWriteBlock(foundClient, opensearchUrl, src, false)
		return fmt.Errorf("final write-blocked catch-up copy: %w", err)
	}

	// _count (like _search) only sees refreshed segments, not documents
	// written moments ago - force a refresh on both indices before trusting
	// the comparison below, otherwise the tail of the catch-up copy above
	// can make destCount look behind even though the copy fully succeeded.
	if err := refreshOpensearchIndex(foundClient, opensearchUrl, src); err != nil {
		_ = setOpensearchIndexWriteBlock(foundClient, opensearchUrl, src, false)
		return fmt.Errorf("refreshing source before final count check: %w", err)
	}
	if err := refreshOpensearchIndex(foundClient, opensearchUrl, dest); err != nil {
		_ = setOpensearchIndexWriteBlock(foundClient, opensearchUrl, src, false)
		return fmt.Errorf("refreshing target before final count check: %w", err)
	}

	srcCount, err := getOpensearchIndexCount(foundClient, opensearchUrl, src)
	if err != nil {
		_ = setOpensearchIndexWriteBlock(foundClient, opensearchUrl, src, false)
		return fmt.Errorf("getting final source count: %w", err)
	}
	destCount, err := getOpensearchIndexCount(foundClient, opensearchUrl, dest)
	if err != nil {
		_ = setOpensearchIndexWriteBlock(foundClient, opensearchUrl, src, false)
		return fmt.Errorf("getting final target count: %w", err)
	}
	if destCount < srcCount {
		// Unblock and let the next automatic retry (this function is
		// idempotent and reruns on every startup) redo the copy - something
		// left the target still behind, and deleting the source with data
		// still missing would be permanent data loss.
		_ = setOpensearchIndexWriteBlock(foundClient, opensearchUrl, src, false)
		return fmt.Errorf("target count %d still behind source count %d after write-blocked catch-up - not deleting source", destCount, srcCount)
	}

	// atomically move the write alias from the old generation to the new one
	write := true
	actions := []OpensearchAliasAction{
		{Remove: &OpensearchAliasActionTarget{Index: src, Alias: baseIndex}},
		{Add: &OpensearchAliasActionTarget{Index: dest, Alias: baseIndex, IsWriteIndex: &write}},
	}
	if err := updateOpensearchAliases(foundClient, opensearchUrl, actions); err != nil {
		return err
	}

	if err := deleteOpensearchIndex(foundClient, opensearchUrl, src); err != nil {
		return err
	}

	log.Printf("[INFO] Migrated mapping for %s: %s -> %s (%d documents verified)", baseIndex, src, dest, destCount)
	return nil
}

// ensureOpensearchMappingTemplates registers an index mapping template per
// append/rollover base index so every future rollover generation is created
// with the current core mappings (existing generations are left untouched).
func ensureOpensearchMappingTemplates(ctx context.Context, opensearchUrl string) {
	for _, baseIndex := range GetOpensearchRolloverIndices() {
		alias := strings.ToLower(GetESIndexPrefix(baseIndex))

		body := map[string]interface{}{
			"index_patterns": []string{alias + "-*"},
			"template": map[string]interface{}{
				"mappings": opensearchMappingsFor(baseIndex),
			},
			"priority": 100,
		}
		bodyJSON, err := json.Marshal(body)
		if err != nil {
			log.Printf("[WARNING] Failed building mapping template for %s: %s", alias, err)
			continue
		}

		templateName := fmt.Sprintf("shuffle-%s-mapping", baseIndex)
		if _, err := project.Es.IndexTemplate.Create(ctx, opensearchapi.IndexTemplateCreateReq{
			IndexTemplate: templateName,
			Body:          bytes.NewReader(bodyJSON),
		}); err != nil {
			log.Printf("[WARNING] Failed to register mapping template for %s: %s", alias, err)
			continue
		}
	}
}

// collapseSingleIndexAliases migrates a stateful (non-append) index that may
// have rolled over in previous versions to a single backing index: it
// merges every older generation into the newest (newest document wins per
// _id), drops the older generations, and detaches rollover so the index
// stays single. Safe to run repeatedly.
func collapseSingleIndexAliases(ctx context.Context, opensearchUrl, fullIndex string) error {
	foundClient := project.Es
	allIndices, err := getOpensearchIndices(foundClient, opensearchUrl)
	if err != nil {
		return err
	}

	generations := []string{}
	for _, idx := range allIndices {
		if idx == fullIndex || strings.HasPrefix(idx, fullIndex+"-") {
			generations = append(generations, idx)
		}
	}

	if len(generations) == 1 {
		// A single surviving index - just make sure it can't roll over.
		return detachOpensearchRollover(ctx, opensearchUrl, generations[0])
	}
	if len(generations) == 0 {
		return nil
	}

	sort.Slice(generations, func(i, j int) bool {
		return getOpensearchGeneration(generations[i]) > getOpensearchGeneration(generations[j])
	})
	writeGen := generations[0]
	olderGens := generations[1:]

	// Merge older generations into the newest (the surviving write target).
	// reindexOpensearchIndex uses op_type:create, so a source _id that
	// already exists in the newest generation is skipped (conflicts=proceed)
	// and the newest copy wins; _ids that only live in older generations are
	// copied across.
	//
	// Iteration order does not matter because the destination always wins
	// on collision.
	for _, older := range olderGens {
		if err := reindexOpensearchIndex(ctx, opensearchUrl, older, writeGen); err != nil {
			return err
		}
	}

	actions := []OpensearchAliasAction{}
	for _, older := range olderGens {
		actions = append(actions, OpensearchAliasAction{
			Remove: &OpensearchAliasActionTarget{Index: older, Alias: fullIndex},
		})
	}
	if err := updateOpensearchAliases(foundClient, opensearchUrl, actions); err != nil {
		return err
	}

	for _, older := range olderGens {
		if err := deleteOpensearchIndex(foundClient, opensearchUrl, older); err != nil {
			return err
		}
	}

	return detachOpensearchRollover(ctx, opensearchUrl, writeGen)
}

// reindexOpensearchIndex copies documents from source into dest via
// runOpensearchReindexToCompletion
//
// ctx is accepted for API compatibility with existing callers but the
// underlying poll loop is not currently context-aware.
func reindexOpensearchIndex(ctx context.Context, opensearchUrl, source, dest string) error {
	return runOpensearchReindexToCompletion(project.Es, opensearchUrl, source, dest)
}

// detachOpensearchRollover removes the ISM rollover policy and clears the
// rollover_alias index setting so a single (non-append) index never rolls over.
func detachOpensearchRollover(ctx context.Context, opensearchUrl, indexName string) error {
	// Remove the ISM rollover policy, if any. Missing policy / missing plugin
	// (4xx) is fine - clearing the rollover_alias setting below is what truly
	// stops rollover.
	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/_plugins/_ism/remove/%s", opensearchUrl, indexName), strings.NewReader("{}"))
	if err == nil {
		req.Header.Set("Content-Type", "application/json")
		if removeResp, performErr := project.Es.Client.Transport.Perform(req); performErr == nil {
			_ = removeResp.Body.Close()
		}
	}

	settingsBody := map[string]interface{}{
		"index": map[string]interface{}{
			"plugins.index_state_management.rollover_alias": nil,
		},
	}

	bodyData, marshalErr := json.Marshal(settingsBody)
	if marshalErr != nil {
		return marshalErr
	}

	if _, err := project.Es.Indices.Settings.Put(ctx, opensearchapi.SettingsPutReq{
		Indices: []string{indexName},
		Body:    bytes.NewReader(bodyData),
	}); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "index_not_found_exception") {
			return nil
		}
		return fmt.Errorf("clear rollover_alias on %s failed: %w", indexName, err)
	}

	return nil
}

// getOpensearchISMRolloverConditions parses the "conditions" object from a
// custom OPENSEARCH_INDEX_ROLLOVER JSON payload (accepting both ISM's native
// min_* keys and the more intuitive max_* aliases), falling back to
// Shuffle's defaults (90d / 40gb / 1,000,000 docs) for any condition not
// set, or if rolloverConfig is empty/invalid.
func getOpensearchISMRolloverConditions(rolloverConfig []byte) map[string]interface{} {
	defaultConditions := map[string]interface{}{
		"min_index_age": opensearchDefaultRolloverMaxAge,
		"min_size":      opensearchDefaultRolloverMaxSize,
		"min_doc_count": opensearchDefaultRolloverMaxDocs,
	}

	parsed := struct {
		Conditions map[string]interface{} `json:"conditions"`
	}{}

	if err := json.Unmarshal(rolloverConfig, &parsed); err != nil {
		return defaultConditions
	}

	if len(parsed.Conditions) == 0 {
		return defaultConditions
	}

	conditions := map[string]interface{}{}
	if value, ok := parsed.Conditions["min_index_age"]; ok {
		conditions["min_index_age"] = value
	} else if value, ok := parsed.Conditions["max_age"]; ok {
		conditions["min_index_age"] = value
	}

	if value, ok := parsed.Conditions["min_size"]; ok {
		conditions["min_size"] = value
	} else if value, ok := parsed.Conditions["max_size"]; ok {
		conditions["min_size"] = value
	}

	if value, ok := parsed.Conditions["min_doc_count"]; ok {
		conditions["min_doc_count"] = value
	} else if value, ok := parsed.Conditions["max_docs"]; ok {
		conditions["min_doc_count"] = value
	}

	if len(conditions) == 0 {
		return defaultConditions
	}

	return conditions
}

// getOpensearchRetentionDays returns how long rolled-over generations of
// baseIndex should be kept before ISM deletes them (e.g. "90d"), preferring
// a per-index override from OPENSEARCH_INDEX_RETENTION_DAYS (a JSON map) over
// Shuffle's built-in defaults. Returns "" (no retention/keep forever) for any
// base index without a default and without an override.
func getOpensearchRetentionDays(baseIndex string) string {
	defaults := map[string]string{
		"shuffle_logs":      "90d",
		"workflowexecution": "365d",
	}

	value := defaults[baseIndex]
	if value == "" {
		return ""
	}

	custom := strings.TrimSpace(os.Getenv("OPENSEARCH_INDEX_RETENTION_DAYS"))
	if custom == "" {
		return value
	}

	parsed := map[string]interface{}{}
	if err := json.Unmarshal([]byte(custom), &parsed); err != nil {
		log.Printf("[WARNING] Invalid JSON in OPENSEARCH_INDEX_RETENTION_DAYS: %s", err)
		return value
	}

	raw, ok := parsed[baseIndex]
	if !ok {
		return value
	}
	if days, ok := raw.(float64); ok {
		return fmt.Sprintf("%dd", int(days))
	}
	if str, ok := raw.(string); ok {
		return str
	}

	return value
}

// existingOpensearchISMPolicy holds the parts of a GET
// /_plugins/_ism/policies/<id> response needed to decide whether the policy
// needs updating, and (if so) to perform a conflict-safe PUT.
type existingOpensearchISMPolicy struct {
	SeqNo         int64                  `json:"_seq_no"`
	PrimaryTerm   int64                  `json:"_primary_term"`
	RawConditions map[string]interface{} // hot state's rollover conditions
	RawRetention  string                 // delete transition's min_index_age, if any
}

// getExistingOpensearchISMPolicy fetches the current ISM policy document for
// policyID, if any, and extracts just the "hot" state's rollover conditions
// and delete-transition retention age (plus the _seq_no/_primary_term
// needed for a conflict-safe PUT). Returns (nil, false, nil) if the policy
// doesn't exist yet, and a distinct "ism plugin not available" error if the
// ISM plugin itself isn't installed on the cluster.
func getExistingOpensearchISMPolicy(ctx context.Context, opensearchUrl, policyID string) (*existingOpensearchISMPolicy, bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/_plugins/_ism/policies/%s", opensearchUrl, policyID), nil)
	if err != nil {
		return nil, false, err
	}

	resp, err := project.Es.Client.Transport.Perform(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		if resp.StatusCode == 404 || resp.StatusCode == 400 {
			if strings.Contains(strings.ToLower(string(body)), "_plugins/_ism") || strings.Contains(strings.ToLower(string(body)), "no handler found") {
				// ISM plugin isn't installed at all.
				return nil, false, fmt.Errorf("ism plugin not available")
			}
		}

		if resp.StatusCode == 404 {
			// Genuinely doesn't exist yet - needs to be created.
			return nil, false, nil
		}

		return nil, false, fmt.Errorf("status: %d, body: %s", resp.StatusCode, string(body))
	}

	parsed := struct {
		SeqNo       int64 `json:"_seq_no"`
		PrimaryTerm int64 `json:"_primary_term"`
		Policy      struct {
			States []struct {
				Name    string `json:"name"`
				Actions []struct {
					Rollover map[string]interface{} `json:"rollover"`
				} `json:"actions"`
				Transitions []struct {
					Conditions struct {
						MinIndexAge string `json:"min_index_age"`
					} `json:"conditions"`
				} `json:"transitions"`
			} `json:"states"`
		} `json:"policy"`
	}{}

	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, false, err
	}

	existing := &existingOpensearchISMPolicy{
		SeqNo:       parsed.SeqNo,
		PrimaryTerm: parsed.PrimaryTerm,
	}
	for _, state := range parsed.Policy.States {
		if state.Name != "hot" {
			continue
		}
		if len(state.Actions) > 0 {
			existing.RawConditions = state.Actions[0].Rollover
		}
		if len(state.Transitions) > 0 {
			existing.RawRetention = state.Transitions[0].Conditions.MinIndexAge
		}
	}

	return existing, true, nil
}

// ensureOpensearchISMRolloverPolicy creates (or updates, if its rollover
// conditions or retention no longer match) the ISM policy that rolls over
// and eventually deletes generations of alias. Returns (true, nil) if a
// usable policy is in place, or (false, nil) - not an error - if the ISM
// plugin isn't installed, so callers can fall back to direct shard rollover.
func ensureOpensearchISMRolloverPolicy(ctx context.Context, opensearchUrl, alias string, rolloverConfig []byte, retentionAge, policyName string) (bool, error) {
	conditions := getOpensearchISMRolloverConditions(rolloverConfig)
	policyID := fmt.Sprintf("%s-%s", policyName, alias)

	states := []map[string]interface{}{
		{
			"name":        "hot",
			"actions":     []map[string]interface{}{{"rollover": conditions}},
			"transitions": []interface{}{},
		},
	}

	if retentionAge != "" {
		states[0]["transitions"] = []map[string]interface{}{
			{
				"state_name": "delete",
				"conditions": map[string]interface{}{"min_index_age": retentionAge},
			},
		}
		states = append(states, map[string]interface{}{
			"name":        "delete",
			"actions":     []map[string]interface{}{{"delete": map[string]interface{}{}}},
			"transitions": []interface{}{},
		})
	}

	policyBody := map[string]interface{}{
		"policy": map[string]interface{}{
			"description":   "Shuffle rollover + retention policy",
			"default_state": "hot",
			"states":        states,
			"ism_template": []map[string]interface{}{
				{
					"index_patterns": []string{fmt.Sprintf("%s-*", alias)},
					"priority":       100,
				},
			},
		},
	}

	policyData, err := json.Marshal(policyBody)
	if err != nil {
		return false, err
	}

	// Check whether the policy already exists, and if so, whether its
	// rollover conditions/retention already match what we'd write - this
	// lets us both (a) avoid a needless PUT (and its 409) when nothing
	// changed, and (b) actually apply changes to OPENSEARCH_INDEX_ROLLOVER /
	// OPENSEARCH_INDEX_RETENTION_DAYS on restart when something did change,
	// which a blind "create-only" PUT can never do once the policy exists.
	existing, found, err := getExistingOpensearchISMPolicy(ctx, opensearchUrl, policyID)
	if err != nil {
		if err.Error() == "ism plugin not available" {
			log.Printf("[INFO] ISM plugin not available. Falling back to direct rollover")
			return false, nil
		}
		return false, err
	}

	putUrl := fmt.Sprintf("%s/_plugins/_ism/policies/%s", opensearchUrl, policyID)
	if found {
		// Compare only the specific rollover condition keys Shuffle manages,
		// not a full deep-equal of the stored object: OpenSearch enriches
		// the stored rollover conditions with its own extra fields we never
		// set (e.g. "copy_alias": false), so a full-map compare would never
		// match and would cause a needless PUT (and misleading "changed -
		// updating" log) on every single restart.
		//
		// %v formatting sidesteps int (our defaults) vs float64 (values
		// decoded from OpenSearch's JSON response) type mismatches on
		// otherwise-equal numbers.
		conditionsMatch := true
		for _, key := range []string{"min_index_age", "min_size", "min_doc_count"} {
			if fmt.Sprintf("%v", existing.RawConditions[key]) != fmt.Sprintf("%v", conditions[key]) {
				conditionsMatch = false
				break
			}
		}
		retentionMatches := existing.RawRetention == retentionAge
		if conditionsMatch && retentionMatches {
			log.Printf("[DEBUG] ISM rollover policy '%s' already up to date for alias %s - skipping", policyID, alias)
			return true, nil
		}

		log.Printf("[INFO] ISM rollover policy '%s' conditions/retention changed for alias %s - updating", policyID, alias)
		putUrl = fmt.Sprintf("%s?if_seq_no=%d&if_primary_term=%d", putUrl, existing.SeqNo, existing.PrimaryTerm)
	}

	req, err := http.NewRequestWithContext(ctx, "PUT", putUrl, bytes.NewReader(policyData))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := project.Es.Client.Transport.Perform(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		if resp.StatusCode == 404 || resp.StatusCode == 400 {
			if strings.Contains(strings.ToLower(string(body)), "_plugins/_ism") || strings.Contains(strings.ToLower(string(body)), "no handler found") {
				log.Printf("[INFO] ISM plugin not available. Falling back to direct rollover")
				return false, nil
			}
		}

		return false, fmt.Errorf("status: %d, body: %s", resp.StatusCode, string(body))
	}

	log.Printf("[INFO] Ensured ISM rollover policy '%s' for alias %s", policyID, alias)
	return true, nil
}

// ensureOpensearchIndexRolloverAliasSetting sets the
// "plugins.index_state_management.rollover_alias" setting on an
// already-existing index (unlike ensureOpensearchIndexRolloverAlias, which
// only patches a create body).
//
// Treats a missing index as success rather than an error, since the index
// may have just been rolled/collapsed away by a concurrent replica.
func ensureOpensearchIndexRolloverAliasSetting(ctx context.Context, opensearchUrl, indexName, alias string) error {
	settingsBody := map[string]interface{}{
		"index": map[string]interface{}{
			"plugins.index_state_management.rollover_alias": alias,
		},
	}

	body, err := json.Marshal(settingsBody)
	if err != nil {
		return err
	}

	_, err = project.Es.Indices.Settings.Put(ctx, opensearchapi.SettingsPutReq{
		Indices: []string{indexName},
		Body:    bytes.NewReader(body),
	})
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "index_not_found_exception") {
			return nil
		}

		return err
	}

	return nil
}

// ensureOpensearchIndexISMPolicy attaches policyName as the managing ISM
// policy for indexName. Treats "already has a policy" and "index not found"
// responses as success, since both mean there's nothing left to do here.
func ensureOpensearchIndexISMPolicy(ctx context.Context, opensearchUrl, indexName, policyName string) error {
	policyBody := map[string]interface{}{
		"policy_id": policyName,
	}

	body, err := json.Marshal(policyBody)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/_plugins/_ism/add/%s", opensearchUrl, indexName), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := project.Es.Client.Transport.Perform(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respBody, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		lowerResp := strings.ToLower(string(respBody))
		if strings.Contains(lowerResp, "already has a policy") {
			return nil
		}

		if resp.StatusCode == 404 && strings.Contains(lowerResp, "index_not_found_exception") {
			return nil
		}

		return fmt.Errorf("status: %d, body: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// OpensearchPrefixFixResult is the result of FixOpensearchIndexPrefix: a
// summary of what was verified, migrated, or repaired.
type OpensearchPrefixFixResult struct {
	Success           bool     `json:"success"`
	Reason            string   `json:"reason,omitempty"`
	ExpectedAliases   int      `json:"expected_aliases,omitempty"`
	FoundAliases      int      `json:"found_aliases,omitempty"`
	MissingAliases    []string `json:"missing_aliases,omitempty"`
	InvalidWriteAlias []string `json:"invalid_write_aliases,omitempty"`
	MigrationTasks    []string `json:"migration_tasks,omitempty"`
	Created           []string `json:"created,omitempty"`
	WriteIndexUpdates []string `json:"write_index_updates,omitempty"`
	AliasUpdates      []string `json:"alias_updates,omitempty"`
	Skipped           []string `json:"skipped,omitempty"`
}

// FixOpensearchIndexPrefix verifies (and repairs) that every base index has
// exactly one correctly-named write alias attached, for every base index
// from GetOpensearchBaseIndices.
//
// It detects two distinct problems and heals both without operator
// interaction: (1) a legacy plain index colliding with its intended alias
// name (kicks off an async collision migration via
// startOpensearchCollisionMigrationAsync), and (2) a missing/invalid write
// alias that can be fixed by a plain alias update.
func FixOpensearchIndexPrefix(ctx context.Context) (OpensearchPrefixFixResult, error) {
	result := OpensearchPrefixFixResult{}
	if project.Environment == "cloud" {
		result.Reason = "Opensearch prefix repair not supported in cloud"
		return result, errors.New(result.Reason)
	}

	if project.DbType != "opensearch" {
		result.Reason = "Opensearch is not configured"
		return result, errors.New(result.Reason)
	}

	opensearchUrl := strings.TrimRight(os.Getenv("SHUFFLE_OPENSEARCH_URL"), "/")
	if len(opensearchUrl) == 0 {
		opensearchUrl = "https://shuffle-opensearch:9200"
	}

	foundClient := project.Es
	allIndices, err := getOpensearchIndices(foundClient, opensearchUrl)
	if err != nil {
		return result, err
	}

	aliasInfo, err := getOpensearchAliases(foundClient, opensearchUrl)
	if err != nil {
		return result, err
	}

	prefix := strings.ToLower(strings.TrimSpace(os.Getenv("SHUFFLE_OPENSEARCH_INDEX_PREFIX")))
	baseIndices := GetOpensearchBaseIndices()
	expectedAliases := []string{}
	for _, baseIndex := range baseIndices {
		expectedAliases = append(expectedAliases, strings.ToLower(GetESIndexPrefix(baseIndex)))
	}

	rolloverConfig, err := json.Marshal(map[string]interface{}{
		"conditions": getOpensearchDefaultRolloverConditions(),
	})
	if err != nil {
		return result, fmt.Errorf("failed building default rollover config: %w", err)
	}

	customRollover := os.Getenv("OPENSEARCH_INDEX_ROLLOVER")
	if len(customRollover) > 0 {
		checkValidJson := map[string]interface{}{}
		if err := json.Unmarshal([]byte(customRollover), &checkValidJson); err != nil {
			log.Printf("[ERROR] Invalid JSON in OPENSEARCH_INDEX_ROLLOVER: %s", err)
		} else {
			rolloverConfig = []byte(customRollover)
		}
	}

	ismEnabled := strings.ToLower(strings.TrimSpace(os.Getenv("OPENSEARCH_USE_ISM_ROLLOVER"))) != "false"
	ismPolicyName := strings.TrimSpace(os.Getenv("OPENSEARCH_ISM_POLICY_NAME"))
	if ismPolicyName == "" {
		ismPolicyName = "shuffle-rollover"
	}

	for _, baseIndex := range baseIndices {
		expectedAlias := strings.ToLower(GetESIndexPrefix(baseIndex))

		if ArrayContains(allIndices, expectedAlias) {
			targetIndex := fmt.Sprintf("%s-000001", expectedAlias)
			// Migration runs fully in the background (see
			// startOpensearchCollisionMigrationAsync) - a legacy monolithic
			// index blocking this alias name can be hundreds of GB, and
			// copying it synchronously here would block backend startup
			// for hours.
			//
			// It resumes automatically (idempotently) on every restart
			// until the alias is finally freed and swapped, with no
			// operator action required.
			startOpensearchCollisionMigrationAsync(foundClient, opensearchUrl, expectedAlias, targetIndex, baseIndex)
			result.MigrationTasks = append(result.MigrationTasks, fmt.Sprintf("%s -> %s (background migration running)", expectedAlias, targetIndex))
			result.Skipped = append(result.Skipped, fmt.Sprintf("%s (collision migration running in background; alias unavailable until it completes)", expectedAlias))
			continue
		}

		targetIndices, writeIndex := selectOpensearchAliasTargets(baseIndex, prefix, aliasInfo, allIndices)
		if len(targetIndices) == 0 {
			newIndex := fmt.Sprintf("%s-000001", expectedAlias)
			if !ArrayContains(allIndices, newIndex) {
				if err := createOpensearchIndex(foundClient, opensearchUrl, newIndex, baseIndex); err != nil {
					return result, err
				}
				result.Created = append(result.Created, newIndex)
				allIndices = append(allIndices, newIndex)
			}

			targetIndices = []string{newIndex}
			writeIndex = newIndex
		}

		actions := []OpensearchAliasAction{}
		for _, indexName := range targetIndices {
			current, hasCurrent := aliasInfo[indexName][expectedAlias]
			desiredWrite := indexName == writeIndex

			if hasCurrent {
				if current.IsWriteIndex != desiredWrite {
					actions = append(actions, OpensearchAliasAction{
						Remove: &OpensearchAliasActionTarget{Index: indexName, Alias: expectedAlias},
					})
					actions = append(actions, OpensearchAliasAction{
						Add: &OpensearchAliasActionTarget{Index: indexName, Alias: expectedAlias, IsWriteIndex: &desiredWrite},
					})
				}
			} else {
				actions = append(actions, OpensearchAliasAction{
					Add: &OpensearchAliasActionTarget{Index: indexName, Alias: expectedAlias, IsWriteIndex: &desiredWrite},
				})
			}

			// Drop any other alias attached to this index that belongs to
			// the same baseIndex - i.e. any legacy multi-prefixed variant
			// left over from the historical double-prefix bug.
			for aliasName, state := range aliasInfo[indexName] {
				if aliasName == expectedAlias || !state.Present {
					continue
				}
				if opensearchIndexBelongsTo(aliasName, baseIndex, prefix) {
					actions = append(actions, OpensearchAliasAction{
						Remove: &OpensearchAliasActionTarget{Index: indexName, Alias: aliasName},
					})
				}
			}
		}

		if len(actions) > 0 {
			if err := updateOpensearchAliases(foundClient, opensearchUrl, actions); err != nil {
				return result, err
			}
			result.AliasUpdates = append(result.AliasUpdates, fmt.Sprintf("%s -> %s", expectedAlias, writeIndex))
		}

		result.WriteIndexUpdates = append(result.WriteIndexUpdates, fmt.Sprintf("%s -> %s", expectedAlias, writeIndex))
	}

	verifiedAliasInfo, err := getOpensearchAliases(foundClient, opensearchUrl)
	if err != nil {
		return result, err
	}

	result.ExpectedAliases = len(expectedAliases)
	result.FoundAliases = 0
	for _, aliasName := range expectedAliases {
		indices := []string{}
		writeIndices := []string{}
		for indexName, aliases := range verifiedAliasInfo {
			state, ok := aliases[aliasName]
			if !ok || !state.Present {
				continue
			}

			indices = append(indices, indexName)
			if state.IsWriteIndex {
				writeIndices = append(writeIndices, indexName)
			}
		}

		if len(indices) == 0 {
			result.MissingAliases = append(result.MissingAliases, aliasName)
			continue
		}

		result.FoundAliases++
		if len(writeIndices) != 1 {
			result.InvalidWriteAlias = append(result.InvalidWriteAlias, fmt.Sprintf("%s (write_indices=%d)", aliasName, len(writeIndices)))
			continue
		}

		// "Latest" prefers a canonically-named generation (aliasName or
		// aliasName+"-NNNNNN") over raw generation number, same preference
		// selectOpensearchAliasTargets uses to pick a write index. Without
		// this, a legacy differently-prefixed generation kept attached
		// read-only after double-prefix cleanup (see
		// opensearchIndexBelongsTo) can coincidentally share its generation
		// number with the canonical one, and a name-string tiebreak alone
		// can then misidentify that legacy copy as "latest" and flag a
		// perfectly correct write-index as invalid.
		sorted := append([]string{}, indices...)
		sort.Slice(sorted, func(i, j int) bool {
			iCanonical := sorted[i] == aliasName || strings.HasPrefix(sorted[i], aliasName+"-")
			jCanonical := sorted[j] == aliasName || strings.HasPrefix(sorted[j], aliasName+"-")
			if iCanonical != jCanonical {
				return iCanonical
			}

			gi := getOpensearchGeneration(sorted[i])
			gj := getOpensearchGeneration(sorted[j])
			if gi == gj {
				return sorted[i] > sorted[j]
			}
			return gi > gj
		})

		latest := sorted[0]
		if writeIndices[0] != latest {
			result.InvalidWriteAlias = append(result.InvalidWriteAlias, fmt.Sprintf("%s (write=%s latest=%s)", aliasName, writeIndices[0], latest))
		}
	}

	if len(result.MissingAliases) > 0 || len(result.InvalidWriteAlias) > 0 || result.FoundAliases != result.ExpectedAliases {
		result.Success = false
		result.Reason = "Opensearch alias verification failed after repair"
		log.Printf("[WARNING] %s. expected_aliases=%d found_aliases=%d missing=%d invalid_write=%d", result.Reason, result.ExpectedAliases, result.FoundAliases, len(result.MissingAliases), len(result.InvalidWriteAlias))
	} else {
		result.Success = true
		result.Reason = "Opensearch alias and index state repaired without data reindexing"
	}

	// Surface in-progress migrations and skipped items in logs too, not just
	// in the API response, so a stuck or silently-failing collision migration
	// is visible without needing to poll the repair endpoint.
	if len(result.MigrationTasks) > 0 {
		log.Printf("[INFO] Opensearch collision migrations in progress: %s", strings.Join(result.MigrationTasks, "; "))
	}
	if len(result.Skipped) > 0 {
		log.Printf("[INFO] Opensearch prefix repair skipped items: %s", strings.Join(result.Skipped, "; "))
	}

	if ismEnabled {
		appendBase := map[string]bool{}
		for _, baseIndex := range GetOpensearchRolloverIndices() {
			appendBase[strings.ToLower(baseIndex)] = true
		}

		for _, aliasName := range expectedAliases {
			bi := strings.TrimPrefix(strings.ToLower(aliasName), strings.ToLower(GetESIndexPrefix("")))
			if !appendBase[bi] {
				continue
			}
			retention := getOpensearchRetentionDays(bi)
			policyID := fmt.Sprintf("%s-%s", ismPolicyName, aliasName)
			ismReady, ismErr := ensureOpensearchISMRolloverPolicy(ctx, opensearchUrl, aliasName, rolloverConfig, retention, ismPolicyName)
			if ismErr != nil {
				log.Printf("[WARNING] Failed ensuring ISM rollover policy '%s' in prefix fix: %s", policyID, ismErr)
				continue
			}
			if !ismReady {
				continue
			}
			for indexName, aliases := range verifiedAliasInfo {
				state, ok := aliases[aliasName]
				if !ok || !state.Present {
					continue
				}

				if err := ensureOpensearchIndexRolloverAliasSetting(ctx, opensearchUrl, indexName, aliasName); err != nil {
					log.Printf("[WARNING] Failed ensuring rollover alias on %s for alias %s: %s", indexName, aliasName, err)
					continue
				}

				if err := ensureOpensearchIndexISMPolicy(ctx, opensearchUrl, indexName, policyID); err != nil {
					log.Printf("[WARNING] Failed attaching ISM policy '%s' to %s: %s", policyID, indexName, err)
				}
			}
		}
	}

	return result, nil
}

// inFlightOpensearchCollisionMigrations tracks alias/source-index names
// currently being migrated by a background goroutine in this process, so a
// repeated call within this process (e.g. the startup init path and the
// manual repair API both invoking FixOpensearchIndexPrefix) never launches a
// second concurrent migration for the same index.
//
// Shuffle backends commonly run as multiple replicas against the same
// OpenSearch cluster, so this in-process guard alone can't stop every
// replica from starting its own copy of the same legacy index at once.
// Cross-replica duplicate-avoidance is handled separately by
// findRunningOpensearchReindexTask, which asks OpenSearch's own _tasks API
// (shared cluster state, not a Shuffle-owned lock) whether a matching
// reindex is already under way before starting a new one.
//
// This is deliberately best-effort rather than a hard mutex: every
// operation in this migration (op_type:create+conflicts:proceed copy,
// 404-tolerant delete, idempotent alias-add) is safe to run redundantly, so
// a missed race only costs some wasted duplicate cluster work, never data
// corruption.
var inFlightOpensearchCollisionMigrations sync.Map

// startOpensearchCollisionMigrationAsync launches (or, if a migration for
// this source index is already running in this process, no-ops) a full
// background migration of a legacy plain index that collides with its
// intended alias name into a correctly-named, correctly-mapped generation
// index, finishing with an atomic alias cutover once - and only once - the
// copy is verified complete with zero document failures.
//
// Runs entirely in a goroutine so a multi-hour reindex of a large legacy
// index (hundreds of GB is realistic here) never blocks backend startup.
//
// Intentionally requires no operator interaction: this must be safe to run
// unattended across every Shuffle deployment, including ones nobody is
// actively watching, and safe to run on every replica of a multi-pod
// deployment - cross-replica duplicate avoidance is handled inside
// runOpensearchReindexToCompletion by checking OpenSearch's own _tasks API
// for an already-running matching reindex before starting a new one.
func startOpensearchCollisionMigrationAsync(foundClient opensearchapi.Client, opensearchUrl, sourceIndex, targetIndex, baseIndex string) {
	if _, alreadyRunning := inFlightOpensearchCollisionMigrations.LoadOrStore(sourceIndex, true); alreadyRunning {
		return
	}

	go func() {
		defer inFlightOpensearchCollisionMigrations.Delete(sourceIndex)

		if err := runOpensearchCollisionMigration(foundClient, opensearchUrl, sourceIndex, targetIndex, baseIndex); err != nil {
			log.Printf("[ERROR] Opensearch collision migration %s -> %s did not complete: %s. Nothing was deleted; this will be retried automatically (from wherever the idempotent copy left off) the next time Opensearch index init runs.", sourceIndex, targetIndex, err)
		}
	}()
}

// runOpensearchCollisionMigration performs the full migration for one
// colliding index: create target (with the corrected mapping) if missing,
// bulk-copy while the source is still live, write-block the source and do a
// final catch-up copy to close any gap from concurrent writes during the
// (potentially very long) bulk copy, verify an exact document count match,
// and only then delete the source and swap the alias in.
//
// Any failure at any step aborts without deleting the source or touching
// the alias, leaving the next automatic retry to pick up from current
// state.
//
// Safe to run concurrently from multiple replicas: every step is
// idempotent/tolerant of having already been done (op_type:create +
// conflicts:proceed copy, 404-tolerant delete, idempotent alias-add), and
// runOpensearchReindexToCompletion additionally avoids starting duplicate
// reindex work when another replica already has a matching task running.
func runOpensearchCollisionMigration(foundClient opensearchapi.Client, opensearchUrl, sourceIndex, targetIndex, baseIndex string) error {
	targetExists, err := checkOpensearchIndexExists(foundClient, opensearchUrl, targetIndex)
	if err != nil {
		return fmt.Errorf("checking target index: %w", err)
	}
	if !targetExists {
		if err := createOpensearchIndex(foundClient, opensearchUrl, targetIndex, baseIndex); err != nil {
			return fmt.Errorf("creating target index: %w", err)
		}
	}

	log.Printf("[INFO] Opensearch collision migration: starting bulk copy %s -> %s (large legacy indices can take a long time here; safe to restart the backend during this phase)", sourceIndex, targetIndex)
	if err := runOpensearchReindexToCompletion(foundClient, opensearchUrl, sourceIndex, targetIndex); err != nil {
		return fmt.Errorf("bulk copy: %w", err)
	}

	// Freeze the source so a final catch-up pass can close any gap opened
	// by writes that landed concurrently during the (potentially
	// hours-long) bulk copy above, before we trust the document counts to
	// match exactly.
	if err := setOpensearchIndexWriteBlock(foundClient, opensearchUrl, sourceIndex, true); err != nil {
		return fmt.Errorf("write-blocking source before final catch-up: %w", err)
	}

	if err := runOpensearchReindexToCompletion(foundClient, opensearchUrl, sourceIndex, targetIndex); err != nil {
		_ = setOpensearchIndexWriteBlock(foundClient, opensearchUrl, sourceIndex, false)
		return fmt.Errorf("final write-blocked catch-up copy: %w", err)
	}

	// _count (like _search) only sees refreshed segments, not documents
	// written moments ago - force a refresh on both indices before trusting
	// the comparison below, otherwise the tail of the catch-up copy above
	// can make targetCount look behind even though the copy fully
	// succeeded, for indices still receiving writes right up to the
	// write-block (exactly the high-volume case this is built for).
	if err := refreshOpensearchIndex(foundClient, opensearchUrl, sourceIndex); err != nil {
		_ = setOpensearchIndexWriteBlock(foundClient, opensearchUrl, sourceIndex, false)
		return fmt.Errorf("refreshing source before final count check: %w", err)
	}
	if err := refreshOpensearchIndex(foundClient, opensearchUrl, targetIndex); err != nil {
		_ = setOpensearchIndexWriteBlock(foundClient, opensearchUrl, sourceIndex, false)
		return fmt.Errorf("refreshing target before final count check: %w", err)
	}

	sourceCount, err := getOpensearchIndexCount(foundClient, opensearchUrl, sourceIndex)
	if err != nil {
		_ = setOpensearchIndexWriteBlock(foundClient, opensearchUrl, sourceIndex, false)
		return fmt.Errorf("getting final source count: %w", err)
	}
	targetCount, err := getOpensearchIndexCount(foundClient, opensearchUrl, targetIndex)
	if err != nil {
		_ = setOpensearchIndexWriteBlock(foundClient, opensearchUrl, sourceIndex, false)
		return fmt.Errorf("getting final target count: %w", err)
	}
	if targetCount < sourceCount {
		// Unblock and let the next automatic retry redo the whole idempotent
		// copy - something (most likely a write landing in the narrow window
		// between the write-block taking effect and the catch-up reindex
		// starting) left the target still behind, and deleting the source
		// with data still missing would be permanent data loss.
		_ = setOpensearchIndexWriteBlock(foundClient, opensearchUrl, sourceIndex, false)
		return fmt.Errorf("target count %d still behind source count %d after write-blocked catch-up - not deleting source", targetCount, sourceCount)
	}

	if err := deleteOpensearchIndex(foundClient, opensearchUrl, sourceIndex); err != nil {
		_ = setOpensearchIndexWriteBlock(foundClient, opensearchUrl, sourceIndex, false)
		return fmt.Errorf("deleting source index after verified migration: %w", err)
	}

	isWrite := true
	actions := []OpensearchAliasAction{
		{
			Add: &OpensearchAliasActionTarget{Index: targetIndex, Alias: sourceIndex, IsWriteIndex: &isWrite},
		},
	}
	// The source index (whose name equals the alias we're about to create)
	// is already gone at this point - there's no going back to a "both
	// exist" state to retry from later within this run.
	//
	// A transient failure here (network blip, master reelection) would
	// otherwise leave the application-facing index name pointing at
	// neither a physical index nor an alias until the next full backend
	// restart picks it up via FixOpensearchIndexPrefix. Retry with backoff
	// in-process instead of relying solely on that next restart.
	var aliasErr error
	for attempt := 0; attempt < 5; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 2 * time.Second)
		}
		aliasErr = updateOpensearchAliases(foundClient, opensearchUrl, actions)
		if aliasErr == nil {
			break
		}
		log.Printf("[WARNING] Opensearch collision migration %s -> %s: alias finalization attempt %d/5 failed (source is already deleted - retrying): %s", sourceIndex, targetIndex, attempt+1, aliasErr)
	}
	if aliasErr != nil {
		return fmt.Errorf("finalizing alias swap after %d attempts (source index '%s' no longer exists - this MUST be fixed manually or by restarting the backend, since the alias '%s' has no target until this succeeds): %w", 5, sourceIndex, sourceIndex, aliasErr)
	}

	log.Printf("[INFO] Opensearch collision migration complete: alias '%s' now served by '%s' (%d documents verified)", sourceIndex, targetIndex, targetCount)
	return nil
}

// runOpensearchReindexToCompletion starts an async reindex task
// (op_type:create + conflicts:proceed, so it is safe to re-run in full any
// number of times) and polls it to completion, surfacing any per-document
// failures as an error.
//
// Before starting a new task, it checks whether a matching reindex (same
// source and target index) is already running somewhere in the cluster -
// e.g. started a moment earlier by another backend replica - via
// findRunningOpensearchReindexTask, and polls that one instead.
//
// This is a best-effort optimization, not a hard mutex: it relies on
// OpenSearch's _tasks API description field including both index names,
// which is long standing behavior but not a formally documented guarantee.
// That's fine here because every step of this migration is safe to run
// redundantly; missing the existing task in a race just means briefly
// running two copies of the same idempotent reindex rather than any data
// loss.
func runOpensearchReindexToCompletion(foundClient opensearchapi.Client, opensearchUrl, sourceIndex, targetIndex string) error {
	taskID, err := findRunningOpensearchReindexTask(foundClient, opensearchUrl, sourceIndex, targetIndex)
	if err != nil {
		log.Printf("[DEBUG] Opensearch collision migration %s -> %s: failed checking for an already-running reindex task (continuing to start a new one): %s", sourceIndex, targetIndex, err)
	}
	if taskID != "" {
		log.Printf("[INFO] Opensearch collision migration %s -> %s: found an already-running matching reindex task %s (likely started by another replica) - polling it instead of starting a duplicate", sourceIndex, targetIndex, taskID)
	} else {
		taskID, err = startOpensearchReindexTask(foundClient, opensearchUrl, sourceIndex, targetIndex)
		if err != nil {
			return err
		}
		if taskID == "" {
			// Nothing to do (e.g. destination already existed under a
			// resource_already_exists_exception, which
			// startOpensearchReindexTask treats as a benign no-op).
			return nil
		}
	}

	for {
		completed, failures, statusErr := getOpensearchTaskStatus(foundClient, opensearchUrl, taskID)
		if statusErr != nil {
			return fmt.Errorf("checking reindex task %s: %w", taskID, statusErr)
		}
		if !completed {
			time.Sleep(30 * time.Second)
			continue
		}
		if len(failures) > 0 {
			sample := failures[0]
			return fmt.Errorf("reindex task %s reported %d document failure(s), first: %s", taskID, len(failures), sample)
		}
		return nil
	}
}

// findRunningOpensearchReindexTask looks for an already-running reindex
// task (GET _tasks?actions=*reindex&detailed=true) whose description
// mentions both sourceIndex and targetIndex, and returns its task ID if
// found. Used purely to avoid starting redundant duplicate reindex work
// when multiple backend replicas race to migrate the same colliding index;
// returns an empty ID (no error) if none is found.
func findRunningOpensearchReindexTask(foundClient opensearchapi.Client, opensearchUrl, sourceIndex, targetIndex string) (string, error) {
	resp, err := foundClient.Tasks.List(context.Background(), &opensearchapi.TasksListReq{
		Params: opensearchapi.TasksListParams{
			Actions:  []string{"*reindex"},
			Detailed: opensearchapi.ToPointer(true),
		},
	})
	if err != nil {
		return "", fmt.Errorf("failed listing tasks: %w", err)
	}

	for nodeID, node := range resp.Nodes {
		for taskID, task := range node.Tasks {
			if strings.Contains(task.Description, sourceIndex) && strings.Contains(task.Description, targetIndex) {
				// _tasks/<id> expects the "<nodeID>:<taskID>" form; the map
				// key from the per-node "tasks" object is already that
				// composite ID, so prefer it over the numeric ID field.
				if strings.Contains(taskID, ":") {
					return taskID, nil
				}
				return fmt.Sprintf("%s:%d", nodeID, task.ID), nil
			}
		}
	}

	return "", nil
}

type opensearchTaskStatusResponse struct {
	Completed bool `json:"completed"`
	Response  struct {
		Failures []struct {
			Index string `json:"index"`
			ID    string `json:"id"`
			Cause struct {
				Reason string `json:"reason"`
			} `json:"cause"`
		} `json:"failures"`
	} `json:"response"`
	// Error is populated when the task aborted with a fatal, task-level
	// exception (e.g. a shard-level query failure like OpenSearch's
	// "ReleasableBytesStreamOutput cannot hold more than 2GB of data" when
	// a batch of large documents overflows a single internal transport
	// message) rather than per-document failures.
	//
	// This is reported alongside completed:true with an empty
	// response.failures, so it must be checked independently - treating a
	// populated Error as success just because failures is empty would
	// silently accept a reindex that only got a fraction of the way
	// through.
	Error *struct {
		Type   string `json:"type"`
		Reason string `json:"reason"`
	} `json:"error"`
}

// getOpensearchTaskStatus polls a single reindex task by ID (GET
// _tasks/<id>), returning whether it has completed and a human-readable
// summary of any per-document failures reported in its final response.
func getOpensearchTaskStatus(foundClient opensearchapi.Client, opensearchUrl, taskID string) (bool, []string, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/_tasks/%s", opensearchUrl, taskID), nil)
	if err != nil {
		return false, nil, err
	}

	resp, err := foundClient.Client.Transport.Perform(req)
	if err != nil {
		return false, nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, nil, err
	}

	if resp.StatusCode == 403 {
		return false, nil, fmt.Errorf("failed checking task %s: permission denied (403) - the OpenSearch role used by Shuffle needs the cluster permission 'cluster:monitor/task/get' to poll reindex tasks to completion: %s", taskID, string(body))
	}
	if resp.StatusCode >= 300 {
		return false, nil, fmt.Errorf("failed checking task %s: %s", taskID, string(body))
	}

	parsed := opensearchTaskStatusResponse{}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return false, nil, err
	}
	if parsed.Error != nil {
		// Task-level fatal error (aborted the whole reindex, distinct from
		// per-document failures below) - never treat this as success even
		// though it's reported with completed:true.
		return true, nil, fmt.Errorf("reindex task %s aborted with a fatal error (%s): %s", taskID, parsed.Error.Type, parsed.Error.Reason)
	}
	if !parsed.Completed {
		return false, nil, nil
	}

	failures := make([]string, 0, len(parsed.Response.Failures))
	for _, f := range parsed.Response.Failures {
		failures = append(failures, fmt.Sprintf("%s/%s: %s", f.Index, f.ID, f.Cause.Reason))
	}

	return true, failures, nil
}

// setOpensearchIndexWriteBlock toggles index.blocks.write on an index. Used
// to briefly freeze the legacy source index for a final catch-up reindex
// pass before trusting a document-count comparison enough to delete it.
func setOpensearchIndexWriteBlock(foundClient opensearchapi.Client, opensearchUrl, indexName string, block bool) error {
	body, err := json.Marshal(map[string]interface{}{
		"index.blocks.write": block,
	})
	if err != nil {
		return err
	}

	if _, err := foundClient.Indices.Settings.Put(context.Background(), opensearchapi.SettingsPutReq{
		Indices: []string{indexName},
		Body:    bytes.NewReader(body),
	}); err != nil {
		return fmt.Errorf("failed setting write block=%v on %s: %w", block, indexName, err)
	}

	return nil
}

// checkOpensearchIndexExists reports whether indexName currently exists,
// via a plain HEAD (200 = exists, 404 = doesn't).
func checkOpensearchIndexExists(foundClient opensearchapi.Client, opensearchUrl, indexName string) (bool, error) {
	resp, err := foundClient.Indices.Exists(context.Background(), opensearchapi.IndicesExistsReq{Indices: []string{indexName}})
	if err != nil {
		if resp != nil && resp.StatusCode == 404 {
			return false, nil
		}
		return false, fmt.Errorf("failed checking index %s: %w", indexName, err)
	}

	return true, nil
}

// refreshOpensearchIndex forces a refresh (POST <index>/_refresh) so
// documents written moments ago become visible to _count/_search
// immediately, instead of waiting for the index's normal refresh_interval
// (30s by default on Shuffle-created indices). Without this,
// getOpensearchIndexCount can under-count an index that just received
// writes (e.g. the tail of a reindex catch-up copy), causing a false
// "target count still behind source count" failure that would never
// converge for an index still receiving writes right up to the
// write-block.
func refreshOpensearchIndex(foundClient opensearchapi.Client, opensearchUrl, indexName string) error {
	_, err := foundClient.Indices.Refresh(context.Background(), &opensearchapi.IndicesRefreshReq{Indices: []string{indexName}})
	if err != nil {
		return fmt.Errorf("failed refreshing index %s: %w", indexName, err)
	}
	return nil
}

// getOpensearchIndexCount returns the current document count for indexName
// via _count. Callers that need this to be accurate right after a write
// should call refreshOpensearchIndex first.
func getOpensearchIndexCount(foundClient opensearchapi.Client, opensearchUrl, indexName string) (int64, error) {
	resp, err := foundClient.Indices.Count(context.Background(), &opensearchapi.IndicesCountReq{Indices: []string{indexName}})
	if err != nil {
		return 0, fmt.Errorf("failed counting index %s: %w", indexName, err)
	}

	return int64(resp.Count), nil
}

// startOpensearchReindexTask starts an async (wait_for_completion=false)
// _reindex from sourceIndex to targetIndex with conflicts:proceed (so
// pre-existing target documents are skipped, not treated as errors), and
// returns the OpenSearch task ID for polling via getOpensearchTaskStatus.
// Returns ("", nil) - not an error - if a matching task already exists
// (resource_already_exists_exception), since that means another caller
// already started an equivalent reindex.
func startOpensearchReindexTask(foundClient opensearchapi.Client, opensearchUrl, sourceIndex, targetIndex string) (string, error) {
	payload := map[string]interface{}{
		"source": map[string]interface{}{
			"index": sourceIndex,
			// Caps how many source documents OpenSearch fetches per
			// underlying batch. Left at the default (1000), a batch of
			// large documents (workflow execution results routinely run
			// into the hundreds of KB each) can overflow a single internal
			// transport message and abort the entire reindex with
			// "ReleasableBytesStreamOutput cannot hold more than 2GB of
			// data" - a fatal task-level error, not a per-document failure
			// (see the Error field on opensearchTaskStatusResponse). A
			// small fixed batch size keeps each batch comfortably under
			// that limit regardless of how large individual documents get.
			"size": 100,
		},
		"dest": map[string]interface{}{
			"index": targetIndex,
		},
		"conflicts": "proceed",
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	resp, err := foundClient.Reindex(context.Background(), opensearchapi.ReindexReq{
		Body:   bytes.NewReader(body),
		Params: opensearchapi.ReindexParams{WaitForCompletion: opensearchapi.ToPointer(false)},
	})
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "resource_already_exists_exception") {
			return "", nil
		}
		return "", fmt.Errorf("failed starting reindex %s -> %s: %w", sourceIndex, targetIndex, err)
	}

	if strings.TrimSpace(resp.Task) == "" {
		return "", fmt.Errorf("reindex task missing in response")
	}

	return resp.Task, nil
}

// deleteOpensearchIndex deletes indexName. Treats "already doesn't exist"
// (404) as success, so it's safe to call redundantly (e.g. after a partial
// retry) without special-casing the not-found case at every call site.
func deleteOpensearchIndex(foundClient opensearchapi.Client, opensearchUrl, indexName string) error {
	resp, err := foundClient.Indices.Delete(context.Background(), opensearchapi.IndicesDeleteReq{Indices: []string{indexName}})
	if err != nil {
		if resp != nil && resp.Inspect().Response != nil && resp.Inspect().Response.StatusCode == 404 {
			return nil
		}
		return fmt.Errorf("failed deleting index %s: %w", indexName, err)
	}

	return nil
}

type opensearchAliasState struct {
	Present      bool
	IsWriteIndex bool
}

// shuffleOwnedOpensearchIndexPatterns returns a comma-separated index
// pattern list matching only the indices Shuffle itself manages
// (GetOpensearchBaseIndices, combined with whatever
// SHUFFLE_OPENSEARCH_INDEX_PREFIX is configured - which defaults to empty,
// i.e. no prefix).
//
// Scoping the cluster-wide _cat/indices and _alias lookups below to this
// pattern lets a least-privilege OpenSearch role grant
// indices:monitor/settings/get only on Shuffle's own indices instead of
// requiring visibility into every index in the cluster (which
// shared/enterprise clusters with other tenants' indices typically won't
// grant) - e.g. a role scoped to exactly "shuffle_*".
//
// When a prefix is configured, this returns a single "<prefix>_*" pattern
// rather than one "<prefix>_<baseIndex>*" per base index: a legacy
// double-prefixed name (e.g. "shuffle_shuffle_notifications-000001", from
// the historical double-prefix bug) does not start with
// "shuffle_notifications", but it still starts with "shuffle_" - so this
// stays a strict subset of the customary "<prefix>_*" role grant while
// still catching any depth of prefix duplication.
// opensearchIndexBelongsTo strictly re-validates every name this turns up,
// so the wider net here only widens what gets considered, never what gets
// migrated.
//
// Without a prefix, "<prefix>_*" would be just "_*" (matching nothing
// useful), so each base index keeps its own unprefixed "<baseIndex>*"
// pattern instead - double-prefixing cannot occur without a prefix to
// duplicate in the first place.
func shuffleOwnedOpensearchIndexPatterns() string {
	prefix := strings.ToLower(strings.TrimSpace(os.Getenv("SHUFFLE_OPENSEARCH_INDEX_PREFIX")))
	if prefix != "" {
		return prefix + "_*"
	}

	baseIndices := GetOpensearchBaseIndices()
	patterns := make([]string, 0, len(baseIndices))
	for _, baseIndex := range baseIndices {
		patterns = append(patterns, strings.ToLower(baseIndex)+"*")
	}

	return strings.Join(patterns, ",")
}

// OpensearchAliasResponse is the shape of a GET <index>/_alias response.
type OpensearchAliasResponse map[string]OpensearchAliasEntry

// OpensearchAliasEntry holds the aliases attached to a single index.
type OpensearchAliasEntry struct {
	Aliases map[string]json.RawMessage `json:"aliases"`
}

// getOpensearchAliases returns, for every Shuffle-owned index
// (shuffleOwnedOpensearchIndexPatterns), which aliases are attached to it
// and whether each is the write index for that alias - the data
// resolveAliasWriteIndex/selectOpensearchAliasTargets are built on.
func getOpensearchAliases(foundClient opensearchapi.Client, opensearchUrl string) (map[string]map[string]opensearchAliasState, error) {
	aliasReq, err := http.NewRequest("GET", fmt.Sprintf("%s/%s/_alias", opensearchUrl, shuffleOwnedOpensearchIndexPatterns()), nil)
	if err != nil {
		return nil, err
	}

	aliasResp, err := foundClient.Client.Transport.Perform(aliasReq)
	if err != nil {
		return nil, err
	}

	aliasBody, err := io.ReadAll(aliasResp.Body)
	if err != nil {
		aliasResp.Body.Close()
		return nil, err
	}
	aliasResp.Body.Close()

	if aliasResp.StatusCode >= 300 {
		return nil, fmt.Errorf("failed reading opensearch aliases: %s", string(aliasBody))
	}

	rawAliasInfo := OpensearchAliasResponse{}
	if err := json.Unmarshal(aliasBody, &rawAliasInfo); err != nil {
		return nil, err
	}

	aliasInfo := map[string]map[string]opensearchAliasState{}
	type aliasDetails struct {
		IsWriteIndex bool `json:"is_write_index,omitempty"`
	}

	for indexName, aliasEntry := range rawAliasInfo {
		aliasInfo[indexName] = map[string]opensearchAliasState{}
		for aliasName, aliasRaw := range aliasEntry.Aliases {
			details := aliasDetails{}
			_ = json.Unmarshal(aliasRaw, &details)
			aliasInfo[indexName][aliasName] = opensearchAliasState{Present: true, IsWriteIndex: details.IsWriteIndex}
		}
	}

	return aliasInfo, nil
}

// getOpensearchIndices resolves the concrete backing indices matching
// Shuffle's own index patterns.
//
// Deliberately implemented via /_settings rather than /_cat/indices:
// _cat/* endpoints are cluster-level actions in OpenSearch's security
// plugin (requiring cluster:monitor/* even when the path includes an index
// pattern) and, once granted, let the credential query /_cluster/state or
// unscoped /_cat/indices directly to see every index's
// name/mappings/settings cluster-wide - a real cross-tenant metadata leak
// on a shared/multi-tenant cluster.
//
// /_settings (and /_alias below), being genuine per-index API endpoints,
// are enforced per matched index by the security plugin: a request for a
// pattern outside the role's granted index_patterns is rejected outright.
func getOpensearchIndices(foundClient opensearchapi.Client, opensearchUrl string) ([]string, error) {
	resp, err := foundClient.Indices.Settings.Get(context.Background(), &opensearchapi.SettingsGetReq{
		Indices: []string{shuffleOwnedOpensearchIndexPatterns()},
		Params:  opensearchapi.SettingsGetParams{FilterPath: []string{"*.settings.index.provided_name"}},
	})
	if err != nil {
		return nil, fmt.Errorf("failed reading opensearch indices: %w", err)
	}

	indices := []string{}
	for indexName := range resp.Indices {
		if strings.TrimSpace(indexName) != "" {
			indices = append(indices, indexName)
		}
	}

	return indices, nil
}

// opensearchIndexBelongsTo reports whether name (an index name or an alias
// name) is baseIndex, a generation of it ("<alias>-000001"), or a legacy
// variant with the SHUFFLE_OPENSEARCH_INDEX_PREFIX applied more than once
// (a historical bug double- or triple-prefixed some index names).
//
// Rather than guessing one specific corrupted variant up front (e.g.
// "prefix_prefix_baseIndex") and checking for that exact string, this
// strips one prefix layer at a time and re-checks, so any number of
// accidental repeats is recognized uniformly.
func opensearchIndexBelongsTo(name, baseIndex, prefix string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	baseIndex = strings.ToLower(strings.TrimSpace(baseIndex))
	prefixed := ""
	if prefix != "" {
		prefixed = prefix + "_"
	}

	for {
		if name == baseIndex || strings.HasPrefix(name, baseIndex+"-") {
			return true
		}

		if prefixed == "" || !strings.HasPrefix(name, prefixed) {
			return false
		}

		name = strings.TrimPrefix(name, prefixed)
	}
}

// selectOpensearchAliasTargets finds every existing index that belongs to
// baseIndex - by alias attachment or by generation-numbered name prefix,
// including legacy multi-prefixed variants (see opensearchIndexBelongsTo)
// - so callers can migrate all of them onto the correct alias in one pass.
//
// Returns the full candidate list plus which one is (or should become) the
// write index, preferring an already-correctly-named generation over the
// highest generation number.
func selectOpensearchAliasTargets(baseIndex, prefix string, aliasInfo map[string]map[string]opensearchAliasState, allIndices []string) ([]string, string) {
	expectedAlias := strings.ToLower(GetESIndexPrefix(baseIndex))
	candidateMap := map[string]bool{}

	for indexName, aliases := range aliasInfo {
		for aliasName, state := range aliases {
			if state.Present && opensearchIndexBelongsTo(aliasName, baseIndex, prefix) {
				candidateMap[indexName] = true
				break
			}
		}
	}

	for _, indexName := range allIndices {
		if opensearchIndexBelongsTo(indexName, baseIndex, prefix) {
			candidateMap[indexName] = true
		}
	}

	targetIndices := []string{}
	for indexName := range candidateMap {
		targetIndices = append(targetIndices, indexName)
	}

	if len(targetIndices) == 0 {
		return targetIndices, ""
	}

	sort.Slice(targetIndices, func(i, j int) bool {
		gi := getOpensearchGeneration(targetIndices[i])
		gj := getOpensearchGeneration(targetIndices[j])
		if gi == gj {
			return targetIndices[i] > targetIndices[j]
		}
		return gi > gj
	})

	writeIndex := ""
	for _, indexName := range targetIndices {
		if indexName == expectedAlias || strings.HasPrefix(indexName, expectedAlias+"-") {
			writeIndex = indexName
			break
		}
	}

	if writeIndex == "" {
		writeIndex = targetIndices[0]
	}

	return targetIndices, writeIndex
}

// getOpensearchGeneration extracts the trailing "-NNNNNN" rollover
// generation number from an index name (e.g. 2 for "shuffle_logs-000002"),
// or 0 if the name has no numeric suffix.
func getOpensearchGeneration(indexName string) int {
	parts := strings.Split(indexName, "-")
	if len(parts) < 2 {
		return 0
	}

	generation := parts[len(parts)-1]
	value, err := strconv.Atoi(generation)
	if err != nil {
		return 0
	}

	return value
}

// OpensearchIndexConfig is the parsed shape of a custom
// OPENSEARCH_INDEX_CONFIG override, or the body built for a default index
// create call.
// Aliases is untyped (json.RawMessage) because its only use is a
// len() presence check before being stripped - see createOpensearchIndex.
type OpensearchIndexConfig struct {
	Aliases  map[string]json.RawMessage `json:"aliases,omitempty"`
	Settings map[string]interface{}     `json:"settings,omitempty"`
	Mappings map[string]interface{}     `json:"mappings,omitempty"`
}

// createOpensearchIndex creates indexName with either the operator-supplied
// OPENSEARCH_INDEX_CONFIG (with any aliases stripped - alias attachment is
// handled separately by the caller) or Shuffle's default settings/mappings
// (3 shards, 1 replica, 30s refresh, strings_as_keywords dynamic template).
//
// baseIndex (the unprefixed, un-generationed alias name, e.g.
// "workflowexecution_live") is used to look up opensearchCoreMappings so a
// freshly created index already has its curated field types instead of
// relying on migrateOpensearchSingleIndex to correct them moments later.
// Pass "" if no curated mapping applies (e.g. an index not in
// opensearchCoreMappings).
func createOpensearchIndex(foundClient opensearchapi.Client, opensearchUrl, indexName, baseIndex string) error {
	indexConfig := OpensearchIndexConfig{}
	customConfig := strings.TrimSpace(os.Getenv("OPENSEARCH_INDEX_CONFIG"))
	if customConfig != "" {
		if err := json.Unmarshal([]byte(customConfig), &indexConfig); err != nil {
			return fmt.Errorf("invalid OPENSEARCH_INDEX_CONFIG: %w", err)
		}

		if len(indexConfig.Aliases) > 0 {
			indexConfig.Aliases = nil
		}
	}

	if len(indexConfig.Settings) == 0 && len(indexConfig.Mappings) == 0 {
		mappings := opensearchDynamicMappingSettings()
		if baseIndex != "" {
			if props, ok := opensearchCoreMappings[baseIndex]["properties"]; ok {
				mappings["properties"] = props
			}
		}

		indexConfig = OpensearchIndexConfig{
			Settings: getOpensearchDefaultIndexSettings(),
			Mappings: mappings,
		}
	}

	indexConfigJson, err := json.Marshal(indexConfig)
	if err != nil {
		return err
	}

	if _, err := foundClient.Indices.Create(context.Background(), opensearchapi.IndicesCreateReq{
		Index: indexName,
		Body:  bytes.NewReader(indexConfigJson),
	}); err != nil {
		return fmt.Errorf("failed creating index %s: %w", indexName, err)
	}

	return nil
}

// OpensearchAliasActionsRequest is the body of a POST _aliases request.
type OpensearchAliasActionsRequest struct {
	Actions []OpensearchAliasAction `json:"actions"`
}

// OpensearchAliasAction is a single add or remove action within an
// OpensearchAliasActionsRequest.
type OpensearchAliasAction struct {
	Add    *OpensearchAliasActionTarget `json:"add,omitempty"`
	Remove *OpensearchAliasActionTarget `json:"remove,omitempty"`
}

// OpensearchAliasActionTarget identifies the index/alias (and, for adds,
// whether it should become the write index) an OpensearchAliasAction
// applies to.
type OpensearchAliasActionTarget struct {
	Index        string `json:"index"`
	Alias        string `json:"alias"`
	IsWriteIndex *bool  `json:"is_write_index,omitempty"`
}

// updateOpensearchAliases applies a batch of alias add/remove actions
// atomically via POST _aliases, e.g. moving a write alias from one
// generation to another in a single request.
func updateOpensearchAliases(foundClient opensearchapi.Client, opensearchUrl string, actions []OpensearchAliasAction) error {
	aliasActions := OpensearchAliasActionsRequest{Actions: actions}
	aliasBody, err := json.Marshal(aliasActions)
	if err != nil {
		return err
	}

	if _, err := foundClient.Aliases(context.Background(), opensearchapi.AliasesReq{Body: bytes.NewReader(aliasBody)}); err != nil {
		return fmt.Errorf("failed updating aliases: %w", err)
	}

	return nil
}

// HandleFixOpensearchPrefix is the admin-triggered HTTP endpoint for
// FixOpensearchIndexPrefix - lets an operator manually re-run the
// alias/index verification and repair instead of waiting for the next
// backend restart.
func HandleFixOpensearchPrefix(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in opensearch prefix fix: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Api authentication failed"}`))
		return
	}

	if user.Role != "admin" {
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Only admins or support can run this"}`))
		return
	}

	ctx := GetContext(request)
	result, err := FixOpensearchIndexPrefix(ctx)
	if err != nil {
		log.Printf("[ERROR] Failed fixing opensearch index prefix: %s", err)
		result.Success = false
		result.Reason = err.Error()
		responseData, _ := json.Marshal(result)
		resp.WriteHeader(500)
		resp.Write(responseData)
		return
	}

	responseData, err := json.Marshal(result)
	if err != nil {
		resp.WriteHeader(500)
		resp.Write([]byte(`{"success": false, "reason": "Failed JSON parsing"}`))
		return
	}

	resp.Header().Set("Content-Type", "application/json")
	resp.WriteHeader(200)
	resp.Write(responseData)
}
