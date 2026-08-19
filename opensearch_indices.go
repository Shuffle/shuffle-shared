// This file is the single declarative source of truth for OpenSearch index
// definitions: which base indices Shuffle explicitly manages, which of
// those are safe to put behind alias+rollover, and their curated field mappings.
// Nothing in this file talks to OpenSearch over the network - it only describes shape.
//
// For everything that acts on this data (creating indices, migrating mappings,
// rolling over, fixing alias collisions, etc.), see opensearch_lifecycle.go.
package shuffle

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// opensearchIgnoreAboveLength is the single source of truth for the
// "ignore_above" setting applied to dynamically mapped string fields (via the
// strings_as_keywords dynamic template) across all explicitly managed
// indices. It mirrors OpenSearch's own default dynamic keyword mapping
// (text+keyword sub-field with ignore_above:256).
const opensearchIgnoreAboveLength = 256

// Default index settings applied to every explicitly managed index (unless
// overridden - see getOpensearchDefaultIndexSettings), and default rollover
// thresholds applied to every rollover-eligible index (unless overridden -
// see getOpensearchDefaultRolloverConditions).
const (
	opensearchDefaultShards          = 3
	opensearchDefaultReplicas        = 1
	opensearchDefaultRefreshInterval = "30s"

	opensearchDefaultRolloverMaxAge  = "90d"
	opensearchDefaultRolloverMaxSize = "40gb"
	opensearchDefaultRolloverMaxDocs = 1000000
)

// getOpensearchDefaultIndexSettings returns the default
// number_of_shards/number_of_replicas/refresh_interval settings block for a
// freshly created index. Override the whole set via OPENSEARCH_INDEX_CONFIG.
func getOpensearchDefaultIndexSettings() map[string]interface{} {
	return map[string]interface{}{
		"number_of_shards":   opensearchDefaultShards,
		"number_of_replicas": opensearchDefaultReplicas,
		"refresh_interval":   opensearchDefaultRefreshInterval,
	}
}

// getOpensearchDefaultRolloverConditions returns Shuffle's default rollover
// thresholds in the Index Rollover API's "max_*" key format (used by
// InitOpensearchIndices/FixOpensearchIndexPrefix to build a direct
// POST <alias>/_rollover body). Override the whole set via
// OPENSEARCH_INDEX_ROLLOVER.
func getOpensearchDefaultRolloverConditions() map[string]interface{} {
	return map[string]interface{}{
		"max_age":  opensearchDefaultRolloverMaxAge,
		"max_size": opensearchDefaultRolloverMaxSize,
		"max_docs": opensearchDefaultRolloverMaxDocs,
	}
}

// opensearchStringsAsKeywordsDynamicTemplate returns the dynamic template
// that maps every dynamically-added string field to a plain keyword with
// opensearchIgnoreAboveLength, matching OpenSearch's own default dynamic
// string mapping. Shared by every index-create/mapping body so the
// ignore_above value has one source of truth.
func opensearchStringsAsKeywordsDynamicTemplate() map[string]interface{} {
	return map[string]interface{}{
		"strings_as_keywords": map[string]interface{}{
			"match_mapping_type": "string",
			"mapping":            map[string]interface{}{"type": "keyword", "ignore_above": opensearchIgnoreAboveLength},
		},
	}
}

// opensearchDynamicMappingSettings returns the "mappings"-level settings
// that must accompany opensearchStringsAsKeywordsDynamicTemplate on every
// index-create body, so dynamically-added fields are consistently typed by
// that template alone.
//
// "date_detection" defaults to true in OpenSearch and runs BEFORE custom
// dynamic_templates are considered: a dynamically-added string field whose
// first-seen value happens to parse as a date (e.g. a user-authored
// workflow action parameter's example value like "2024-01-01") gets
// classified as "date" by this built-in check, which pre-empts
// match_mapping_type:"string" ever matching - completely bypassing the
// strings_as_keywords template for that field. Any later document whose
// value for that same field path is plain text then fails with "mapper
// [...] cannot be changed from type [date] to [keyword]", permanently
// (mappings are immutable once set). Disabling date_detection ensures only
// strings_as_keywords governs dynamic string typing, regardless of what a
// field's value happens to look like.
//
// "numeric_detection" is the same content-sniffing hazard for numbers
// instead of dates (a string like "42" would get promoted to long/double
// instead of keyword). It already defaults to false, so this isn't fixing
// an active bug - it's set explicitly so correctness here doesn't depend on
// an OpenSearch/cluster-level default that could change out from under us.
func opensearchDynamicMappingSettings() map[string]interface{} {
	return map[string]interface{}{
		"date_detection":    false,
		"numeric_detection": false,
		"dynamic_templates": []map[string]interface{}{
			opensearchStringsAsKeywordsDynamicTemplate(),
		},
	}
}

// Create ElasticSearch/OpenSearch index prefix
// It is used where a single cluster of ElasticSearch/OpenSearch utilized by several
// Shuffle instance
// E.g. Instance1_Workflowapp
func GetESIndexPrefix(index string) string {
	prefix := os.Getenv("SHUFFLE_OPENSEARCH_INDEX_PREFIX")
	if len(prefix) > 0 {
		return fmt.Sprintf("%s_%s", prefix, index)
	}

	return index
}

// GetOpensearchBaseIndices returns a list of indices managed by Shuffle.
// Shuffle also uses other indices, that are implicitly created on first write.
// Indices in this list are explicitly created by Shuffle on startup.
func GetOpensearchBaseIndices() []string {
	return []string{
		"workflowexecution",
		"workflowexecution_live",
		"datastore_ngram",
		"org_cache",
		"org_cache_revisions",
		"notifications",
		"shuffle_logs",
		"environments",
		"org_statistics",
		"workflowapp",
		"workflow",
		"workflow_revisions",
		"datastore_category",
	}
}

// GetOpensearchRolloverIndices returns the subset of base indices that are
// genuinely append-only (or, for workflowexecution, append-only AFTER the
// hot/cold lifecycle split below) and therefore want alias + automatic
// rollover + ISM retention.
func GetOpensearchRolloverIndices() []string {
	return []string{
		"shuffle_logs",
		// Content-addressed / fresh-id-per-write revision stores: a given _id is
		// never rewritten once created, so alias+rollover is safe here.
		"workflow_revisions",  // _id = md5(name+id+actions+triggers+variables)
		"org_cache_revisions", // _id = <org>_<key>[_<category>]_<uuid>
		// workflowexecution is the ARCHIVE for confirmed-terminal
		// executions (see execution_lifecycle.go). Nothing writes to it
		// except archiveExecutionDocument, which resolves any existing copy of an
		// execution_id to its concrete backing index before writing (rather than
		// writing through the alias blindly), so rollover is safe here even though
		// the same execution_id can in rare cases be revisited (see the unarchive
		// path in writeExecutionDocument).
		"workflowexecution",
	}
}

// opensearchCoreMappings holds the curated field mappings for base indices:
// applied to fresh index-create bodies, and used as the target that
// migrateOpensearchSingleIndex (opensearch_lifecycle.go) compares live
// indices against on every startup - a mismatch is migrated onto these
// mappings automatically via reindex + alias cutover, since OpenSearch
// mappings themselves are immutable in place. Keys are the base index names
// from GetOpensearchBaseIndices.
//
// id/ref fields are keyword, date/epoch fields are date (epoch_second), and
// numeric counters/priorities are long so numeric sorting and filtering work.
// The default strings_as_keywords dynamic template only handles strings; these
// explicit types keep the mapping stable regardless of how a value is written.
//
// Large/binary blobs (e.g. images) are mapped with index:false + doc_values:false:
// they stay retrievable via _source but are never added to the inverted index
// or doc_values, avoiding index bloat and too-big-field failures. Add a field
// only when its type is known to be stable and it is actually sorted/filtered
// on (or when it must be excluded from indexing).
//
// created/edited/started_at on workflowexecution are deliberately "long", not
// "date": these three fields are sorted across workflowexecution_live+archive
// (started_at, in GetUnfinishedExecutions/GetAllWorkflowExecutions[V2]/
// GetWorkflowRunsBySearch) or across archive generations (created/edited, in
// findExecutionInArchive). OpenSearch stores "date" doc values internally as
// epoch milliseconds regardless of the "format" annotation - format only
// affects range-query parsing, not the raw value a sort clause returns. Any
// pre-existing customer index created before this mapping existed has these
// fields dynamically inferred as "long" (the app always wrote raw epoch
// SECONDS as JSON numbers). Mapping them "date" here would make freshly
// created generations sort in milliseconds while old/legacy generations sort
// in seconds - since ms values are ~1000x larger, every doc in a
// date-mapped generation would silently outrank every doc in a long-mapped
// generation regardless of true chronological order.
// Keeping these three fields "long" matches what already-deployed clusters
// have and keeps sort units identical across every generation, old and new.
// completed_at has no cross-generation/cross-index sort today (only a
// same-index numeric range filter in the archival sweep), so it is left as
// "date" for existing single-index range-query compatibility.
var opensearchCoreMappings = map[string]map[string]interface{}{
	"workflowexecution": {
		"properties": map[string]interface{}{
			"execution_id":  map[string]interface{}{"type": "keyword"},
			"workflow_id":   map[string]interface{}{"type": "keyword"},
			"execution_org": map[string]interface{}{"type": "keyword"},
			"status":        map[string]interface{}{"type": "keyword"},
			"created":       map[string]interface{}{"type": "long"},
			"edited":        map[string]interface{}{"type": "long"},
			"started_at":    map[string]interface{}{"type": "long"},
			"completed_at":  map[string]interface{}{"type": "date", "format": "epoch_second"},
			"priority":      map[string]interface{}{"type": "long"},
		},
	},
	"notifications": {
		"properties": map[string]interface{}{
			"id":                  map[string]interface{}{"type": "keyword"},
			"org_id":              map[string]interface{}{"type": "keyword"},
			"user_id":             map[string]interface{}{"type": "keyword"},
			"execution_id":        map[string]interface{}{"type": "keyword"},
			"workflow_id":         map[string]interface{}{"type": "keyword"},
			"org_notification_id": map[string]interface{}{"type": "keyword"},
			"created_at":          map[string]interface{}{"type": "date", "format": "epoch_second"},
			"updated_at":          map[string]interface{}{"type": "date", "format": "epoch_second"},
			"amount":              map[string]interface{}{"type": "long"},
			"image":               map[string]interface{}{"type": "keyword", "index": false, "doc_values": false},
			"read":                map[string]interface{}{"type": "boolean"},
			"ignored":             map[string]interface{}{"type": "boolean"},
			"dismissable":         map[string]interface{}{"type": "boolean"},
			"personal":            map[string]interface{}{"type": "boolean"},
		},
	},
	"org_statistics": {
		"properties": map[string]interface{}{
			"org_id":                      map[string]interface{}{"type": "keyword"},
			"last_cleared":                map[string]interface{}{"type": "date", "format": "epoch_second"},
			"total_app_executions":        map[string]interface{}{"type": "long"},
			"total_workflow_executions":   map[string]interface{}{"type": "long"},
			"total_agent_executions":      map[string]interface{}{"type": "long"},
			"total_agent_tokens":          map[string]interface{}{"type": "long"},
			"total_ai_executions":         map[string]interface{}{"type": "long"},
			"total_app_executions_failed": map[string]interface{}{"type": "long"},
		},
	},
	"datastore_ngram": {
		"properties": map[string]interface{}{
			"key":    map[string]interface{}{"type": "keyword"},
			"org_id": map[string]interface{}{"type": "keyword"},
			"amount": map[string]interface{}{"type": "long"},
		},
	},
	"workflow": {
		"properties": map[string]interface{}{
			"id":           map[string]interface{}{"type": "keyword"},
			"org_id":       map[string]interface{}{"type": "keyword"},
			"created":      map[string]interface{}{"type": "date", "format": "epoch_second"},
			"edited":       map[string]interface{}{"type": "date", "format": "epoch_second"},
			"last_runtime": map[string]interface{}{"type": "long"},
		},
	},
	"workflowapp": {
		"properties": map[string]interface{}{
			"app_id":      map[string]interface{}{"type": "keyword"},
			"app_version": map[string]interface{}{"type": "keyword"},
			"generated":   map[string]interface{}{"type": "boolean"},
			"small_image": map[string]interface{}{"type": "keyword", "index": false, "doc_values": false},
			"large_image": map[string]interface{}{"type": "keyword", "index": false, "doc_values": false},
		},
	},
	"org_cache": {
		"properties": map[string]interface{}{
			"key":    map[string]interface{}{"type": "keyword"},
			"org_id": map[string]interface{}{"type": "keyword"},
		},
	},
}

// ensureOpensearchIndexRolloverAlias sets the
// "plugins.index_state_management.rollover_alias" setting on an index-create
// body to alias, so ISM knows which alias to roll over once this generation
// meets its rollover conditions.
// No-op (returns indexConfig unchanged) if the body can't be parsed as JSON.
func ensureOpensearchIndexRolloverAlias(indexConfig []byte, alias string) []byte {
	unmarshalled := map[string]interface{}{}
	if err := json.Unmarshal(indexConfig, &unmarshalled); err != nil {
		return indexConfig
	}

	settings, ok := unmarshalled["settings"].(map[string]interface{})
	if !ok || settings == nil {
		settings = map[string]interface{}{}
	}

	settings["plugins.index_state_management.rollover_alias"] = alias
	unmarshalled["settings"] = settings

	updated, err := json.Marshal(unmarshalled)
	if err != nil {
		return indexConfig
	}

	return updated
}

// applyOpensearchCoreMappings injects the pragmatic core field mappings for a
// base index into a fresh index-create body.
func applyOpensearchCoreMappings(indexConfig []byte, index string) []byte {
	key := strings.TrimPrefix(strings.ToLower(index), strings.ToLower(GetESIndexPrefix("")))
	properties, ok := opensearchCoreMappings[key]
	if !ok {
		return indexConfig
	}

	unmarshalled := map[string]interface{}{}
	if err := json.Unmarshal(indexConfig, &unmarshalled); err != nil {
		return indexConfig
	}

	mappings, _ := unmarshalled["mappings"].(map[string]interface{})
	if mappings == nil {
		mappings = map[string]interface{}{}
	}

	if _, exists := mappings["properties"]; !exists {
		mappings["properties"] = properties["properties"]
	}
	unmarshalled["mappings"] = mappings

	updated, err := json.Marshal(unmarshalled)
	if err != nil {
		return indexConfig
	}

	return updated
}

// opensearchMappingsFor builds the mappings section (dynamic string->keyword
// template plus the curated core field mappings) for a base index.
func opensearchMappingsFor(baseIndex string) map[string]interface{} {
	mappings := opensearchDynamicMappingSettings()

	if props, ok := opensearchCoreMappings[baseIndex]["properties"]; ok {
		mappings["properties"] = props
	}

	return mappings
}

// opensearchMappingsDiffer reports whether the live index mapping (its
// "properties" subtree) is missing any curated field, or has a field whose
// type/format/indexability no longer matches the desired core mappings. Only
// fields we explicitly map are compared.
func opensearchMappingsDiffer(baseIndex string, actualProps map[string]interface{}) bool {
	desired, ok := opensearchCoreMappings[baseIndex]["properties"].(map[string]interface{})
	if !ok {
		return false
	}

	for name, dv := range desired {
		desiredProp, _ := dv.(map[string]interface{})
		actualProp, exists := actualProps[name].(map[string]interface{})
		if !exists {
			return true
		}

		if fmt.Sprint(desiredProp["type"]) != fmt.Sprint(actualProp["type"]) {
			return true
		}

		if df, ok := desiredProp["format"]; ok && fmt.Sprint(actualProp["format"]) != fmt.Sprint(df) {
			return true
		}

		if fmt.Sprint(desiredProp["index"]) == "false" && fmt.Sprint(actualProp["index"]) != "false" {
			return true
		}
	}

	return false
}
