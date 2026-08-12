package shuffle

import (
	"encoding/json"
	"sort"
	"testing"
)

func TestBuildAliasSearchBody(t *testing.T) {
	body, err := buildAliasSearchBody("last_cleared", "abc-123")
	if err != nil {
		t.Fatalf("buildAliasSearchBody: %v", err)
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if doc["size"] != float64(1) {
		t.Fatalf("expected size 1, got %v", doc["size"])
	}

	query := doc["query"].(map[string]interface{})
	ids := query["ids"].(map[string]interface{})["values"].([]interface{})
	if len(ids) != 1 || ids[0] != "abc-123" {
		t.Fatalf("unexpected ids values: %v", ids)
	}

	sortArr := doc["sort"].([]interface{})
	first := sortArr[0].(map[string]interface{})["last_cleared"].(map[string]interface{})
	if first["order"] != "desc" || first["unmapped_type"] != "long" {
		t.Fatalf("unexpected sort: %v", first)
	}
}

func TestBuildAliasSearchBodyNoSort(t *testing.T) {
	body, err := buildAliasSearchBody("", "x")
	if err != nil {
		t.Fatalf("buildAliasSearchBody: %v", err)
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if _, ok := doc["sort"]; ok {
		t.Fatalf("expected no sort when sortField empty")
	}
}

func TestCollapseGenerationOrdering(t *testing.T) {
	gens := []string{"org_stats-000001", "org_stats-000004", "org_stats-000002"}
	sort.Slice(gens, func(i, j int) bool {
		return getOpensearchGeneration(gens[i]) > getOpensearchGeneration(gens[j])
	})

	want := []string{"org_stats-000004", "org_stats-000002", "org_stats-000001"}
	for i := range want {
		if gens[i] != want[i] {
			t.Fatalf("expected %v, got %v", want, gens)
		}
	}
}

func TestResolveAppendIndexCreationTarget(t *testing.T) {
	tests := []struct {
		name              string
		existingIndices   []string
		index             string
		wantTarget        string
		wantAlreadyExists bool
	}{
		{
			name:              "fresh index with no existing generations",
			existingIndices:   []string{"some_other_index-000001"},
			index:             "workflowexecution",
			wantTarget:        "workflowexecution-000001",
			wantAlreadyExists: false,
		},
		{
			name:              "already-collapsed archive sitting at generation 3",
			existingIndices:   []string{"workflowexecution-000003", "shuffle_logs-000001"},
			index:             "workflowexecution",
			wantTarget:        "workflowexecution-000003",
			wantAlreadyExists: true,
		},
		{
			name:              "multiple existing generations picks the highest",
			existingIndices:   []string{"workflowexecution-000001", "workflowexecution-000002", "workflowexecution-000005"},
			index:             "workflowexecution",
			wantTarget:        "workflowexecution-000005",
			wantAlreadyExists: true,
		},
		{
			name:              "does not match a different index with a similar prefix",
			existingIndices:   []string{"workflowexecution_live-000001"},
			index:             "workflowexecution",
			wantTarget:        "workflowexecution-000001",
			wantAlreadyExists: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target, alreadyExists := resolveAppendIndexCreationTarget(tt.existingIndices, tt.index)
			if target != tt.wantTarget || alreadyExists != tt.wantAlreadyExists {
				t.Fatalf("expected (%s, %v), got (%s, %v)", tt.wantTarget, tt.wantAlreadyExists, target, alreadyExists)
			}
		})
	}
}

func TestOpensearchMappingsDiffer(t *testing.T) {
	kw := func() map[string]interface{} { return map[string]interface{}{"type": "keyword"} }

	// datastore_ngram desired: key, org_id keyword; amount long
	if !opensearchMappingsDiffer("datastore_ngram", nil) {
		t.Fatalf("expected differ when no properties present")
	}

	if opensearchMappingsDiffer("datastore_ngram", map[string]interface{}{
		"key":    kw(),
		"org_id": kw(),
		"amount": map[string]interface{}{"type": "long"},
	}) {
		t.Fatalf("expected no differ when datastore_ngram fields match")
	}

	// amount wrong type (keyword instead of long) -> differs
	if !opensearchMappingsDiffer("datastore_ngram", map[string]interface{}{
		"key":    kw(),
		"org_id": kw(),
		"amount": kw(),
	}) {
		t.Fatalf("expected differ on wrong type")
	}

	// notifications.image must be index:false; live index:true -> differs
	if !opensearchMappingsDiffer("notifications", map[string]interface{}{
		"id":          kw(),
		"org_id":      kw(),
		"user_id":     kw(),
		"created_at":  map[string]interface{}{"type": "date", "format": "epoch_second"},
		"updated_at":  map[string]interface{}{"type": "date", "format": "epoch_second"},
		"amount":      map[string]interface{}{"type": "long"},
		"image":       map[string]interface{}{"type": "keyword", "index": true},
		"read":        map[string]interface{}{"type": "boolean"},
		"ignored":     map[string]interface{}{"type": "boolean"},
		"dismissable": map[string]interface{}{"type": "boolean"},
		"personal":    map[string]interface{}{"type": "boolean"},
	}) {
		t.Fatalf("expected differ when image is indexed")
	}

	// notifications with image index:false matches
	if opensearchMappingsDiffer("notifications", map[string]interface{}{
		"id":                  kw(),
		"org_id":              kw(),
		"user_id":             kw(),
		"execution_id":        kw(),
		"workflow_id":         kw(),
		"org_notification_id": kw(),
		"created_at":          map[string]interface{}{"type": "date", "format": "epoch_second"},
		"updated_at":          map[string]interface{}{"type": "date", "format": "epoch_second"},
		"amount":              map[string]interface{}{"type": "long"},
		"image":               map[string]interface{}{"type": "keyword", "index": false},
		"read":                map[string]interface{}{"type": "boolean"},
		"ignored":             map[string]interface{}{"type": "boolean"},
		"dismissable":         map[string]interface{}{"type": "boolean"},
		"personal":            map[string]interface{}{"type": "boolean"},
	}) {
		t.Fatalf("expected no differ when image is not indexed")
	}
}
func TestWorkflowExecutionLiveReusesExecutionMapping(t *testing.T) {
	liveMapping := opensearchMappingsFor("workflowexecution_live")
	archiveMapping := opensearchMappingsFor("workflowexecution")

	liveProps, _ := liveMapping["properties"].(map[string]interface{})
	archiveProps, _ := archiveMapping["properties"].(map[string]interface{})
	if len(liveProps) == 0 || len(liveProps) != len(archiveProps) {
		t.Fatalf("expected workflowexecution_live mapping to match workflowexecution mapping, got %d vs %d fields", len(liveProps), len(archiveProps))
	}
}
