package shuffle

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestGetNotificationRetentionDaysDefaultDisabled(t *testing.T) {
	os.Unsetenv("OPENSEARCH_NOTIFICATION_RETENTION_DAYS")
	if got := getNotificationRetentionDays(); got != 0 {
		t.Fatalf("expected default 0 (disabled), got %d", got)
	}
}

func TestGetNotificationRetentionDaysOverride(t *testing.T) {
	os.Setenv("OPENSEARCH_NOTIFICATION_RETENTION_DAYS", "30")
	defer os.Unsetenv("OPENSEARCH_NOTIFICATION_RETENTION_DAYS")

	if got := getNotificationRetentionDays(); got != 30 {
		t.Fatalf("expected 30, got %d", got)
	}
}

func TestGetNotificationRetentionDaysInvalidFallsBackToDisabled(t *testing.T) {
	os.Setenv("OPENSEARCH_NOTIFICATION_RETENTION_DAYS", "not-a-number")
	defer os.Unsetenv("OPENSEARCH_NOTIFICATION_RETENTION_DAYS")

	if got := getNotificationRetentionDays(); got != 0 {
		t.Fatalf("expected fallback to disabled (0), got %d", got)
	}
}

func TestSweepOldNotificationsNoOpsWhenDisabled(t *testing.T) {
	os.Unsetenv("OPENSEARCH_NOTIFICATION_RETENTION_DAYS")

	if err := sweepOldNotifications(nil); err != nil {
		t.Fatalf("expected nil error when retention disabled (no-op), got %s", err)
	}
}

func TestBuildNotificationRetentionQuery(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	query := buildNotificationRetentionQuery(now, 90)

	boolQuery, ok := query["query"].(map[string]interface{})["bool"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected bool query, got %v", query)
	}

	must, ok := boolQuery["must"].([]map[string]interface{})
	if !ok || len(must) != 2 {
		t.Fatalf("expected 2 must clauses (read-or-ignored + updated_at cutoff), got %v", must)
	}

	shouldClause, ok := must[0]["bool"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected first clause to be a bool/should for read OR ignored, got %v", must[0])
	}
	should, ok := shouldClause["should"].([]map[string]interface{})
	if !ok || len(should) != 2 {
		t.Fatalf("expected 2 should clauses (read=true, ignored=true), got %v", should)
	}

	rangeQuery, ok := must[1]["range"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected second clause to be a range on updated_at, got %v", must[1])
	}
	updatedAtRange, ok := rangeQuery["updated_at"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected updated_at range, got %v", rangeQuery)
	}

	wantCutoff := now.AddDate(0, 0, -90).Unix()
	if updatedAtRange["lt"] != wantCutoff {
		t.Fatalf("expected cutoff %d, got %v", wantCutoff, updatedAtRange["lt"])
	}
}

func TestNotificationRetentionFieldMappingWarningsAllCompatible(t *testing.T) {
	fieldTypes := map[string]string{
		"read":       "boolean",
		"ignored":    "boolean",
		"updated_at": "date",
	}

	warnings := notificationRetentionFieldMappingWarnings("notifications", fieldTypes)
	if len(warnings) != 0 {
		t.Fatalf("expected no warnings for compatible mapping, got %v", warnings)
	}
}

func TestNotificationRetentionFieldMappingWarningsLegacyUpdatedAtAsLong(t *testing.T) {
	// Mirrors what a legacy pre-opensearchCoreMappings index looks like: JSON
	// booleans dynamically infer as "boolean" fine, but a raw epoch-second
	// int64 dynamically infers as "long", not "date".
	fieldTypes := map[string]string{
		"read":       "boolean",
		"ignored":    "boolean",
		"updated_at": "long",
	}

	warnings := notificationRetentionFieldMappingWarnings("notifications", fieldTypes)
	if len(warnings) != 1 {
		t.Fatalf("expected exactly 1 warning for updated_at mismatch, got %v", warnings)
	}
	if !strings.Contains(warnings[0], "updated_at") || !strings.Contains(warnings[0], "long") {
		t.Fatalf("expected warning to mention updated_at/long, got %q", warnings[0])
	}
}

func TestNotificationRetentionFieldMappingWarningsReadIgnoredAsKeyword(t *testing.T) {
	fieldTypes := map[string]string{
		"read":       "keyword",
		"ignored":    "keyword",
		"updated_at": "date",
	}

	warnings := notificationRetentionFieldMappingWarnings("notifications", fieldTypes)
	if len(warnings) != 2 {
		t.Fatalf("expected 2 warnings (read + ignored), got %v", warnings)
	}
}

func TestNotificationRetentionFieldMappingWarningsMissingFieldsNotAWarning(t *testing.T) {
	// An empty freshly-created index has no properties yet - absence isn't a
	// mismatch, it just means no docs have been written.
	warnings := notificationRetentionFieldMappingWarnings("notifications", map[string]string{})
	if len(warnings) != 0 {
		t.Fatalf("expected no warnings when fields are simply absent, got %v", warnings)
	}
}
