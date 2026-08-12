package shuffle

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/shuffle/opensearch-go/v4/opensearchapi"
)

const defaultNotificationRetentionDaysValue = 0

// getNotificationRetentionDays returns how many days a read/ignored
// notification is kept before the cleanup sweep deletes it.
func getNotificationRetentionDays() int {
	raw := strings.TrimSpace(os.Getenv("OPENSEARCH_NOTIFICATION_RETENTION_DAYS"))
	if raw == "" {
		return defaultNotificationRetentionDaysValue
	}

	parsed, err := strconv.Atoi(raw)
	if err != nil || parsed <= 0 {
		if raw != "0" {
			log.Printf("[WARNING] Invalid OPENSEARCH_NOTIFICATION_RETENTION_DAYS %q, notification retention stays disabled", raw)
		}
		return defaultNotificationRetentionDaysValue
	}

	return parsed
}

// buildNotificationRetentionQuery builds the query for finding notifications
// eligible for deletion: read OR ignored, and last updated before the
// retention cutoff.
func buildNotificationRetentionQuery(now time.Time, retentionDays int) map[string]interface{} {
	cutoff := now.AddDate(0, 0, -retentionDays).Unix()

	return map[string]interface{}{
		"size": 1000,
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": []map[string]interface{}{
					{
						"bool": map[string]interface{}{
							"should": []map[string]interface{}{
								{"term": map[string]interface{}{"read": true}},
								{"term": map[string]interface{}{"ignored": true}},
							},
						},
					},
					{
						"range": map[string]interface{}{
							"updated_at": map[string]interface{}{
								"lt": cutoff,
							},
						},
					},
				},
			},
		},
	}
}

// sweepOldNotifications deletes notifications that are read or ignored and
// older than getNotificationRetentionDays().
func sweepOldNotifications(ctx context.Context) error {
	retentionDays := getNotificationRetentionDays()
	if retentionDays <= 0 {
		return nil
	}

	query := buildNotificationRetentionQuery(time.Now(), retentionDays)

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(query); err != nil {
		return err
	}

	resp, err := project.Es.Search(ctx, &opensearchapi.SearchReq{
		Indices: []string{strings.ToLower(GetESIndexPrefix("notifications"))},
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

	type notificationHit struct {
		Source Notification `json:"_source"`
	}
	type notificationSearchWrapper struct {
		Hits struct {
			Hits []notificationHit `json:"hits"`
		} `json:"hits"`
	}

	wrapped := notificationSearchWrapper{}
	if err := json.Unmarshal(respBody, &wrapped); err != nil {
		return err
	}

	deleted := 0
	for _, hit := range wrapped.Hits.Hits {
		if err := DeleteKey(ctx, "notifications", hit.Source.Id); err != nil {
			log.Printf("[WARNING] Failed deleting old notification %s: %s", hit.Source.Id, err)
			continue
		}
		deleted++
	}

	if deleted > 0 {
		log.Printf("[INFO] Deleted %d notifications older than %d days retention", deleted, getNotificationRetentionDays())
	}

	return nil
}

// notificationRetentionMappingWarning checks whether the notifications index
// mapping actually supports the retention sweep's query (read/ignored as
// boolean, updated_at as date). On indexes created before opensearchCoreMappings
// existed, these fields may be dynamically mapped as keyword/long instead,
// which makes buildNotificationRetentionQuery's term/range clauses silently
// match nothing - the sweep looks "active" (no errors, ticks every 24h) but
// never actually deletes anything. This surfaces that as an explicit
// [WARNING] log line instead of a silent no-op, so retention reads as
// "inactive" rather than "active" when it can't work.
func notificationRetentionMappingWarning(ctx context.Context) {
	alias := strings.ToLower(GetESIndexPrefix("notifications"))

	resp, err := project.Es.Indices.Mapping.Get(ctx, &opensearchapi.MappingGetReq{
		Indices: []string{alias},
	})
	if err != nil {
		return
	}

	res := resp.Inspect().Response
	if res == nil {
		return
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return
	}

	for indexName, indexMapping := range resp.Indices {
		var parsed struct {
			Properties map[string]struct {
				Type string `json:"type"`
			} `json:"properties"`
		}
		if err := json.Unmarshal(indexMapping.Mappings, &parsed); err != nil {
			continue
		}

		fieldTypes := make(map[string]string, len(parsed.Properties))
		for field, prop := range parsed.Properties {
			fieldTypes[field] = prop.Type
		}

		for _, warning := range notificationRetentionFieldMappingWarnings(indexName, fieldTypes) {
			log.Printf("[WARNING] %s", warning)
		}
	}
}

// notificationRetentionFieldMappingWarnings is the pure comparison logic
// behind notificationRetentionMappingWarning, factored out so it's
// unit-testable without a live OpenSearch cluster. fieldTypes maps a field
// name to its mapped OpenSearch type (empty string / absent means the field
// has no mapping yet, e.g. an empty freshly-created index - not a mismatch).
func notificationRetentionFieldMappingWarnings(indexName string, fieldTypes map[string]string) []string {
	var warnings []string

	if fieldType := fieldTypes["read"]; fieldType != "" && fieldType != "boolean" {
		warnings = append(warnings, fmt.Sprintf("Notification retention sweep on %s: 'read' field is mapped as %q, not 'boolean' - the retention query will silently match nothing on this index. Retention is effectively inactive here until a reindex fixes the mapping.", indexName, fieldType))
	}
	if fieldType := fieldTypes["ignored"]; fieldType != "" && fieldType != "boolean" {
		warnings = append(warnings, fmt.Sprintf("Notification retention sweep on %s: 'ignored' field is mapped as %q, not 'boolean' - the retention query will silently match nothing on this index. Retention is effectively inactive here until a reindex fixes the mapping.", indexName, fieldType))
	}
	if fieldType := fieldTypes["updated_at"]; fieldType != "" && fieldType != "date" {
		warnings = append(warnings, fmt.Sprintf("Notification retention sweep on %s: 'updated_at' field is mapped as %q, not 'date' - the retention query's date range will silently match nothing on this index. Retention is effectively inactive here until a reindex fixes the mapping.", indexName, fieldType))
	}

	return warnings
}

// StartNotificationRetentionSweeper runs sweepOldNotifications once per day.
func StartNotificationRetentionSweeper(ctx context.Context) {
	if project.DbType != "opensearch" {
		return
	}

	if getNotificationRetentionDays() > 0 {
		notificationRetentionMappingWarning(ctx)
	}

	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := sweepOldNotifications(ctx); err != nil {
				log.Printf("[WARNING] Notification retention sweep failed: %s", err)
			}
		}
	}
}
