package shuffle

import (
	"encoding/json"
	"testing"
)

// Helper to compare JSON semantically (ignores key order)
func jsonEqual(a, b string) bool {
	var ma, mb any
	if err := json.Unmarshal([]byte(a), &ma); err != nil {
		return false
	}
	if err := json.Unmarshal([]byte(b), &mb); err != nil {
		return false
	}
	return deepEqual(ma, mb)
}

func deepEqual(a, b any) bool {
	switch aa := a.(type) {
	case map[string]any:
		bb, ok := b.(map[string]any)
		if !ok || len(aa) != len(bb) {
			return false
		}
		for k, v := range aa {
			if !deepEqual(v, bb[k]) {
				return false
			}
		}
		return true
	case []any:
		bb, ok := b.([]any)
		if !ok || len(aa) != len(bb) {
			return false
		}
		for i := range aa {
			if !deepEqual(aa[i], bb[i]) {
				return false
			}
		}
		return true
	default:
		return a == b
	}
}

func TestEvalPolicyJSON_Comprehensive(t *testing.T) {
	tests := []struct {
		name       string
		policy     string
		oldJSON    string
		newJSON    string
		wantJSON   string
		wantOk     bool
		wantReason string
	}{
		// ---------------------- 1. Basic Merging ----------------------
		{
			name:       "merge_top-level_allowed_field",
			policy:     `merge if allowed_fields["hello","foo"]`,
			oldJSON:    `{"foo":"bar","hello":"world"}`,
			newJSON:    `{"hello":"you"}`,
			wantJSON:   `{"foo":"bar","hello":"you"}`,
			wantOk:     true,
			wantReason: "",
		},
		{
			name:       "merge_allowed_field_partial_update",
			policy:     `merge if allowed_fields["nested","missing"]`,
			oldJSON:    `{"nested":{"a":1}}`,
			newJSON:    `{"nested":{"a":2}}`,
			wantJSON:   `{"nested":{"a":2}}`,
			wantOk:     true,
			wantReason: "",
		},

		// ---------------------- 2. Overwrite / Shape Checks ----------------------
		{
			name:       "overwrite_same_shape_success",
			policy:     `overwrite if same_shape`,
			oldJSON:    `{"a":1,"b":2}`,
			newJSON:    `{"a":10,"b":20}`,
			wantJSON:   `{"a":10,"b":20}`,
			wantOk:     true,
			wantReason: "",
		},
		{
			name:       "overwrite_shape_mismatch_fails",
			policy:     `overwrite if same_shape`,
			oldJSON:    `{"a":1}`,
			newJSON:    `{"a":1,"b":2}`,
			wantJSON:   `{"a":1}`,
			wantOk:     false,
			wantReason: "no matching allow rule",
		},

		// ---------------------- 3. Deny / Deletion Logic ----------------------
		{
			name:       "deny_deleted_field_simple",
			policy:     `deny if has_deleted_field`,
			oldJSON:    `{"a":1,"b":2}`,
			newJSON:    `{"a":1}`,
			wantJSON:   `{"a":1,"b":2}`,
			wantOk:     false,
			// UPDATED: Now expects specific path
			wantReason: "deny: field deletion detected at 'b'",
		},
		{
			name:       "deny_deleted_field_nested",
			policy:     `deny if has_deleted_field`,
			oldJSON:    `{"nested":{"x":1,"y":2}}`,
			newJSON:    `{"nested":{"x":1}}`,
			wantJSON:   `{"nested":{"x":1,"y":2}}`,
			wantOk:     false,
			// UPDATED: Now expects nested path
			wantReason: "deny: field deletion detected at 'nested.y'",
		},
		{
			// Implicit Merge + Injection (Should be allowed if only deny rules exist)
			name:       "deny_only_allows_injection",
			policy:     `deny if has_deleted_field`,
			oldJSON:    `{"a":1}`,
			newJSON:    `{"a":1, "b":2}`,
			wantJSON:   `{"a":1, "b":2}`,
			wantOk:     true,
			wantReason: "",
		},

		// ---------------------- 4. Interaction: Merge + Deny ----------------------
		{
			name:       "merge_allowed_and_deny_deleted",
			policy:     `merge if allowed_fields["nested"]; deny if has_deleted_field`,
			oldJSON:    `{"nested":{"a":1,"b":2},"keep":42}`,
			newJSON:    `{"nested":{"b":20},"keep":42}`,
			wantJSON:   `{"nested":{"a":1,"b":20},"keep":42}`,
			wantOk:     true,
			wantReason: "",
		},
		{
			name:       "merge_safely_ignores_missing_unallowed_fields",
			policy:     `merge if allowed_fields["nested"]; deny if has_deleted_field`,
			oldJSON:    `{"nested":{"a":1,"b":2},"keep":42}`,
			newJSON:    `{"nested":{"b":20}}`, // 'keep' is missing here
			wantJSON:   `{"nested":{"a":1,"b":20},"keep":42}`, // 'keep' is preserved by merge logic
			wantOk:     true,
			wantReason: "",
		},

		// ---------------------- 5. Complex Nested / Edge Cases ----------------------
		{
			name:       "nested_overwrite_same_shape",
			policy:     `overwrite if same_shape`,
			oldJSON:    `{"nested":{"x":1,"y":2}}`,
			newJSON:    `{"nested":{"x":10,"y":20}}`,
			wantJSON:   `{"nested":{"x":10,"y":20}}`,
			wantOk:     true,
			wantReason: "",
		},
		{
			name:       "allow_type_change_string_to_map",
			policy:     `deny if has_deleted_field`,
			oldJSON:    `{"a": "value"}`,
			newJSON:    `{"a": {"sub": 1}}`,
			wantJSON:   `{"a": {"sub": 1}}`,
			wantOk:     true,
			wantReason: "",
		},
		{
			name:       "deny_type_change_map_to_string",
			policy:     `deny if has_deleted_field`,
			oldJSON:    `{"a": {"sub": 1}}`,
			newJSON:    `{"a": "value"}`,
			wantJSON:   `{"a": {"sub": 1}}`,
			wantOk:     false,
			// UPDATED: "a" is the key where the map structure disappeared
			wantReason: "deny: field deletion detected at 'a'",
		},
		
		// ---------------------- 6. Array Deletion Logic ----------------------
		{
			name:       "deny_deleted_nested_in_array",
			policy:     `deny if has_deleted_field`,
			oldJSON:    `{"list": [ {"id": 1, "secret": "keep_me"}, {"id": 2} ]}`,
			newJSON:    `{"list": [ {"id": 1}, {"id": 2} ]}`,
			wantJSON:   `{"list": [ {"id": 1, "secret": "keep_me"}, {"id": 2} ]}`,
			wantOk:     false,
			// UPDATED: Standard array notation
			wantReason: "deny: field deletion detected at 'list[0].secret'",
		},
		{
			name:       "deny_deleted_array_item",
			policy:     `deny if has_deleted_field`,
			oldJSON:    `{"list": [1, 2, 3]}`,
			newJSON:    `{"list": [1, 2]}`, // Deleted '3'
			wantJSON:   `{"list": [1, 2, 3]}`,
			wantOk:     false,
			// UPDATED: Index 2 is missing
			wantReason: "deny: field deletion detected at 'list[2]'",
		},
		
		// ---------------------- 7. Array Append Logic ----------------------
		{
			// FAILING CASE: User sends a partial object in the list.
			name:       "nested_array_partial_update_fails_deletion_check",
			policy:     "merge if always; deny if has_deleted_field",
			oldJSON:    `{"metadata":{"tasks":[{"id":1,"title":"Keep Me"}]}}`,
			// "title" field is removed in this update
			newJSON:    `{"metadata":{"tasks":[{"id":2}]}}`, 
			wantJSON:   `{"metadata":{"tasks":[{"id":1,"title":"Keep Me"}]}}`,
			wantOk:     false,
			// UPDATED: Nested path inside array
			wantReason: "deny: field deletion detected at 'metadata.tasks[0].title'",
		},
		{
			// SUCCESS CASE: User sends the Full List (Old + New).
			name:       "nested_array_full_update_succeeds",
			policy:     "merge if always; deny if has_deleted_field",
			oldJSON:    `{"metadata":{"tasks":[{"id":1,"title":"Keep Me"}]}}`,
			newJSON:    `{"metadata":{"tasks":[{"id":1,"title":"Keep Me"},{"id":2,"title":"New Task"}]}}`,
			wantJSON:   `{"metadata":{"tasks":[{"id":1,"title":"Keep Me"},{"id":2,"title":"New Task"}]}}`,
			wantOk:     true,
			wantReason: "",
		},
		{
			// APPEND SUCCESS: User sends ONLY the new item.
			// Logic now appends it to the existing list.
			name:       "merge_array_append_behavior",
			policy:     "merge; deny if has_deleted_field",
			oldJSON:    `{"tasks": [{"id":1, "title":"Keep Me"}]}`,
			newJSON:    `{"tasks": [{"id":2, "title":"New Task"}]}`,
			// Result should have BOTH
			wantJSON:   `{"tasks": [{"id":1, "title":"Keep Me"},{"id":2,"title":"New Task"}]}`,
			wantOk:     true,
			wantReason: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotJSON, gotOk, gotReason := EvalPolicyJSON(tt.policy, tt.oldJSON, tt.newJSON)

			if gotOk != tt.wantOk {
				t.Errorf("\nCheck: %s\nWanted OK: %v\nGot OK:    %v\nReason:    %q", tt.name, tt.wantOk, gotOk, gotReason)
			}
			
			// Only check reason if we expected a failure
			if !tt.wantOk && gotReason != tt.wantReason {
				t.Errorf("\nCheck: %s\nWanted Reason: %q\nGot Reason:    %q", tt.name, tt.wantReason, gotReason)
			}

			if !jsonEqual(gotJSON, tt.wantJSON) {
				t.Errorf("\nCheck: %s\nWanted JSON: %s\nGot JSON:    %s", tt.name, tt.wantJSON, gotJSON)
			}
		})
	}
}
