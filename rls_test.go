package shuffle

import (
	"testing"
	"encoding/json"
	//"log"
	//"reflect"
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

// go test -v rls_test.go rls.go
func TestEvalPolicyJSON_Comprehensive(t *testing.T) {
	tests := []struct {
		name      string
		policy    string
		oldJSON   string
		newJSON   string
		wantJSON  string
		wantOk    bool
		wantReason string

	}{
		{
			name:      "merge_top-level_allowed_field",
			policy:    `merge if allowed_fields["hello","foo"]`,
			oldJSON:   `{"foo":"bar","hello":"world"}`,
			newJSON:   `{"hello":"you"}`,
			wantJSON:  `{"foo":"bar","hello":"you"}`,
			wantOk:    true,
			wantReason: "",
		},
		// ---------------------- Overwrite if same shape ----------------------
		{
			name:      "overwrite_same_shape",
			policy:    `overwrite if same_shape`,
			oldJSON:   `{"a":1,"b":2}`,
			newJSON:   `{"a":10,"b":20}`,
			wantJSON:  `{"a":10,"b":20}`,
			wantOk:    true,
			wantReason: "",
		},
		// ---------------------- Overwrite denied due to shape mismatch ----------------------
		{
			name:      "overwrite_shape_mismatch",
			policy:    `overwrite if same_shape`,
			oldJSON:   `{"a":1}`,
			newJSON:   `{"a":1,"b":2}`,
			wantJSON:  `{"a":1}`, // old JSON returned
			wantOk:    false,
			wantReason: "same_shape",
		},
		// ---------------------- Deny if field deleted ----------------------
		{
			name:      "deny_deleted_field",
			policy:    `deny if has_deleted_field`,
			oldJSON:   `{"a":1,"b":2}`,
			newJSON:   `{"a":1}`,
			wantJSON:  `{"a":1,"b":2}`,
			wantOk:    false,
			wantReason: "has_deleted_field",
		},
		// ---------------------- Nested merge ----------------------
		{
			name:      "merge_nested_allowed_field",
			policy:    `merge if allowed_fields["nested"]`,
			oldJSON:   `{"nested":{"x":1,"y":2},"other":10}`,
			newJSON:   `{"nested":{"y":20}}`,
			wantJSON:  `{"nested":{"x":1,"y":20},"other":10}`,
			wantOk:    true,
			wantReason: "",
		},
		// ---------------------- Multiple rules: merge then deny ----------------------
		{
			name:      "merge_then_deny",
			policy:    `merge if allowed_fields["nested"]; deny if has_deleted_field`,
			oldJSON:   `{"nested":{"a":1,"b":2},"keep":42}`,
			newJSON:   `{"nested":{"b":20},"keep":42}`,
			wantJSON:  `{"nested":{"a":1,"b":20},"keep":42}`,
			wantOk:    true,
			wantReason: "",
		},
		// ---------------------- Deny triggered after merge attempt ----------------------
		{
			name:      "deny_after_merge_attempt",
			policy:    `merge if allowed_fields["nested"]; deny if has_deleted_field`,
			oldJSON:   `{"nested":{"a":1,"b":2},"keep":42}`,
			newJSON:   `{"nested":{"b":20}}`, // deleted 'keep'
			wantJSON:  `{"nested":{"a":1,"b":2},"keep":42}`,
			wantOk:    false,
			wantReason: "has_deleted_field",
		},
		// ---------------------- Allowed fields missing ----------------------
		{
			name:      "merge_allowed_field_missing",
			policy:    `merge if allowed_fields["nested","missing"]`,
			oldJSON:   `{"nested":{"a":1}}`,
			newJSON:   `{"nested":{"a":2}}`,
			wantJSON:  `{"nested":{"a":1}}`,
			wantOk:    false,
			wantReason: `allowed_fields["nested","missing"]`,
		},
		// ---------------------- Overwrite nested same shape ----------------------
		{
			name:      "overwrite_nested_same_shape",
			policy:    `overwrite if same_shape`,
			oldJSON:   `{"nested":{"x":1,"y":2}}`,
			newJSON:   `{"nested":{"x":10,"y":20}}`,
			wantJSON:  `{"nested":{"x":10,"y":20}}`,
			wantOk:    true,
			wantReason: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotJSON, gotOk, gotReason := EvalPolicyJSON(tt.policy, tt.oldJSON, tt.newJSON)
			if gotOk != tt.wantOk {
				t.Errorf("EvalPolicyJSON ok = %v, want %v", gotOk, tt.wantOk)
			}
			if gotReason != tt.wantReason {
				t.Errorf("EvalPolicyJSON reason = %v, want %v", gotReason, tt.wantReason)
			}
			if !jsonEqual(gotJSON, tt.wantJSON) {
				t.Errorf("EvalPolicyJSON gotJSON = %s, want %s", gotJSON, tt.wantJSON)
			}
		})
	}

}

// go test -v rls_test.go rls.go
