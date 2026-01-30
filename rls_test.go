package shuffle 

import (
	"testing"
)

func TestEvalPolicyJSON(t *testing.T) {
	tests := []struct {
		name       string
		policy     string
		oldJSON    string
		newJSON    string
		wantJSON   string
		wantOk     bool
	}{
		// -----------------------------
		// Basic top-level merge
		// -----------------------------
		{
			name:     "merge top-level allowed field",
			policy:   `merge if allowed_fields["hello"]`,
			oldJSON:  `{"hello": null, "foo": "bar"}`,
			newJSON:  `{"hello": "world"}`,
			wantJSON: `{"hello":"world","foo":"bar"}`,
			wantOk:   true,
		},
		{
			name:     "merge top-level disallowed field",
			policy:   `merge if allowed_fields["hello"]`,
			oldJSON:  `{"hello": null}`,
			newJSON:  `{"other": "test"}`,
			wantJSON: `{"hello": null}`,
			wantOk:   true,
		},

		// -----------------------------
		// Overwrite action
		// -----------------------------
		{
			name:     "overwrite same_shape",
			policy:   `overwrite if same_shape`,
			oldJSON:  `{"a": 1, "b": 2}`,
			newJSON:  `{"a": 3, "b": 4}`,
			wantJSON: `{"a":3,"b":4}`,
			wantOk:   true,
		},
		{
			name:     "overwrite shape mismatch",
			policy:   `overwrite if same_shape`,
			oldJSON:  `{"a":1}`,
			newJSON:  `{"a":1,"b":2}`,
			wantJSON: `{}`,
			wantOk:   false,
		},

		// -----------------------------
		// Deny action
		// -----------------------------
		{
			name:     "deny has_deleted_field",
			policy:   `deny if has_deleted_field`,
			oldJSON:  `{"a":1,"b":2}`,
			newJSON:  `{"a":1}`,
			wantJSON: ``,
			wantOk:   false,
		},
		{
			name:     "deny no deleted field",
			policy:   `deny if has_deleted_field`,
			oldJSON:  `{"a":1}`,
			newJSON:  `{"a":2}`,
			wantJSON: `{"a":2}`,
			wantOk:   true,
		},

		// -----------------------------
		// Nested objects
		// -----------------------------
		{
			name:     "merge nested allowed field",
			policy:   `merge if allowed_fields["a.b"]`,
			oldJSON:  `{"a":{"b":1,"c":2}}`,
			newJSON:  `{"a":{"b":42}}`,
			wantJSON: `{"a":{"b":42,"c":2}}`,
			wantOk:   true,
		},
		{
			name:     "merge nested disallowed field",
			policy:   `merge if allowed_fields["a.b"]`,
			oldJSON:  `{"a":{"b":1,"c":2}}`,
			newJSON:  `{"a":{"c":99}}`,
			wantJSON: `{"a":{"b":1,"c":2}}`,
			wantOk:   true,
		},

		// -----------------------------
		// Null values
		// -----------------------------
		{
			name:     "merge null -> value",
			policy:   `merge if allowed_fields["hello"]`,
			oldJSON:  `{"hello":null}`,
			newJSON:  `{"hello":"world"}`,
			wantJSON: `{"hello":"world"}`,
			wantOk:   true,
		},
		{
			name:     "merge value -> null",
			policy:   `merge if allowed_fields["hello"]`,
			oldJSON:  `{"hello":"old"}`,
			newJSON:  `{"hello":null}`,
			wantJSON: `{"hello":null}`,
			wantOk:   true,
		},

		// -----------------------------
		// Arrays
		// -----------------------------
		{
			name:     "merge arrays append-only",
			policy:   `merge if allowed_fields["arr"]`,
			oldJSON:  `{"arr":[1,2]}`,
			newJSON:  `{"arr":[2,3]}`,
			wantJSON: `{"arr":[1,2,3]}`,
			wantOk:   true,
		},
		{
			name:     "merge nested arrays",
			policy:   `merge if allowed_fields["a.b"]`,
			oldJSON:  `{"a":{"b":[1,2]}}`,
			newJSON:  `{"a":{"b":[2,3]}}`,
			wantJSON: `{"a":{"b":[1,2,3]}}`,
			wantOk:   true,
		},

		// -----------------------------
		// New top-level fields
		// -----------------------------
		{
			name:     "merge adds new top-level field",
			policy:   `merge if allowed_fields["new"]`,
			oldJSON:  `{"existing":1}`,
			newJSON:  `{"new":42}`,
			wantJSON: `{"existing":1,"new":42}`,
			wantOk:   true,
		},

		// -----------------------------
		// Combination rules
		// -----------------------------
		{
			name: "merge + overwrite + deny combo",
			policy: `
				merge if allowed_fields["hello","hell"];
				overwrite if same_shape;
				deny if has_deleted_field
			`,
			oldJSON:  `{"hell":"naw","hello":null}`,
			newJSON:  `{"hell":"naw","hello":"you"}`,
			wantJSON: `{"hell":"naw","hello":"you"}`,
			wantOk:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotJSON, ok := EvalPolicyJSON(tt.policy, tt.oldJSON, tt.newJSON)
			if ok != tt.wantOk {
				t.Errorf("EvalPolicyJSON ok = %v, want %v", ok, tt.wantOk)
			}
			if gotJSON != tt.wantJSON {
				t.Errorf("EvalPolicyJSON gotJSON = %v, want %v", gotJSON, tt.wantJSON)
			}
		})
	}
}
