package shuffle 

import (
	"testing"
)

func TestEvalPolicyJSON_Comprehensive(t *testing.T) {
	tests := []struct {
		name     string
		policy   string
		oldJSON  string
		newJSON  string
		wantJSON string
		wantOk   bool
	}{
		// -----------------------------
		// Basic merge tests
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
			wantJSON: `{"hello":null}`,
			wantOk:   true,
		},

		// -----------------------------
		// Overwrite action tests
		// -----------------------------
		{
			name:     "overwrite same_shape",
			policy:   `overwrite if same_shape`,
			oldJSON:  `{"a":1,"b":2}`,
			newJSON:  `{"a":3,"b":4}`,
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
			name:     "deny deleted field",
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
		// Nulls
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
		// Type replacement
		// -----------------------------
		{
			name: "replace object with primitive",
			policy: `merge if allowed_fields["hell"]`,
			oldJSON: `{"hell":{"hell":"naw","hello":"you"}}`,
			newJSON: `{"hell":"naw"}`,
			wantJSON: `{"hell":"naw"}`,
			wantOk: true,
		},
		{
			name: "replace primitive with object",
			policy: `merge if allowed_fields["hello"]`,
			oldJSON: `{"hello":"old"}`,
			newJSON: `{"hello":{"nested":42}}`,
			wantJSON: `{"hello":{"nested":42}}`,
			wantOk: true,
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

		{
			name: "merge + overwrite + deny with deleted field",
			policy: `
				merge if allowed_fields["hello","hell"];
				overwrite if same_shape;
				deny if has_deleted_field
			`,
			oldJSON:  `{"hell":"naw","hello":"old"}`,
			newJSON:  `{"hell":"naw"}`, // hello deleted
			wantJSON: ``,
			wantOk:   false,
		},

		{
			name: "deeply nested merge allowed fields",
			policy: `merge if allowed_fields["a.b.c.d"]`,
			oldJSON: `{"a":{"b":{"c":{"d":1,"e":2}}}}`,
			newJSON: `{"a":{"b":{"c":{"d":99}}}}`,
			wantJSON: `{"a":{"b":{"c":{"d":99,"e":2}}}}`,
			wantOk: true,
		},
		{
			name: "deeply nested overwrite same_shape",
			policy: `overwrite if same_shape`,
			oldJSON: `{"x":{"y":{"z":1}}}`,
			newJSON: `{"x":{"y":{"z":42}}}`,
			wantJSON: `{"x":{"y":{"z":42}}}`,
			wantOk: true,
		},
		{
			name: "deeply nested shape mismatch overwrite",
			policy: `overwrite if same_shape`,
			oldJSON: `{"x":{"y":{"z":1}}}`,
			newJSON: `{"x":{"y":42}}`,
			wantJSON: `{}`,
			wantOk: false,
		},

		// -----------------------------
		// Arrays of primitives + nested objects
		// -----------------------------
		{
			name: "array merge with nested objects",
			policy: `merge if allowed_fields["arr"]`,
			oldJSON: `{"arr":[{"id":1,"val":"a"},{"id":2,"val":"b"}]}`,
			newJSON: `{"arr":[{"id":2,"val":"b"},{"id":3,"val":"c"}]}`,
			wantJSON: `{"arr":[{"id":1,"val":"a"},{"id":2,"val":"b"},{"id":3,"val":"c"}]}`,
			wantOk: true,
		},

		// -----------------------------
		// Nulls inside nested objects/arrays
		// -----------------------------
		{
			name: "merge null in nested object",
			policy: `merge if allowed_fields["a.b"]`,
			oldJSON: `{"a":{"b":null,"c":2}}`,
			newJSON: `{"a":{"b":99}}`,
			wantJSON: `{"a":{"b":99,"c":2}}`,
			wantOk: true,
		},
		{
			name: "merge null inside array of objects",
			policy: `merge if allowed_fields["arr"]`,
			oldJSON: `{"arr":[{"id":1,"val":null}]}`,
			newJSON: `{"arr":[{"id":1,"val":"filled"}]}`,
			wantJSON: `{"arr":[{"id":1,"val":"filled"}]}`,
			wantOk: true,
		},

		// -----------------------------
		// Type replacement edge cases
		// -----------------------------
		{
			name: "replace object with array",
			policy: `merge if allowed_fields["foo"]`,
			oldJSON: `{"foo":{"nested":42}}`,
			newJSON: `{"foo":[1,2,3]}`,
			wantJSON: `{"foo":[1,2,3]}`,
			wantOk: true,
		},
		{
			name: "replace array with object",
			policy: `merge if allowed_fields["bar"]`,
			oldJSON: `{"bar":[1,2]}`,
			newJSON: `{"bar":{"x":1}}`,
			wantJSON: `{"bar":{"x":1}}`,
			wantOk: true,
		},

		// -----------------------------
		// Multiple allowed fields overlapping
		// -----------------------------
		{
			name: "merge multiple overlapping fields",
			policy: `merge if allowed_fields["a.b","a.c","a.d.e"]`,
			oldJSON: `{"a":{"b":1,"c":2,"d":{"e":3,"f":4}}}`,
			newJSON: `{"a":{"b":99,"c":22,"d":{"e":33}}}`,
			wantJSON: `{"a":{"b":99,"c":22,"d":{"e":33,"f":4}}}`,
			wantOk: true,
		},

		// -----------------------------
		// Deleted fields with deny
		// -----------------------------
		{
			name: "deny when nested field deleted",
			policy: `deny if has_deleted_field`,
			oldJSON: `{"a":{"b":1,"c":2}}`,
			newJSON: `{"a":{"b":1}}`,
			wantJSON: ``,
			wantOk: false,
		},

		// -----------------------------
		// Complex mix of merge/overwrite/deny
		// -----------------------------
		{
			name: "merge + overwrite + deny complex",
			policy: `
				merge if allowed_fields["x","y.z"];
				overwrite if same_shape;
				deny if has_deleted_field
			`,
			oldJSON: `{"x":1,"y":{"z":2,"w":3}}`,
			newJSON: `{"x":10,"y":{"z":20,"w":3}}`,
			wantJSON: `{"x":10,"y":{"z":20,"w":3}}`,
			wantOk: true,
		},
		{
			name: "merge + overwrite + deny complex with deleted",
			policy: `
				merge if allowed_fields["x","y.z"];
				overwrite if same_shape;
				deny if has_deleted_field
			`,
			oldJSON: `{"x":1,"y":{"z":2,"w":3}}`,
			newJSON: `{"x":10,"y":{"z":20}}`,
			wantJSON: ``,
			wantOk: false,
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
